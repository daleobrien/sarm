#!/usr/bin/env python3
"""Deterministic hostile traffic against a running sarm, with every
byte the server sends back captured (docs/SECURITY.md Steps 10 and 11).

Two tests need the same thing: a workload that reaches as much of the
server as malformed input can reach, over every protocol it speaks, and
never varies between runs.

  * `leak_checks.py` (Step 10) scans what comes back for secrets.
  * `test_syscalls.sh` (Step 11) runs it under a syscall tracer and
    checks what the server asked the kernel for while serving it.

So the traffic lives here, once, and the two tests differ only in what
they do with the result.

Five campaigns, each a generator of connections:

  http1      request lines and header blocks that are wrong in one
             generated way: bad methods, bad versions, traversal,
             percent-encoded traversal, NUL and control bytes, header
             lines past the buffer, absurd Content-Length, no
             terminator at all, and pipelined requests behind a valid
             one.
  h2c        the cleartext HTTP/2 preface followed by generated
             frames: unknown types, lengths that disagree with the
             payload, HPACK that decodes to nothing, DATA on a stream
             that was never opened, and a settings block that is
             legal but large.
  tls_junk   bytes in the shape of TLS records, but not a handshake:
             every content type, versions the server rejects, lengths
             at and past TLS_MAX_CIPHERTEXT, ClientHellos truncated
             mid-extension.
  tls_real   an actual TLS 1.3 handshake through the stdlib `ssl`
             module (certificate verification off — the point is to
             reach the server's post-handshake state, not to trust
             it), ALPN `h2`, then real requests and generated frames
             inside the encrypted stream. The only campaign that gets
             past the handshake, and so the only one that can show a
             leak from a connection the server considers established.
  fragmented a valid request delivered one or two bytes at a time,
             with the connection sometimes dropped mid-header.

Determinism comes from `random.Random(seed)` and nothing else: no
wall-clock, no address, no ordering dependence between connections.

Every connection is recorded as a `Conn`: the bytes sent, the bytes
received (ciphertext as it came off the socket for the TLS campaigns,
so a leak in a plaintext record is visible), and — for `tls_real` —
the decrypted application data as well.

Usage (standalone, for the tracer):
    hostile_workload.py <port> [--cases N] [--seed S] [--quiet]
"""

import argparse
import os
import random
import socket
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2_browser_sim as sim                                  # noqa: E402

HOST = "127.0.0.1"
TIMEOUT = 1.0

# A request marker the leak checks look for coming back. Chosen to be
# unmistakable in a hex dump and to contain no byte that any header the
# server writes could produce by arithmetic.
MARKER_PREFIX = b"SARMLEAKCANARY"


class Conn:
    """One connection: what was sent, and every byte that came back."""

    __slots__ = ("campaign", "sent", "raw", "plain", "marker", "error",
                 "peercert")

    def __init__(self, campaign, marker=None):
        self.campaign = campaign
        self.sent = bytearray()
        self.raw = bytearray()      # off the socket, ciphertext included
        self.plain = bytearray()    # decrypted app data (tls_real only)
        self.marker = marker
        self.error = None
        self.peercert = None    # DER, tls_real only

    def __repr__(self):
        return (f"<Conn {self.campaign} sent={len(self.sent)} "
                f"raw={len(self.raw)} plain={len(self.plain)}>")


# ── socket helpers ──────────────────────────────────────────────────
def _connect(port):
    s = socket.create_connection((HOST, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    return s


def _drain(sock, conn, limit=1 << 20):
    """Read until the server closes, times out, or `limit` bytes.

    The write side is closed first. Every campaign here has said
    everything it is going to say by the time it drains, and a server
    that keeps the connection alive waiting for the next pipelined
    request would otherwise cost a full timeout per case. The half-close
    is also the truthful thing to send: "no more requests", which is
    exactly the state a truncated request ends in.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    while len(conn.raw) < limit:
        try:
            b = sock.recv(65536)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not b:
            break
        conn.raw += b


def _send(sock, conn, data):
    conn.sent += data
    try:
        sock.sendall(data)
        return True
    except OSError as e:
        conn.error = repr(e)
        return False


# ── campaign 1: HTTP/1 ──────────────────────────────────────────────
BAD_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"TRACE", b"CONNECT",
               b"GETX", b"", b"G" * 64, b"\x00GET", b"gEt"]
BAD_VERSIONS = [b"HTTP/1.1", b"HTTP/1.0", b"HTTP/2.0", b"HTTP/9.9", b"HTTP/",
                b"", b"HTTP/1.1 ", b"\x01\x02"]
BAD_PATHS = [
    b"/", b"/index.html", b"/../etc/passwd", b"/%2e%2e%2fetc%2fpasswd",
    b"/%00", b"/%01x", b"/....//....//etc/passwd", b"/" + b"a" * 8192,
    b"//////", b"/?" + b"q" * 4096, b"/\x7f", b"/\xff\xfe",
    b"*", b"http://evil.example/", b"/.%2e/.%2e/etc/shadow",
]


def _http1_case(rnd, marker):
    """One generated HTTP/1 request, as bytes."""
    method = rnd.choice(BAD_METHODS)
    path = rnd.choice(BAD_PATHS)
    version = rnd.choice(BAD_VERSIONS)

    # The marker rides in whichever field this case picks, so a leak of
    # any of the three request buffers (filename_buf, query_buf,
    # authority_buf) can show up.
    where = rnd.randrange(4)
    if where == 0:
        path = b"/" + marker + path
    elif where == 1:
        path = path + b"?" + marker

    lines = [b" ".join(x for x in (method, path, version) if x)]
    if where == 2:
        lines.append(b"Host: " + marker + b".example")
    else:
        lines.append(b"Host: localhost")
    if where == 3:
        lines.append(b"X-Canary: " + marker)

    for _ in range(rnd.randrange(6)):
        kind = rnd.randrange(8)
        if kind == 0:
            lines.append(b"Content-Length: " + str(rnd.choice(
                [-1, 0, 1, 2 ** 31, 2 ** 63, 10 ** 20])).encode())
        elif kind == 1:
            lines.append(b"Range: bytes=" + rnd.choice(
                [b"0-", b"-1", b"0-99999999999", b"9999-1", b"a-b", b"0-0,1-1"]))
        elif kind == 2:
            lines.append(b"X-" + b"L" * rnd.randrange(1, 20000) + b": v")
        elif kind == 3:
            lines.append(b"Transfer-Encoding: chunked")
        elif kind == 4:
            lines.append(b"Connection: " + rnd.choice([b"close", b"keep-alive",
                                                       b"\x00", b"upgrade"]))
        elif kind == 5:
            lines.append(bytes(rnd.randrange(1, 256)
                               for _ in range(rnd.randrange(1, 64))))
        elif kind == 6:
            lines.append(b"If-None-Match: " + b'"' + b"x" * 200 + b'"')
        else:
            lines.append(b"Accept-Encoding: gzip")

    body = b"\r\n".join(lines)
    if rnd.randrange(8) == 0:
        return body                          # no terminator at all
    req = body + b"\r\n\r\n"
    if rnd.randrange(6) == 0:                # pipelined behind a valid one
        req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" + req
    return req


def campaign_http1(port, rnd, marker):
    conn = Conn("http1", marker)
    try:
        s = _connect(port)
    except OSError as e:
        conn.error = repr(e)
        return conn
    with s:
        if _send(s, conn, _http1_case(rnd, marker)):
            _drain(s, conn)
    return conn


# ── campaign 2: h2c ─────────────────────────────────────────────────
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _frame(ftype, flags, sid, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) \
        + struct.pack(">I", sid) + payload


def _h2_valid_block(path, authority, scheme="https"):
    """A well-formed request, encoded by the simulator's HPACK encoder.

    Reused rather than rewritten so that a "valid" case here really is
    the one tests/h2_browser_sim.py sends: a hostile campaign whose
    valid control case is subtly invalid tests nothing, because the
    server's answer to it is an error either way — and an error page is
    a much smaller piece of the response path than a real body.
    """
    block = bytearray()
    block += sim.hpack_field(2, "GET", False)          # :method
    block += sim.hpack_field(6, scheme, False)         # :scheme
    block += sim.hpack_field(4, path, False)           # :path
    block += sim.hpack_field(1, authority, True)       # :authority
    block += sim.hpack_new_field("user-agent", "sarm-leak-probe", True)
    return bytes(block)


def _h2_hostile_block(rnd, marker):
    """A header block that is wrong in one generated way, always
    carrying the marker in :path or :authority so a disclosure of the
    HPACK buffers or of `filename_buf` shows the marker itself."""
    path = "/" + marker.decode()
    authority = marker.decode() + ".example"
    kind = rnd.randrange(5)
    if kind == 0:                       # legal, hostile content only
        return _h2_valid_block(path, authority)
    if kind == 1:                       # a literal claiming more than follows
        block = bytearray(_h2_valid_block(path, authority))
        block.append(0x00)
        block.append(0x05)
        block.extend(b"x-bad")
        block.append(0x7F)              # a length prefix with no continuation
        return bytes(block)
    if kind == 2:                       # a dynamic-table index that does not exist
        return _h2_valid_block(path, authority) + bytes([0xFF, 0xFF, 0x7F])
    if kind == 3:                       # raw bytes where a block should be
        return bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 200)))
    # a huge literal name, to run the decoder past its buffers
    block = bytearray(_h2_valid_block(path, authority))
    block += sim.hpack_new_field("x-" + "n" * rnd.randrange(1, 5000),
                                 marker.decode(), False)
    return bytes(block)


def campaign_h2c(port, rnd, marker):
    conn = Conn("h2c", marker)
    try:
        s = _connect(port)
    except OSError as e:
        conn.error = repr(e)
        return conn
    with s:
        buf = bytearray(H2_PREFACE)
        buf += _frame(0x4, 0, 0, b"")                       # SETTINGS
        kind = rnd.randrange(8)
        if kind == 0:                                       # large but legal
            buf += _frame(0x4, 0, 0, b"".join(
                struct.pack(">HI", 0xF000 + i, 0) for i in range(500)))
        elif kind == 1:                                     # unknown type
            buf += _frame(rnd.randrange(0x10, 0x100), rnd.randrange(256),
                          rnd.randrange(1 << 16), b"")
        elif kind == 2:                                     # DATA, no stream
            buf += _frame(0x0, 0x1, rnd.choice([0, 1, 3, 0x7FFFFFFF]),
                          bytes(rnd.randrange(256) for _ in range(32)))
        elif kind == 3:                                     # length lie
            hdr = _h2_hostile_block(rnd, marker)
            buf += struct.pack(">I", len(hdr) + 4000)[1:] + bytes([0x1, 0x5]) \
                + struct.pack(">I", 1) + hdr
        elif kind == 4:                                     # WINDOW_UPDATE 0
            buf += _frame(0x8, 0, 1, struct.pack(">I", 0))
        elif kind == 5:                                     # PRIORITY on self
            buf += _frame(0x2, 0, 1, struct.pack(">IB", 1, 16))
        elif kind == 6:                                     # legal, marked
            buf += _frame(0x1, 0x5, 1,
                          _h2_valid_block("/", "localhost", "http"))
            buf += _frame(0x1, 0x5, 3,
                          _h2_valid_block("/" + marker.decode(),
                                          marker.decode() + ".example", "http"))
        else:
            buf += _frame(0x1, 0x5, 1, _h2_hostile_block(rnd, marker))
        if rnd.randrange(4) == 0:
            buf += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 64)))
        if _send(s, conn, bytes(buf)):
            _drain(s, conn)
    return conn


# ── campaign 3: TLS junk ────────────────────────────────────────────
def _tls_record(ctype, version, payload, length=None):
    n = len(payload) if length is None else length
    return bytes([ctype, version >> 8, version & 0xFF, n >> 8, n & 0xFF]) \
        + payload


def campaign_tls_junk(port, rnd, marker):
    conn = Conn("tls_junk", marker)
    try:
        s = _connect(port)
    except OSError as e:
        conn.error = repr(e)
        return conn
    with s:
        kind = rnd.randrange(6)
        if kind == 0:                       # a plausible but empty handshake
            data = _tls_record(22, 0x0301, b"")
        elif kind == 1:                     # every content type
            data = b"".join(
                _tls_record(t, 0x0303,
                            bytes(rnd.randrange(256) for _ in range(rnd.randrange(64))))
                for t in (20, 21, 22, 23, rnd.randrange(256)))
        elif kind == 2:                     # a length past TLS_MAX_CIPHERTEXT
            data = _tls_record(23, 0x0303, b"A" * 64, length=0xFFFF)
        elif kind == 3:                     # ClientHello, truncated
            body = bytes([0x03, 0x03]) + marker.ljust(32, b"\x00")[:32] \
                + bytes([0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00])
            hs = bytes([1, 0, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + body
            data = _tls_record(22, 0x0301, hs[:rnd.randrange(5, len(hs) + 1)])
        elif kind == 4:                     # the marker, raw, no framing
            data = marker * 4
        else:
            data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 512)))
        if _send(s, conn, data):
            _drain(s, conn)
    return conn


# ── campaign 4: a real TLS 1.3 connection ───────────────────────────
def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2"])
    except NotImplementedError:
        pass
    return ctx


def campaign_tls_real(port, rnd, marker, ctx=None):
    """A completed handshake, then h2 traffic inside it.

    Both layers are captured: `conn.raw` gets the ciphertext as it
    arrives (a secret written into a plaintext record would show there),
    `conn.plain` gets what the TLS layer hands back after decryption
    (a secret written into a response body shows there).
    """
    conn = Conn("tls_real", marker)
    ctx = ctx or _tls_context()
    try:
        raw = _connect(port)
    except OSError as e:
        conn.error = repr(e)
        return conn
    try:
        s = ctx.wrap_socket(raw, server_hostname="localhost")
    except (ssl.SSLError, OSError) as e:
        conn.error = repr(e)
        raw.close()
        return conn
    with s:
        # The certificate is kept aside rather than folded into the
        # captured bytes: the server is *supposed* to send it, so a
        # scanner looking for certificate memory in a response would
        # find it here and be right for the wrong reason. The caller
        # uses it to confirm this is the build it thinks it is.
        try:
            conn.peercert = s.getpeercert(binary_form=True)
        except (ValueError, ssl.SSLError):
            pass

        # A real request first: the response to it is a real body off
        # the real response path, which is the traffic a leak would
        # most likely ride in. The hostile request follows on its own
        # stream, so one connection carries both.
        buf = bytearray(H2_PREFACE)
        buf += _frame(0x4, 0, 0, b"")
        buf += _frame(0x8, 0, 0, struct.pack(">I", 1 << 20))   # room for it
        buf += _frame(0x1, 0x5, 1, _h2_valid_block("/", "localhost"))
        buf += _frame(0x1, 0x5, 3, _h2_hostile_block(rnd, marker))
        if rnd.randrange(4) == 0:                       # garbage after it
            buf += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 128)))

        try:
            conn.sent += bytes(buf)
            s.sendall(bytes(buf))
        except (ssl.SSLError, OSError) as e:
            conn.error = repr(e)
            return conn
        while len(conn.plain) < (1 << 20):
            try:
                b = s.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            except (ssl.SSLError, OSError) as e:
                conn.error = repr(e)
                break
            if not b:
                break
            conn.plain += b
    return conn


# ── campaign 5: fragmented delivery ─────────────────────────────────
def campaign_fragmented(port, rnd, marker):
    conn = Conn("fragmented", marker)
    try:
        s = _connect(port)
    except OSError as e:
        conn.error = repr(e)
        return conn
    with s:
        req = (b"GET /" + marker + b" HTTP/1.1\r\nHost: localhost\r\n"
               b"X-Canary: " + marker + b"\r\n\r\n")
        if rnd.randrange(3) == 0:
            req = req[:rnd.randrange(1, len(req))]      # stop mid-request
        i = 0
        while i < len(req):
            n = rnd.randrange(1, 4)
            if not _send(s, conn, req[i:i + n]):
                break
            i += n
        _drain(s, conn)
    return conn


CAMPAIGNS = [
    ("http1", campaign_http1),
    ("h2c", campaign_h2c),
    ("tls_junk", campaign_tls_junk),
    ("tls_real", campaign_tls_real),
    ("fragmented", campaign_fragmented),
]


def run(port, cases=250, seed=0x5A524D, on_conn=None, campaigns=None):
    """Run `cases` connections, cycling the campaigns. Returns the list
    of `Conn` records (or, if `on_conn` is given, feeds them to it and
    returns the count — which is how a long run stays bounded in
    memory)."""
    rnd = random.Random(seed)
    picks = campaigns or [name for name, _ in CAMPAIGNS]
    fns = dict(CAMPAIGNS)
    ctx = _tls_context()
    out = []
    n = 0
    for i in range(cases):
        name = picks[i % len(picks)]
        marker = MARKER_PREFIX + b"%06d" % i
        fn = fns[name]
        conn = (fn(port, rnd, marker, ctx) if name == "tls_real"
                else fn(port, rnd, marker))
        n += 1
        if on_conn is not None:
            on_conn(conn)
        else:
            out.append(conn)
    return out if on_conn is None else n


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", type=int)
    ap.add_argument("--cases", type=int, default=250)
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x5A524D)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    tally = {}
    errors = {}

    def note(conn):
        tally[conn.campaign] = tally.get(conn.campaign, 0) + 1
        if conn.error:
            errors[conn.campaign] = errors.get(conn.campaign, 0) + 1

    run(args.port, cases=args.cases, seed=args.seed, on_conn=note)
    if not args.quiet:
        for name in sorted(tally):
            print(f"  {name:<12} {tally[name]:>5} connections, "
                  f"{errors.get(name, 0)} refused or reset")
    return 0


if __name__ == "__main__":
    sys.exit(main())
