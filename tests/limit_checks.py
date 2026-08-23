#!/usr/bin/env python3
"""Resource-limit measurements against a running sarm
(docs/SECURITY.md §8 and Step 12; run by tests/test_limits.sh).

Steps 6-9 asked what the parsers *do* with hostile bytes. Step 12 asks
what they *cost*: a server can answer every malformed input perfectly
and still fall over because answering was the expensive part, or because
the client never stopped asking.

    Attack: connections, handshake state, buffers, CPU.
    Test:   resource use remains bounded.

"Bounded" is only a claim if a number is attached to it, so every check
here measures something about the process — how many children exist, how
resident they are, how long one client can hold one, how much CPU a
connection buys for the price of a packet — and compares it against a
ceiling this file names. A check that cannot fail is worse than no
check, so each campaign also asserts its own non-vacuity: that the attack
really did reach the thing it was aiming at.

Four campaigns, each driven by test_limits.sh against a server started in
the shape that campaign needs:

  connections   N concurrent clients that connect and then go quiet.
                Costs one forked child each. Checks that the server keeps
                serving while they are held, that a child's resident size
                does not depend on the client, and that every one of them
                is reclaimed when the receive timeout expires.

  deadline      the attack the receive timeout does not stop: a client
                that sends one byte just often enough to restart it, in
                each of the three shapes the server speaks — an HTTP/1
                header, an h2c frame, and a TLS handshake padded out with
                the change_cipher_spec records RFC 8446 Appendix D.4
                requires the server to tolerate. Checks that CONN_DEADLINE
                ends all three, and — the non-vacuity half — that the drip
                really did outlive the receive timeout on the way there.

  buffers       inputs chosen to make a server want more memory: headers
                past BUF_SIZE, a path past its cap, hundreds of header
                lines, TLS records at and past the maximum, h2 frames
                over the advertised size, more concurrent streams than
                SETTINGS advertised, and an HPACK dynamic table stuffed
                to its cap. sarm allocates nothing at runtime, so the
                property is exact: peak resident size under all of that
                must not exceed peak resident size under plain traffic.

  cpu           per-connection CPU, measured in no_fork mode so one
                process's own accounting answers for the work. Compares a
                complete TLS 1.3 handshake against connections that are
                rejected before it, which is where SECURITY.md §8 puts
                the requirement: "a malformed packet should generally be
                rejected before expensive crypto".

Output: one "OK: ..." or "FAIL: ..." line per check, the same contract
leak_checks.py has with its shell script.

Usage:
    limit_checks.py <campaign> <port> --pid N [options]
    limit_checks.py --self-test
"""

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2_browser_sim as sim                                  # noqa: E402

HOST = "127.0.0.1"

# ── the ceilings ────────────────────────────────────────────────────
# Every one of these is a claim about the server, not a tuning knob.
# Raising one to make a test pass is a change to the threat model, and
# docs/SECURITY.md §8 is where it has to be argued.

# A child's resident image. Measured at ~176 KB on macOS/arm64 for every
# protocol and every input; the ceiling is generous because RSS includes
# shared pages the OS accounts differently under load, and because the
# check that matters is the *comparison* below, not this number.
RSS_CEILING_KB = 1024

# How much more resident a child may be under the hostile corpus than
# under plain traffic. sarm has no heap and no runtime allocation, so the
# honest answer is zero; one page of slack absorbs the accounting.
RSS_GROWTH_KB = 64

# CPU seconds per connection, for any connection at all.
CPU_CEILING_MS = 2.0

# How much cheaper a connection rejected before the key exchange has to
# be than one that completes it. Measured at ~16x; 4x is the floor the
# test enforces, so an accidental "validate after the ECDH" reordering
# fails without the check being sensitive to which machine it runs on.
CPU_REJECT_RATIO = 4.0


def report(ok, desc):
    print(("OK: " if ok else "FAIL: ") + desc)
    return ok


# ── process measurement ─────────────────────────────────────────────

def children_of(pid):
    """(child pid, RSS in KB) for every direct child of `pid`."""
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,rss="],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 3 and f[1] == str(pid):
            try:
                rows.append((int(f[0]), int(f[2])))
            except ValueError:
                pass
    return rows


def cpu_seconds(pid):
    """CPU time consumed by `pid`, in seconds.

    /proc is preferred where it exists: Linux `ps -o time` rounds to the
    second, which at these magnitudes is no measurement at all, while
    utime+stime in /proc/PID/stat carry clock-tick resolution. macOS has
    no /proc and its `ps` prints hundredths, which is enough once the
    campaign divides by a few thousand connections.
    """
    try:
        with open(f"/proc/{pid}/stat") as f:
            fields = f.read().rsplit(") ", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])       # utime + stime
        return ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        pass
    out = subprocess.run(["ps", "-p", str(pid), "-o", "time="],
                         capture_output=True, text=True).stdout.strip()
    if not out:
        return None
    days, _, rest = out.rpartition("-")
    parts = rest.split(":")
    secs = float(parts[-1])
    if len(parts) > 1:
        secs += 60 * int(parts[-2])
    if len(parts) > 2:
        secs += 3600 * int(parts[-3])
    if days:
        secs += 86400 * int(days)
    return secs


class RssSampler:
    """Peak resident size across all of a server's children, sampled by
    polling. A child that lives for a millisecond can be missed; that is
    acceptable here because every case this samples is deliberately held
    open while the sample runs."""

    def __init__(self, pid):
        self.pid = pid
        self.peak = 0
        self.samples = 0

    def sample(self):
        for _, rss in children_of(self.pid):
            self.peak = max(self.peak, rss)
            self.samples += 1
        return self.peak


# ── clients ─────────────────────────────────────────────────────────

def http_get(port, path="/", timeout=5.0):
    """One complete HTTP/1.1 request. Returns the status line, or b'' if
    the server never answered."""
    try:
        s = socket.create_connection((HOST, port), timeout=timeout)
    except OSError as exc:
        return b"<connect: %s>" % str(exc).encode()
    try:
        s.sendall(b"GET %s HTTP/1.1\r\nHost: localhost\r\n"
                  b"Connection: close\r\n\r\n" % path.encode())
        s.settimeout(timeout)
        data = b""
        while len(data) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        return data.split(b"\r\n", 1)[0]
    except OSError as exc:
        return b"<recv: %s>" % str(exc).encode()
    finally:
        s.close()


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # sarm ships a self-signed dev cert
    ctx.set_alpn_protocols(["h2"])
    return ctx


def capture_client_hello():
    """A real TLS 1.3 ClientHello, as bytes.

    Built by handing the stdlib's own handshake a socketpair and taking
    the first flight off the other end. Writing one by hand would mean
    this file owning a second, worse TLS implementation; borrowing one
    means the bytes the server sees are the bytes a real client sends,
    including the key share the campaigns below go on to corrupt.
    """
    a, b = socket.socketpair()
    try:
        s = tls_context().wrap_socket(a, do_handshake_on_connect=False,
                                      server_hostname="localhost")
        s.setblocking(False)
        try:
            s.do_handshake()
        except (ssl.SSLWantReadError, BlockingIOError):
            pass
        b.setblocking(False)
        try:
            return b.recv(65536)
        except OSError:
            return b""
    finally:
        for sock in (a, b):
            try:
                sock.close()
            except OSError:
                pass


def truncated_key_share(hello):
    """The same ClientHello with the key_share's key_exchange length cut
    to 31 octets — an X25519 share that is one byte short.

    The point is where it is rejected, not that it is: 31 is caught by the
    ClientHello parser's bounds walk, before any scalar multiplication
    happens, which is exactly the ordering the `cpu` campaign measures.
    """
    i = hello.find(b"\x00\x33", 60)              # extension type key_share
    if i < 0 or i + 10 > len(hello):
        return None
    out = bytearray(hello)
    out[i + 8:i + 10] = (31).to_bytes(2, "big")  # key_exchange length
    return bytes(out)


CCS_RECORD = bytes.fromhex("140303000101")       # change_cipher_spec, one byte
H2_PREFACE = sim.PREFACE


# ── campaign: connections ───────────────────────────────────────────

def campaign_connections(port, pid, recv_timeout, count):
    ok = True
    socks = []
    refused = 0
    for _ in range(count):
        try:
            s = socket.create_connection((HOST, port), timeout=5)
            s.sendall(b"G")                      # enough to be a connection,
            socks.append(s)                      # never enough to be a request
        except OSError:
            refused += 1

    ok &= report(refused == 0,
                 f"all {count} concurrent connections were accepted"
                 + (f" ({refused} refused)" if refused else ""))

    time.sleep(0.75)
    kids = children_of(pid)

    # Non-vacuity: if the server had already dropped them, everything
    # below would pass by measuring nothing.
    ok &= report(len(kids) >= count,
                 f"each held connection costs exactly one child "
                 f"({len(kids)} children for {count} connections)")

    if kids:
        rss = [r for _, r in kids]
        ok &= report(max(rss) <= RSS_CEILING_KB,
                     f"no child exceeds {RSS_CEILING_KB} KB resident "
                     f"(peak {max(rss)} KB)")
        ok &= report(max(rss) - min(rss) <= RSS_GROWTH_KB,
                     f"every child costs the same ({min(rss)}-{max(rss)} KB, "
                     f"spread {max(rss) - min(rss)} KB)")

    # The server is still a server while it is under attack.
    status = http_get(port)
    ok &= report(status.startswith(b"HTTP/1.1 200"),
                 f"a real request is still served while {count} connections "
                 f"are held (got {status[:40]!r})")

    # And the held connections go away on their own.
    deadline = time.time() + recv_timeout + 8
    while time.time() < deadline:
        if not children_of(pid):
            break
        time.sleep(0.25)
    left = len(children_of(pid))
    ok &= report(left == 0,
                 f"every idle connection is reclaimed within "
                 f"RECV_TIMEOUT+8s ({left} children left)")

    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    return ok


# ── campaign: deadline ──────────────────────────────────────────────

def _drip(sock, chunks, gap, limit):
    """Send `chunks` one at a time, `gap` seconds apart, until the peer
    goes away or `limit` seconds pass. Returns (held seconds, chunks
    sent)."""
    start = time.time()
    sent = 0
    for chunk in chunks:
        if time.time() - start > limit:
            break
        try:
            sock.sendall(chunk)
            sent += 1
        except OSError:
            break
        time.sleep(gap)
        gone = False
        try:
            sock.setblocking(False)
            gone = sock.recv(65536) == b""       # FIN: the child is gone
        except (BlockingIOError, ssl.SSLWantReadError):
            pass
        except OSError:
            gone = True
        if gone:
            break
        try:
            sock.setblocking(True)
        except OSError:
            break
    return time.time() - start, sent


def _hold(name, sock, chunks, gap, deadline, recv_timeout, sink):
    """One drip attack, and the two things its result has to satisfy.

    Verdicts go into `sink` rather than straight to stdout: the three
    shapes are run concurrently (they are three independent clients, and
    running them one after another would cost three deadlines of wall
    clock), so the output is ordered by shape afterwards rather than by
    whichever thread finished first.
    """
    limit = deadline + 15
    held, sent = _drip(sock, chunks, gap, limit)
    try:
        sock.close()
    except OSError:
        pass

    sink.append((held <= deadline + 4,
                 f"[{name}] the connection ended at CONN_DEADLINE "
                 f"(held {held:.1f}s, deadline {deadline}s)"))
    # Non-vacuity: a drip that the receive timeout killed proves nothing
    # about the deadline. The hold has to have outlived RECV_TIMEOUT.
    sink.append((held > recv_timeout + gap,
                 f"[{name}] the drip outlived RECV_TIMEOUT on the way there "
                 f"({held:.1f}s > {recv_timeout}s, {sent} chunks sent)"))


def campaign_deadline(port, pid, deadline, recv_timeout):
    gap = max(0.25, recv_timeout / 2.0)
    n = int((deadline + 15) / gap) + 4
    ok = True
    shapes = []

    # 1. HTTP/1: a request header, one byte at a time.
    header = (b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: "
              + b"a" * 4096 + b"\r\n\r\n")
    s = socket.create_connection((HOST, port), timeout=5)
    shapes.append(("http1-drip", s, [header[i:i + 1] for i in range(n)], []))

    # 2. h2c: the preface, then a SETTINGS frame one byte at a time.
    s = socket.create_connection((HOST, port), timeout=5)
    s.sendall(H2_PREFACE)
    settings = sim.settings_frame([(0x3, 100), (0x4, 65535)])
    chunks = [settings[i:i + 1] for i in range(len(settings))]
    chunks += [b"\x00"] * n                      # then dribble a frame header
    shapes.append(("h2c-drip", s, chunks[:n], []))

    # 3. TLS: a real ClientHello, then change_cipher_spec forever. RFC
    #    8446 Appendix D.4 requires tolerating these and sets no limit,
    #    so this is the one drip the protocol itself asks for.
    hello = capture_client_hello()
    s = socket.create_connection((HOST, port), timeout=5)
    s.sendall(hello)
    time.sleep(0.3)
    try:
        s.setblocking(False)
        served = s.recv(65536)
    except OSError:
        served = b""
    finally:
        s.setblocking(True)
    started = served[:1] == b"\x16"
    shapes.append(("tls-ccs-flood", s, [CCS_RECORD] * n, []))

    threads = [threading.Thread(target=_hold,
                                args=(name, sock, chunks, gap, deadline,
                                      recv_timeout, sink))
               for name, sock, chunks, sink in shapes]
    for t in threads:
        t.start()
    for t in threads:
        t.join(deadline + 30)

    for name, _, _, sink in shapes:
        if name == "tls-ccs-flood":
            ok &= report(started,
                         f"[tls-ccs-flood] the handshake really started "
                         f"({len(served)} bytes of server flight)")
        if not sink:
            ok &= report(False, f"[{name}] the drip never finished")
        for verdict, desc in sink:
            ok &= report(verdict, desc)

    # Nothing above may have cost the server itself.
    ok &= report(http_get(port).startswith(b"HTTP/1.1 200"),
                 "the server still serves after every deadline expiry")
    return ok


# ── campaign: buffers ───────────────────────────────────────────────

def _plain_case(port, payload, hold, sampler):
    """Send `payload`, keep the socket open for `hold` seconds while the
    sampler watches, return the first line of the answer."""
    try:
        s = socket.create_connection((HOST, port), timeout=5)
    except OSError as exc:
        return b"<connect: %s>" % str(exc).encode()
    try:
        s.sendall(payload)
    except OSError:
        pass
    end = time.time() + hold
    while time.time() < end:
        sampler.sample()
        time.sleep(0.05)
    try:
        s.settimeout(3)
        data = s.recv(4096)
    except OSError:
        data = b""
    s.close()
    return data.split(b"\r\n", 1)[0]


def _h2c_stream_flood(port, sampler, streams=64, window=2.0):
    """More concurrent streams than SETTINGS_MAX_CONCURRENT_STREAMS
    advertises (32), opened in one flight so the server sees them all at
    once, plus an HPACK dynamic table stuffed as it goes."""
    try:
        s = socket.create_connection((HOST, port), timeout=5)
    except OSError:
        return 0
    out = bytearray(H2_PREFACE)
    out += sim.settings_frame([(0x3, 100), (0x4, 65535)])
    authority = f"localhost:{port}"
    for i in range(streams):
        block = sim.encode_request("/", authority, indexing=True)
        # every stream adds a distinct field, so the dynamic table is
        # pushed at its 4096-byte / 128-entry cap rather than reusing
        # one entry over and over
        block += sim.hpack_new_field(f"x-pad-{i}", "z" * 64, True)
        out += sim.frame(sim.FRAME_HEADERS, 0x4 | 0x1, 1 + 2 * i, bytes(block))
    try:
        s.sendall(bytes(out))
    except OSError:
        pass
    got = 0
    end = time.time() + window
    s.settimeout(0.25)
    while time.time() < end:
        sampler.sample()
        try:
            chunk = s.recv(65536)
        except (socket.timeout, BlockingIOError):
            continue
        except OSError:
            break
        if not chunk:
            break
        got += len(chunk)
    s.close()
    return got


def _tls_h2_case(port, sampler):
    """One ordinary TLS 1.3 + h2 request, sampled while it runs — the
    most .bss any well-behaved connection touches."""
    try:
        c = tls_context().wrap_socket(
            socket.create_connection((HOST, port), timeout=5),
            server_hostname="localhost")
    except (OSError, ssl.SSLError):
        return
    try:
        authority = f"localhost:{port}"
        c.sendall(H2_PREFACE + sim.settings_frame([(0x3, 100), (0x4, 65535)])
                  + sim.frame(sim.FRAME_HEADERS, 0x4 | 0x1, 1,
                              sim.encode_request("/", authority)))
        end = time.time() + 0.5
        c.settimeout(0.2)
        while time.time() < end:
            sampler.sample()
            try:
                if not c.recv(65536):
                    break
            except (socket.timeout, ssl.SSLError):
                continue
            except OSError:
                break
    finally:
        try:
            c.close()
        except OSError:
            pass


def campaign_buffers(port, pid):
    ok = True

    # Phase 1 — plain traffic, to establish what a child costs when
    # nobody is attacking it.
    #
    # All three protocols, not just HTTP/1: an h2 child touches the frame
    # and stream buffers an HTTP/1 child never faults in, and a TLS child
    # touches the record buffers and the key schedule on top of that. A
    # baseline taken over GETs alone would attribute those pages to the
    # attack in phase 2 and fail on the server working normally.
    baseline = RssSampler(pid)
    for _ in range(16):
        _plain_case(port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    0.05, baseline)
    for _ in range(2):
        _h2c_stream_flood(port, baseline, streams=4, window=0.6)
        _tls_h2_case(port, baseline)
    ok &= report(baseline.samples > 0,
                 f"the sampler saw the server's children "
                 f"({baseline.samples} samples, peak {baseline.peak} KB)")

    # Phase 2 — the same measurement, under everything that might make a
    # buffer grow. Each case also states what the server is expected to
    # answer, so a case that stops reaching its bound is visible.
    hostile = RssSampler(pid)
    cases = [
        ("header past BUF_SIZE",
         b"GET / HTTP/1.1\r\nHost: localhost\r\nX-A: " + b"b" * 65000
         + b"\r\n\r\n", b"HTTP/1.1 431"),
        ("path past its cap",
         b"GET /" + b"a" * 8192 + b" HTTP/1.1\r\nHost: localhost\r\n\r\n",
         b"HTTP/1.1 414"),
        ("600 header lines",
         b"GET / HTTP/1.1\r\nHost: localhost\r\n"
         + b"".join(b"X-%d: y\r\n" % i for i in range(600)) + b"\r\n", None),
        ("Content-Length past 2^63",
         b"POST / HTTP/1.1\r\nHost: localhost\r\n"
         b"Content-Length: 99999999999999999999\r\n\r\n", None),
        ("TLS record at the maximum",
         bytes.fromhex("160303") + (16640).to_bytes(2, "big")
         + b"\x00" * 16640, None),
        ("TLS record past the maximum",
         bytes.fromhex("160303") + (65535).to_bytes(2, "big")
         + b"\x00" * 4096, None),
        ("h2c frame past SETTINGS_MAX_FRAME_SIZE",
         H2_PREFACE + sim.settings_frame([(0x4, 65535)])
         + sim.frame(sim.FRAME_HEADERS, 0x4, 1, b"\x00" * 65536), None),
    ]
    for name, payload, expect in cases:
        got = _plain_case(port, payload, 0.35, hostile)
        if expect is not None:
            ok &= report(got.startswith(expect),
                         f"[{name}] answered {expect.decode()} "
                         f"(got {got[:48]!r})")

    got = _h2c_stream_flood(port, hostile)
    ok &= report(got > 0,
                 f"[64 concurrent h2c streams] the server answered "
                 f"({got} bytes back)")

    ok &= report(hostile.peak <= RSS_CEILING_KB,
                 f"no child exceeds {RSS_CEILING_KB} KB resident under the "
                 f"hostile corpus (peak {hostile.peak} KB)")
    # The property sarm's no-allocation design actually promises: the
    # attacker cannot choose how much memory the server uses.
    ok &= report(hostile.peak <= baseline.peak + RSS_GROWTH_KB,
                 f"peak resident size does not grow with the input "
                 f"(plain {baseline.peak} KB, hostile {hostile.peak} KB, "
                 f"limit +{RSS_GROWTH_KB} KB)")

    ok &= report(http_get(port).startswith(b"HTTP/1.1 200"),
                 "the server still serves after the whole corpus")
    return ok


# ── campaign: cpu ───────────────────────────────────────────────────

def _cpu_per_conn(pid, fn, n):
    """CPU seconds the server spent per connection, over `n` of them.

    Run against a `no_fork` server, so the connections are served by the
    process being measured rather than by children whose accounting dies
    with them.
    """
    before = cpu_seconds(pid)
    done = 0
    for _ in range(n):
        try:
            fn()
            done += 1
        except (OSError, ssl.SSLError):
            pass
    after = cpu_seconds(pid)
    if before is None or after is None or done == 0:
        return None, done
    return (after - before) / done, done


def _speak(port, payload, wait=0.15):
    s = socket.create_connection((HOST, port), timeout=3)
    try:
        s.sendall(payload)
        s.settimeout(wait)
        while True:
            if not s.recv(65536):
                break
    except OSError:
        pass
    finally:
        s.close()


def campaign_cpu(port, pid, count):
    ok = True
    hello = capture_client_hello()
    bad = truncated_key_share(hello)
    ok &= report(bad is not None and bad != hello,
                 "the ClientHello's key_share was found and corrupted")
    if bad is None:
        return False

    # Non-vacuity, twice over: the real handshake has to succeed, and the
    # corrupted one has to fail. Without both, the ratio below is
    # comparing two of the same thing.
    try:
        c = tls_context().wrap_socket(
            socket.create_connection((HOST, port), timeout=5),
            server_hostname="localhost")
        alpn = c.selected_alpn_protocol()
        c.close()
        handshake_ok = alpn == "h2"
    except (OSError, ssl.SSLError) as exc:
        handshake_ok = False
        alpn = str(exc)
    ok &= report(handshake_ok,
                 f"a well-formed TLS 1.3 handshake completes (ALPN {alpn!r})")

    s = socket.create_connection((HOST, port), timeout=5)
    s.sendall(bad)
    s.settimeout(2)
    try:
        answer = s.recv(65536)
    except OSError:
        answer = b""
    s.close()
    ok &= report(answer[:1] != b"\x16",
                 f"the truncated key_share is rejected, not served "
                 f"({len(answer)} bytes back)")

    def full():
        c = tls_context().wrap_socket(
            socket.create_connection((HOST, port), timeout=5),
            server_hostname="localhost")
        c.close()

    measured = {}
    for name, fn, n in (
        ("http1", lambda: _speak(
            port, b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                  b"Connection: close\r\n\r\n"), count),
        ("tls-junk", lambda: _speak(port, b"\x16\x03\x01\x00\x05hello"), count),
        ("tls-bad-key-share", lambda: _speak(port, bad), count),
        ("tls-handshake", full, max(1, count // 2)),
    ):
        per, done = _cpu_per_conn(pid, fn, n)
        measured[name] = per
        if per is None:
            ok &= report(False, f"[{name}] CPU time could not be measured")
            continue
        ok &= report(per * 1000 <= CPU_CEILING_MS,
                     f"[{name}] {per * 1000:.3f} ms of CPU per connection "
                     f"(ceiling {CPU_CEILING_MS} ms, {done} connections)")

    full_cost = measured.get("tls-handshake")
    if full_cost:
        # Non-vacuity for the ratio: if a complete handshake were free,
        # every rejection would trivially be "cheaper" than one.
        ok &= report(full_cost * 1000 > 0.005,
                     f"a complete handshake is measurably expensive "
                     f"({full_cost * 1000:.3f} ms)")
        for name in ("tls-junk", "tls-bad-key-share"):
            cheap = measured.get(name)
            if cheap is None:
                continue
            ratio = full_cost / cheap if cheap else float("inf")
            ok &= report(ratio >= CPU_REJECT_RATIO,
                         f"[{name}] is rejected before the key exchange "
                         f"({ratio:.1f}x cheaper than a handshake, "
                         f"floor {CPU_REJECT_RATIO}x)")
    return ok


# ── the measurements' own test ──────────────────────────────────────

def self_test():
    """Before trusting a clean run, check the instruments read anything
    at all. Every campaign above is a comparison between two numbers this
    file produced; a `ps` that silently returns nothing, or a CPU clock
    that never advances, would make all of them pass."""
    ok = True

    sleeper = subprocess.Popen([sys.executable, "-c",
                                "import time; time.sleep(30)"])
    time.sleep(0.4)
    try:
        kids = children_of(os.getpid())
        ok &= report(any(p == sleeper.pid for p, _ in kids),
                     f"children_of finds a known child ({len(kids)} found)")
        ok &= report(all(rss > 0 for _, rss in kids),
                     "children_of reads a non-zero resident size")
        ok &= report(children_of(1 << 30) == [],
                     "children_of finds no children of a pid that has none")
    finally:
        sleeper.terminate()
        sleeper.wait()

    burner = subprocess.Popen([sys.executable, "-c",
                               "x=0\nwhile True: x+=1"])
    try:
        time.sleep(0.2)
        first = cpu_seconds(burner.pid)
        time.sleep(0.8)
        second = cpu_seconds(burner.pid)
        ok &= report(first is not None and second is not None,
                     "cpu_seconds reads a running process")
        if first is not None and second is not None:
            ok &= report(second > first,
                         f"cpu_seconds advances for a busy process "
                         f"({first:.3f}s -> {second:.3f}s)")
    finally:
        burner.terminate()
        burner.wait()

    hello = capture_client_hello()
    ok &= report(len(hello) > 100 and hello[:1] == b"\x16",
                 f"a ClientHello can be captured ({len(hello)} bytes)")
    bad = truncated_key_share(hello)
    ok &= report(bad is not None and len(bad) == len(hello) and bad != hello,
                 "the key_share corruption changes exactly the length field")
    return ok


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("campaign", nargs="?",
                    choices=["connections", "deadline", "buffers", "cpu"])
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--pid", type=int)
    ap.add_argument("--deadline", type=int, default=120)
    ap.add_argument("--recv-timeout", type=int, default=10)
    ap.add_argument("--connections", type=int, default=48)
    ap.add_argument("--cpu-cases", type=int, default=1200)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    args = ap.parse_args()

    if args.help:
        print(__doc__.strip())
        return 0
    if args.self_test:
        return 0 if self_test() else 1
    if not args.campaign or args.port is None or args.pid is None:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    if args.campaign == "connections":
        ok = campaign_connections(args.port, args.pid, args.recv_timeout,
                                  args.connections)
    elif args.campaign == "deadline":
        ok = campaign_deadline(args.port, args.pid, args.deadline,
                               args.recv_timeout)
    elif args.campaign == "buffers":
        ok = campaign_buffers(args.port, args.pid)
    else:
        ok = campaign_cpu(args.port, args.pid, args.cpu_cases)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
