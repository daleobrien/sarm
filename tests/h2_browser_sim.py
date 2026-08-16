#!/usr/bin/env python3
"""sarm HTTP/2 browser simulator.

A dependency-free raw HTTP/2 client (its own frame writer and just enough
HPACK to encode a request) that reproduces the frame patterns a real
browser produces — the ones curl and nghttp do not, because they grant
huge flow-control windows up front and drive one request at a time.

Every scenario prints the per-stream outcome, so a stall shows up as
"STALLED" with the byte count where it stopped, and a connection the
server tears down shows up as a GOAWAY line with its error code.

Scenarios
  page-load    two-phase load: GET /, then the subresources the HTML
               references, acking DATA with WINDOW_UPDATEs (the healthy
               baseline — everything should complete)
  burst        every request in one flight, before any response is read
  no-credit    like page-load but never sends a WINDOW_UPDATE; shows how
               far a response gets on the initial 65535-byte window
  reload       repeats the page load N times on ONE connection, which is
               how a browser blows past the 32-entry stream table
  late-wu      opens enough streams to recycle the table, then sends a
               WINDOW_UPDATE for the very first stream
  settings-resize
               raises SETTINGS_INITIAL_WINDOW_SIZE while a stream is open,
               which RFC 9113 §6.9.2 says must retroactively widen it

Usage
  ./tests/h2_browser_sim.py                 # page-load on :8443
  ./tests/h2_browser_sim.py --port 8080 reload
  ./tests/h2_browser_sim.py all             # every scenario in turn
"""

import argparse
import socket
import ssl
import struct
import sys
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS = 0x0, 0x1, 0x4
FRAME_GOAWAY, FRAME_WINDOW_UPDATE = 0x7, 0x8
FLAG_END_STREAM, FLAG_END_HEADERS = 0x1, 0x4

FRAME_NAMES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
               4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
               8: "WINDOW_UPDATE", 9: "CONTINUATION"}

H2_ERRORS = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
             3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT",
             5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
             8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR",
             11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY",
             13: "HTTP_1_1_REQUIRED"}

# the page sarm serves out of www/ — index.html first, then what it links
DOCUMENT = "/"
SUBRESOURCES = ["/favicon.svg", "/logo.png", "/manifest.json",
                "/assets/index-Q2Xld2VX.js", "/assets/index-pzx_VsSR.css"]

# what Safari puts on every request; the long cookie is what pushes the
# HPACK dynamic table into eviction after a handful of requests
BROWSER_HEADERS = [
    ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 "
                   "Safari/605.1.15"),
    ("cookie", "test=test; Idea-3312c333=6454e962-02e2-4de4-8551-208fa3b614ed"),
    ("accept", "*/*"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-AU,en;q=0.9"),
]

GRN, RED, YLW, CLR = "\033[0;32m", "\033[0;31m", "\033[0;33m", "\033[0m"


# ── HPACK (encode side only) ─────────────────────────────────────────
# Enough of RFC 7541 to build a request: integers (§5.1), raw literal
# strings (§5.2 without Huffman), and the two literal field forms (§6.2).

def hpack_int(value, prefix_bits, mask):
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([mask | value])
    out = bytearray([mask | limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_str(text):
    raw = text.encode()
    return hpack_int(len(raw), 7, 0x00) + raw


def hpack_field(index, value, indexed):
    """Literal with an indexed name. `indexed` = incremental indexing
    (§6.2.1), which is what makes the server's dynamic table grow."""
    mask, bits = (0x40, 6) if indexed else (0x00, 4)
    return hpack_int(index, bits, mask) + hpack_str(value)


def hpack_new_field(name, value, indexed):
    mask, bits = (0x40, 6) if indexed else (0x00, 4)
    return hpack_int(0, bits, mask) + hpack_str(name) + hpack_str(value)


def encode_request(path, authority, indexing=True):
    """Encode one GET. `indexing` mirrors what a browser's encoder does —
    it adds the repeated fields to the dynamic table so later requests can
    reference them. Turning it off keeps the server's dynamic table empty,
    which is how you tell an HPACK bug apart from a stream-table one."""
    block = bytearray()
    block += hpack_field(2, "GET", False)        # static 2  — :method
    block += hpack_field(6, "https", False)      # static 6  — :scheme
    block += hpack_field(4, path, False)         # static 4  — :path
    block += hpack_field(1, authority, indexing)  # static 1 — :authority
    for name, value in BROWSER_HEADERS:
        block += hpack_new_field(name, value, indexing)
    return bytes(block)


# ── framing ──────────────────────────────────────────────────────────

def frame(ftype, flags, stream_id, payload=b""):
    return (struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) +
            struct.pack(">I", stream_id) + payload)


def settings_frame(pairs):
    body = b"".join(struct.pack(">HI", k, v) for k, v in pairs)
    return frame(FRAME_SETTINGS, 0, 0, body)


def window_update(stream_id, increment):
    return frame(FRAME_WINDOW_UPDATE, 0, stream_id,
                 struct.pack(">I", increment))


class Connection:
    """One HTTP/2 connection, driven frame by frame."""

    def __init__(self, port, initial_window=65535, conn_window_update=0,
                 verbose=False, indexing=True):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE       # sarm ships a self-signed cert
        ctx.set_alpn_protocols(["h2"])
        self.sock = ctx.wrap_socket(socket.create_connection(("localhost", port)),
                                    server_hostname="localhost")
        self.alpn = self.sock.selected_alpn_protocol()
        self.authority = f"localhost:{port}"
        self.verbose = verbose
        self.indexing = indexing
        self.buf = b""
        self.next_id = 1
        self.paths = {}          # stream id -> path
        self.body = {}           # stream id -> bytes received
        self.complete = set()
        self.headers_seen = set()
        self.goaway = None
        self.closed = False

        opening = PREFACE + settings_frame([(0x3, 100), (0x4, initial_window)])
        if conn_window_update:
            opening += window_update(0, conn_window_update)
        self.sock.sendall(opening)

    # -- sending ------------------------------------------------------
    def request(self, path):
        """Queue one GET; returns its stream id (not yet flushed)."""
        sid = self.next_id
        self.next_id += 2
        self.paths[sid] = path
        self.body[sid] = 0
        return sid, frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM,
                          sid, encode_request(path, self.authority,
                                              self.indexing))

    def send(self, data):
        if data and not self.closed:
            try:
                self.sock.sendall(data)
            except (BrokenPipeError, ssl.SSLError, ConnectionResetError):
                self.closed = True

    def get(self, paths):
        """Send every path as one flight, the way a browser does."""
        out, ids = b"", []
        for path in paths:
            sid, data = self.request(path)
            ids.append(sid)
            out += data
        self.send(out)
        return ids

    # -- receiving ----------------------------------------------------
    def pump(self, seconds, ack_windows=True):
        """Read frames for up to `seconds`, acking DATA the way a browser
        drains its receive buffer. Returns early on GOAWAY or EOF."""
        deadline = time.time() + seconds
        while time.time() < deadline and not self.closed:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLError):
                return
            except ConnectionResetError:
                self.note(f"{RED}connection reset by server{CLR}")
                self.closed = True
                return
            if not chunk:
                self.note(f"{RED}server closed the connection (EOF){CLR}")
                self.closed = True
                return
            self.buf += chunk
            if not self._drain(ack_windows):
                return

    def _drain(self, ack_windows):
        """Parse whole frames out of self.buf. False = stop pumping."""
        while len(self.buf) >= 9:
            length = int.from_bytes(self.buf[:3], "big")
            if len(self.buf) < 9 + length:
                return True
            ftype, flags = self.buf[3], self.buf[4]
            sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
            payload = self.buf[9:9 + length]
            self.buf = self.buf[9 + length:]

            if self.verbose:
                self.note(f"  <- {FRAME_NAMES.get(ftype, hex(ftype)):<13} "
                          f"stream {sid:<3} len {length}")

            if ftype == FRAME_DATA:
                self.body[sid] = self.body.get(sid, 0) + length
                if length and ack_windows:
                    # a browser credits both the connection and the stream
                    self.send(window_update(0, length) +
                              window_update(sid, length))
            elif ftype == FRAME_HEADERS:
                self.headers_seen.add(sid)
            elif ftype == FRAME_GOAWAY:
                last = int.from_bytes(payload[:4], "big")
                code = int.from_bytes(payload[4:8], "big")
                self.goaway = (last, code)
                self.note(f"{RED}GOAWAY{CLR} last_stream={last} "
                          f"error={code} ({H2_ERRORS.get(code, '?')})")
                self.closed = True
                return False
            if flags & FLAG_END_STREAM and ftype in (FRAME_DATA, FRAME_HEADERS):
                self.complete.add(sid)
        return True

    def note(self, text):
        print(f"    {text}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # -- reporting ----------------------------------------------------
    def report(self, only=None):
        ids = only if only is not None else list(self.paths)
        failures = 0
        for sid in ids:
            size = self.body.get(sid, 0)
            if sid in self.complete:
                state, colour = "COMPLETE", GRN
            elif sid in self.headers_seen:
                state, colour = "STALLED", RED
                failures += 1
            else:
                state, colour = "NO RESPONSE", RED
                failures += 1
            print(f"    stream {sid:>3}  {self.paths[sid]:<30} "
                  f"{size:>7} bytes  {colour}{state}{CLR}")
        return failures


# ── scenarios ────────────────────────────────────────────────────────

def scenario_page_load(args):
    """Two-phase load: the document, then its subresources."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    print("  phase 1 — GET /")
    c.get([DOCUMENT])
    c.pump(args.wait)
    print("  phase 2 — subresources")
    c.get(SUBRESOURCES)
    c.pump(args.wait)
    failures = c.report()
    c.close()
    return failures


def scenario_burst(args):
    """Every request in a single flight, before any response is read."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    c.get([DOCUMENT] + SUBRESOURCES)
    c.pump(args.wait)
    failures = c.report()
    c.close()
    return failures


def scenario_no_credit(args):
    """Never grant flow-control credit — shows where a response stops."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    print("  (no WINDOW_UPDATEs — responses should stop at the initial window)")
    c.get([DOCUMENT] + SUBRESOURCES)
    c.pump(args.wait, ack_windows=False)
    c.report()
    c.close()
    return 0     # stalling here is the correct server behaviour


def scenario_reload(args):
    """Reload the page N times on ONE connection.

    A browser keeps its connection and reuses it across navigations, so
    the stream ids climb without bound. sarm's stream table holds 32
    entries and recycles the closed ones, which is where a connection
    that has served a few pages starts behaving differently from a fresh
    one."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    failures = 0
    for page in range(1, args.reloads + 1):
        ids = c.get([DOCUMENT] + SUBRESOURCES)
        c.pump(args.wait)
        bad = c.report(only=ids)
        highest = max(ids)
        status = f"{RED}FAILED{CLR}" if bad else f"{GRN}ok{CLR}"
        print(f"  page {page} (streams up to {highest}): {status}")
        failures += bad
        if c.closed:
            print(f"  {RED}connection died after {page} page load(s){CLR}")
            break
    c.close()
    return failures


def scenario_late_wu(args):
    """WINDOW_UPDATE for a stream the table has since recycled.

    RFC 9113 §5.1 requires a WINDOW_UPDATE that arrives for a stream in
    the "closed" state to be ignored — the peer may well have had it in
    flight when we sent END_STREAM. Only a genuinely idle stream (an id
    the connection has never opened) is a PROTOCOL_ERROR.

    A server that drops closed streams from a fixed table cannot tell the
    two apart by lookup alone, so the id it targets matters: this aims at
    the most recently completed stream, the one a bounded table is most
    likely to have just reused, and the one whose WINDOW_UPDATE is most
    likely to still be in flight."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    first, recent = None, None
    for _ in range(args.streams):
        previous = recent
        ids = c.get(["/logo.png"])
        first = first or ids[0]
        recent = ids[0]
        c.pump(0.4)
        if c.closed:
            break
    print(f"  opened and completed {len(c.complete)} streams "
          f"(ids {first}..{c.next_id - 2})")
    if c.closed:
        print(f"  {RED}connection already gone{CLR}")
        return 1
    targets = [t for t in (previous, recent, first) if t]
    print(f"  now sending late WINDOW_UPDATEs for closed streams {targets}")
    for target in targets:
        c.send(window_update(target, 65535))
    c.pump(1.5)
    if c.goaway:
        print(f"  {RED}FAILED{CLR} — a closed stream's WINDOW_UPDATE killed "
              f"the connection")
        return 1
    if c.closed:
        print(f"  {RED}FAILED{CLR} — connection closed")
        return 1
    print(f"  {GRN}ok{CLR} — WINDOW_UPDATE ignored, connection healthy")
    return 0


def scenario_settings_resize(args):
    """Raise SETTINGS_INITIAL_WINDOW_SIZE while a stream is already open.

    RFC 9113 §6.9.2: a SETTINGS_INITIAL_WINDOW_SIZE that changes mid
    connection MUST adjust the send window of every stream that is
    already open by the difference — the new value is not just for
    streams opened later. A client that grants its credit this way (a
    big INITIAL_WINDOW_SIZE plus connection-level WINDOW_UPDATEs, and no
    per-stream WINDOW_UPDATE at all) will hang on any response larger
    than the initial 65535-byte window if the server ignores the
    adjustment."""
    c = Connection(args.port, conn_window_update=args.conn_window,
                   verbose=args.verbose, indexing=not args.no_indexing)
    print(f"  ALPN: {c.alpn}")
    print("  requesting the large asset on the default 65535 stream window")
    ids = c.get([p for p in SUBRESOURCES if "index-Q2Xld2VX" in p] or
                [SUBRESOURCES[-1]])
    c.pump(1.5, ack_windows=False)
    before = c.body.get(ids[0], 0)
    print(f"  {before} bytes in before the window ran out")
    print("  raising SETTINGS_INITIAL_WINDOW_SIZE to 1048576")
    c.send(settings_frame([(0x4, 1048576)]))
    # connection-level credit only — the stream's credit must come from
    # the SETTINGS adjustment, which is the thing under test
    c.send(window_update(0, 1048576))
    c.pump(args.wait, ack_windows=False)
    failures = c.report(only=ids)
    if ids[0] not in c.complete:
        print(f"  {RED}FAILED{CLR} — stalled at {c.body.get(ids[0], 0)} bytes; "
              f"the open stream's window was not adjusted (§6.9.2)")
    else:
        print(f"  {GRN}ok{CLR} — the open stream picked up the new window")
    c.close()
    return failures


SCENARIOS = {
    "page-load": scenario_page_load,
    "settings-resize": scenario_settings_resize,
    "burst": scenario_burst,
    "no-credit": scenario_no_credit,
    "reload": scenario_reload,
    "late-wu": scenario_late_wu,
}


def main():
    ap = argparse.ArgumentParser(
        description="Reproduce browser HTTP/2 frame patterns against sarm.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="scenarios: " + ", ".join(SCENARIOS) + ", all")
    ap.add_argument("scenario", nargs="?", default="page-load",
                    choices=list(SCENARIOS) + ["all"])
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--wait", type=float, default=4.0,
                    help="seconds to wait for a phase's responses")
    ap.add_argument("--conn-window", type=int, default=10485760,
                    help="connection WINDOW_UPDATE sent up front (0 = none)")
    ap.add_argument("--reloads", type=int, default=6,
                    help="page loads for the reload scenario")
    ap.add_argument("--streams", type=int, default=40,
                    help="streams to open for the late-wu scenario")
    ap.add_argument("--paths", nargs="+", metavar="PATH",
                    help="override the page's resources (first is the "
                         "document); handy for isolating whether a failure "
                         "needs the large asset's flow-control stall")
    ap.add_argument("--no-indexing", action="store_true",
                    help="encode requests without HPACK incremental "
                         "indexing, leaving the server's dynamic table empty")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every frame received")
    args = ap.parse_args()

    if args.paths:
        globals()["DOCUMENT"] = args.paths[0]
        globals()["SUBRESOURCES"] = args.paths[1:]

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    failures = 0
    for name in names:
        print(f"\n{YLW}── {name} ──{CLR}")
        try:
            failures += SCENARIOS[name](args)
        except (ConnectionRefusedError, OSError) as exc:
            print(f"  {RED}cannot reach localhost:{args.port} — {exc}{CLR}")
            print(f"  start the server first:  ./sarm {args.port} d")
            return 2
    print()
    if failures:
        print(f"{RED}{failures} stream(s) did not complete{CLR}")
    else:
        print(f"{GRN}all streams completed{CLR}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
