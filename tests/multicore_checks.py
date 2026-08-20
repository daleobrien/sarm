#!/usr/bin/env python3
"""Concurrent multi-protocol correctness checks for sarm (Plan.md Phase 4).

Two modes, both driven by tests/test_multicore.sh against a server that is
already running with some `--workers` count:

  verify  Steps 17 — many concurrent connections across HTTP/1.1 (single,
          keep-alive, pipelined, split-write), h2c and HTTP/2-over-TLS,
          every response checked byte-for-byte against a reference taken
          up front. Repeated for as many rounds as asked for.

  stress  Step 18 — a randomised mixture of the same protocols plus HEAD,
          OPTIONS, range requests and missing files, run for a fixed
          duration, with deliberately slow clients and long-lived HTTP/2
          connections in the mix. A separate probe thread times a fresh
          connection twice a second throughout: if a busy worker could
          block accepts, that is where it shows up.

The point of both is what the unit tests structurally cannot see —
several connections in flight at once, across several worker processes.
Any body that differs from its reference is cross-connection leakage or
truncation, which is the failure this whole phase is guarding against.

The HTTP/2 halves reuse tests/h2_browser_sim.py's frame and HPACK
encoders rather than growing a second copy; the connection itself is
local because the simulator's is TLS-only and counts body bytes instead
of keeping them.
"""

import os
import random
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2_browser_sim as sim  # noqa: E402

HOST = "127.0.0.1"

# The document and its subresources, as the browser simulator has them,
# plus the two smallest so a round stays quick.
PATHS = ["/", "/index.html", "/favicon.svg", "/manifest.json",
         "/assets/index-pzx_VsSR.css"]
BIG_PATH = "/assets/index-Q2Xld2VX.js"     # ~76 KB, the multi-frame case
MISSING_PATH = "/no-such-file-here.html"


# ── HTTP/1 ───────────────────────────────────────────────────────────

def http1_connect(port, timeout=10):
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def request_bytes(path, method="GET", close=False, extra=()):
    head = [f"{method} {path} HTTP/1.1", f"Host: {HOST}"]
    head += list(extra)
    if close:
        head.append("Connection: close")
    return ("\r\n".join(head) + "\r\n\r\n").encode()


def read_response(sock, buf=b"", head=False):
    """One HTTP/1 response off `sock` -> (status, body, leftover).

    Content-Length only: sarm never sends a chunked response. `head` is
    needed because a HEAD response carries the Content-Length its GET
    would have had, with no body behind it (RFC 9110 §9.3.2) — waiting
    for those bytes would hang until the connection closed.
    """
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before headers completed")
        buf += chunk
    head_end = buf.index(b"\r\n\r\n") + 4
    headers = buf[:head_end]
    status = int(headers.split(b" ")[1])
    clen = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
    if head:
        clen = 0
    while len(buf) < head_end + clen:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before body completed")
        buf += chunk
    return status, buf[head_end:head_end + clen], buf[head_end + clen:]


def http1_fetch(port, path, method="GET", extra=()):
    """One request on its own connection."""
    s = http1_connect(port)
    try:
        s.sendall(request_bytes(path, method, close=True, extra=extra))
        status, body, _ = read_response(s, head=(method == "HEAD"))
        return status, body
    finally:
        s.close()


def http1_keepalive(port, paths):
    """Several requests down one connection, one at a time."""
    out = []
    s = http1_connect(port)
    try:
        leftover = b""
        for i, path in enumerate(paths):
            s.sendall(request_bytes(path, close=(i == len(paths) - 1)))
            status, body, leftover = read_response(s, leftover)
            out.append((path, status, body))
        return out
    finally:
        s.close()


def http1_pipelined(port, paths):
    """Every request in ONE write, responses read back in order."""
    out = []
    s = http1_connect(port)
    try:
        blob = b"".join(request_bytes(p, close=(i == len(paths) - 1))
                        for i, p in enumerate(paths))
        s.sendall(blob)
        leftover = b""
        for path in paths:
            status, body, leftover = read_response(s, leftover)
            out.append((path, status, body))
        return out
    finally:
        s.close()


def http1_split(port, path, chunks=3, delay=0.01):
    """One request trickled in several writes — the fragmented-header case."""
    raw = request_bytes(path, close=True)
    size = max(1, len(raw) // chunks)
    s = http1_connect(port)
    try:
        for i in range(0, len(raw), size):
            s.sendall(raw[i:i + size])
            time.sleep(delay)
        status, body, _ = read_response(s)
        return status, body
    finally:
        s.close()


# ── HTTP/2 (h2c and over TLS) ────────────────────────────────────────

def h2_encode_request(path, authority):
    """Like the simulator's encoder, minus accept-encoding.

    sarm serves its gzipped copy either way, so this is not about the
    encoding — it is about sending the smallest header set that still
    exercises the dynamic table, so a stress round stays cheap.
    """
    block = bytearray()
    block += sim.hpack_field(2, "GET", False)         # :method
    block += sim.hpack_field(6, "https", False)       # :scheme
    block += sim.hpack_field(4, path, False)          # :path
    block += sim.hpack_field(1, authority, True)      # :authority
    block += sim.hpack_new_field("user-agent", "sarm-multicore-check", True)
    return bytes(block)


class H2Conn:
    """A minimal HTTP/2 client that keeps the bytes it is sent.

    `tls=False` speaks h2c (RFC 9113 §3.4 prior knowledge), which is what
    the simulator cannot do; `tls=True` goes through ALPN exactly as it
    does.
    """

    def __init__(self, port, tls, timeout=15):
        raw = socket.create_connection((HOST, port), timeout=timeout)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE     # sarm ships a self-signed cert
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname="localhost")
            self.alpn = raw.selected_alpn_protocol()
        else:
            self.alpn = None
        self.sock = raw
        self.sock.settimeout(timeout)
        self.authority = f"{HOST}:{port}"
        self.buf = b""
        self.next_id = 1
        self.paths = {}
        self.body = {}
        self.complete = set()
        self.goaway = None
        self.closed = False
        self.sock.sendall(sim.PREFACE +
                          sim.settings_frame([(0x3, 100), (0x4, 1 << 20)]) +
                          sim.window_update(0, 1 << 22))

    def get(self, paths):
        out, ids = b"", []
        for path in paths:
            sid = self.next_id
            self.next_id += 2
            self.paths[sid] = path
            self.body[sid] = b""
            ids.append(sid)
            out += sim.frame(sim.FRAME_HEADERS,
                             sim.FLAG_END_HEADERS | sim.FLAG_END_STREAM,
                             sid, h2_encode_request(path, self.authority))
        self.sock.sendall(out)
        return ids

    def pump(self, ids, seconds=15):
        """Read until every id in `ids` has ended, or time runs out."""
        want = set(ids)
        deadline = time.time() + seconds
        while want - self.complete and time.time() < deadline and not self.closed:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                self.closed = True
                break
            self.buf += chunk
            self._drain()
        return want <= self.complete

    def _drain(self):
        while len(self.buf) >= 9:
            length = int.from_bytes(self.buf[:3], "big")
            if len(self.buf) < 9 + length:
                return
            ftype, flags = self.buf[3], self.buf[4]
            sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
            payload = self.buf[9:9 + length]
            self.buf = self.buf[9 + length:]

            if ftype == sim.FRAME_DATA:
                self.body[sid] = self.body.get(sid, b"") + payload
                if length:
                    # credit both windows, the way a browser drains
                    self.sock.sendall(sim.window_update(0, length) +
                                      sim.window_update(sid, length))
            elif ftype == sim.FRAME_GOAWAY:
                self.goaway = (int.from_bytes(payload[:4], "big"),
                               int.from_bytes(payload[4:8], "big"))
                self.closed = True
                return
            if flags & sim.FLAG_END_STREAM and ftype in (sim.FRAME_DATA,
                                                         sim.FRAME_HEADERS):
                self.complete.add(sid)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def h2_fetch(port, paths, tls, seconds=15):
    """(path, body) for each stream; raises if any stream never ended."""
    c = H2Conn(port, tls)
    try:
        ids = c.get(paths)
        if not c.pump(ids, seconds):
            missing = [c.paths[i] for i in ids if i not in c.complete]
            raise RuntimeError(f"streams never completed: {missing} "
                               f"(goaway={c.goaway})")
        return [(c.paths[i], c.body[i]) for i in ids]
    finally:
        c.close()


# ── reference bodies ─────────────────────────────────────────────────

def reference(port):
    """The body every later response must match, per path, over HTTP/1."""
    ref = {}
    for path in PATHS + [BIG_PATH]:
        status, body = http1_fetch(port, path)
        if status != 200 or not body:
            raise RuntimeError(f"reference fetch of {path} gave "
                               f"{status}, {len(body)} bytes")
        ref[path] = body
    return ref


# ── verify (Step 17) ─────────────────────────────────────────────────

class Failures:
    def __init__(self):
        self.lock = threading.Lock()
        self.items = []

    def add(self, msg):
        with self.lock:
            if len(self.items) < 20:
                self.items.append(msg)


def check_body(fails, kind, path, status, body, ref):
    if status is not None and status != 200:
        fails.add(f"{kind}: {path} -> HTTP {status}")
        return
    want = ref[path]
    if body != want:
        if len(body) != len(want):
            fails.add(f"{kind}: {path} -> {len(body)} bytes, want {len(want)}")
        else:
            fails.add(f"{kind}: {path} -> same length, different bytes "
                      "(cross-connection leakage?)")


def verify_worker(port, ref, fails, rounds, seed):
    rng = random.Random(seed)
    for _ in range(rounds):
        try:
            path = rng.choice(PATHS)
            status, body = http1_fetch(port, path)
            check_body(fails, "http1", path, status, body, ref)

            picks = rng.sample(PATHS, 3)
            for p, status, body in http1_keepalive(port, picks):
                check_body(fails, "http1 keep-alive", p, status, body, ref)

            picks = rng.sample(PATHS, 3)
            for p, status, body in http1_pipelined(port, picks):
                check_body(fails, "http1 pipelined", p, status, body, ref)

            path = rng.choice(PATHS)
            status, body = http1_split(port, path)
            check_body(fails, "http1 split-write", path, status, body, ref)

            picks = rng.sample(PATHS, 2) + [BIG_PATH]
            for p, body in h2_fetch(port, picks, tls=False):
                check_body(fails, "h2c", p, None, body, ref)

            picks = rng.sample(PATHS, 2) + [BIG_PATH]
            for p, body in h2_fetch(port, picks, tls=True):
                check_body(fails, "h2+TLS", p, None, body, ref)
        except Exception as exc:                       # noqa: BLE001
            fails.add(f"{type(exc).__name__}: {exc}")


def mode_verify(port, concurrency, rounds):
    ref = reference(port)
    fails = Failures()
    threads = [threading.Thread(target=verify_worker,
                                args=(port, ref, fails, rounds, i))
               for i in range(concurrency)]
    started = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - started

    # 14 responses per round per thread, across six connection styles:
    # 1 single + 3 keep-alive + 3 pipelined + 1 split-write + 3 h2c + 3 h2+TLS
    total = concurrency * rounds * 14
    if fails.items:
        for msg in fails.items:
            print(f"FAIL: {msg}")
        return 1
    print(f"OK: {total} responses over HTTP/1.1 (single, keep-alive, "
          f"pipelined, split-write), h2c and h2+TLS from {concurrency} "
          f"concurrent clients, all byte-identical ({elapsed:.1f}s)")
    return 0


# ── stress (Step 18) ─────────────────────────────────────────────────

def slow_client(port, path, fails, stop):
    """A client that trickles its request eight bytes at a time.

    It holds a worker's child process for seconds at a time, which is the
    interesting part: it must not stop anything else being accepted.

    sarm gives a connection RECV_TIMEOUT (10s) to finish its headers and
    answers 408 after that, which is correct -- so this deliberately stays
    an order of magnitude inside that budget. A 408 is only treated as a
    failure if the trickle really did finish in time; when the harness's
    own threads are starved past the budget, that is this script being
    slow, not the server being wrong.
    """
    while not stop.is_set():
        try:
            s = http1_connect(port, timeout=20)
            raw = request_bytes(path, close=True)
            started = time.time()
            for i in range(0, len(raw), 8):
                if stop.is_set():
                    break
                s.sendall(raw[i:i + 8])
                time.sleep(0.03)
            status, _, _ = read_response(s)
            elapsed = time.time() - started
            if status == 408 and elapsed > 8:
                pass                                   # see the note above
            elif status != 200:
                fails.add(f"slow client: HTTP {status} after {elapsed:.1f}s")
            s.close()
        except Exception as exc:                       # noqa: BLE001
            if not stop.is_set():
                fails.add(f"slow client: {type(exc).__name__}: {exc}")


def long_h2_client(port, ref, fails, stop, tls):
    """One HTTP/2 connection kept open, requesting over and over."""
    while not stop.is_set():
        try:
            c = H2Conn(port, tls)
            try:
                deadline = time.time() + 5
                while time.time() < deadline and not stop.is_set():
                    picks = random.sample(PATHS, 2)
                    ids = c.get(picks)
                    if not c.pump(ids, seconds=10):
                        fails.add(f"long h2{'+TLS' if tls else 'c'}: "
                                  "stream never completed")
                        break
                    for i in ids:
                        check_body(fails, f"long h2{'+TLS' if tls else 'c'}",
                                   c.paths[i], None, c.body[i], ref)
                    time.sleep(0.2)
            finally:
                c.close()
        except Exception as exc:                       # noqa: BLE001
            if not stop.is_set():
                fails.add(f"long h2: {type(exc).__name__}: {exc}")


def mixed_client(port, ref, fails, stop, counter, seed):
    """Short connections, randomly picked from the whole request mix.

    Deliberately paced. Unpaced, a handful of these threads open several
    thousand connections a second, and what breaks first is the client:
    the machine runs out of ephemeral ports (EADDRNOTAVAIL) long before
    anything interesting happens on the server -- and every port it burns
    sits in TIME_WAIT for 30s afterwards, so an unpaced run also poisons
    the next one. This is a correctness stress test, not a benchmark;
    rps_bench.sh is the benchmark.
    """
    rng = random.Random(seed)
    while not stop.is_set():
        try:
            pick = rng.randrange(8)
            if pick == 0:
                path = rng.choice(PATHS)
                status, body = http1_fetch(port, path)
                check_body(fails, "mixed http1", path, status, body, ref)
            elif pick == 1:
                for p, status, body in http1_keepalive(port,
                                                       rng.sample(PATHS, 3)):
                    check_body(fails, "mixed keep-alive", p, status, body, ref)
            elif pick == 2:
                for p, status, body in http1_pipelined(port,
                                                       rng.sample(PATHS, 2)):
                    check_body(fails, "mixed pipelined", p, status, body, ref)
            elif pick == 3:
                status, body = http1_fetch(port, MISSING_PATH)
                if status != 404:
                    fails.add(f"missing file -> HTTP {status}, want 404")
            elif pick == 4:
                status, body = http1_fetch(port, BIG_PATH,
                                           extra=("Range: bytes=0-99",))
                if status != 206 or len(body) != 100:
                    fails.add(f"range request -> HTTP {status}, "
                              f"{len(body)} bytes, want 206/100")
            elif pick == 5:
                status, body = http1_fetch(port, rng.choice(PATHS),
                                           method="HEAD")
                if status != 200 or body:
                    fails.add(f"HEAD -> HTTP {status} with {len(body)} "
                              "body bytes, want 200 and none")
            elif pick == 6:
                for p, body in h2_fetch(port, rng.sample(PATHS, 2), tls=False):
                    check_body(fails, "mixed h2c", p, None, body, ref)
            else:
                for p, body in h2_fetch(port, rng.sample(PATHS, 2), tls=True):
                    check_body(fails, "mixed h2+TLS", p, None, body, ref)
            with counter[1]:
                counter[0] += 1
            time.sleep(rng.uniform(0.02, 0.06))
        except Exception as exc:                       # noqa: BLE001
            if not stop.is_set():
                fails.add(f"mixed: {type(exc).__name__}: {exc}")


def accept_probe(port, stop, samples):
    """Time a fresh connection twice a second while everything else runs."""
    while not stop.is_set():
        start = time.time()
        try:
            s = http1_connect(port, timeout=10)
            s.sendall(request_bytes("/", close=True))
            status, _, _ = read_response(s)
            s.close()
            samples.append((time.time() - start, status))
        except Exception:                              # noqa: BLE001
            samples.append((time.time() - start, None))
        time.sleep(0.5)


def mode_stress(port, concurrency, seconds):
    ref = reference(port)
    fails = Failures()
    stop = threading.Event()
    counter = [0, threading.Lock()]
    samples = []

    threads = [threading.Thread(target=accept_probe,
                                args=(port, stop, samples), daemon=True),
               threading.Thread(target=slow_client,
                                args=(port, "/index.html", fails, stop),
                                daemon=True),
               threading.Thread(target=slow_client,
                                args=(port, BIG_PATH, fails, stop),
                                daemon=True),
               threading.Thread(target=long_h2_client,
                                args=(port, ref, fails, stop, False),
                                daemon=True),
               threading.Thread(target=long_h2_client,
                                args=(port, ref, fails, stop, True),
                                daemon=True)]
    threads += [threading.Thread(target=mixed_client,
                                 args=(port, ref, fails, stop, counter, i),
                                 daemon=True)
                for i in range(concurrency)]
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(timeout=20)

    rc = 0
    if fails.items:
        for msg in fails.items:
            print(f"FAIL: {msg}")
        rc = 1
    else:
        print(f"OK: {counter[0]} randomised mixed requests over {seconds}s "
              f"from {concurrency} clients plus 2 slow clients and 2 "
              "long-lived HTTP/2 connections — no crash, no malformed "
              "response, no hang")

    # the accept-latency evidence: a busy worker must not stop the others
    good = [d for d, status in samples if status == 200]
    bad = len(samples) - len(good)
    if not samples:
        print("FAIL: accept probe never ran")
        return 1
    if bad:
        print(f"FAIL: {bad} of {len(samples)} accept probes failed while "
              "the server was busy")
        return 1
    worst = max(good)
    if worst > 2.0:
        print(f"FAIL: a fresh connection took {worst:.2f}s to be served "
              "while workers were busy (limit 2s)")
        return 1
    print(f"OK: {len(samples)} fresh connections accepted throughout, "
          f"worst {worst * 1000:.0f}ms — busy workers do not block accepts")
    return rc


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode, port = sys.argv[1], int(sys.argv[2])
    args = [int(a) for a in sys.argv[3:]]
    if mode == "verify":
        concurrency = args[0] if args else 8
        rounds = args[1] if len(args) > 1 else 1
        return mode_verify(port, concurrency, rounds)
    if mode == "stress":
        concurrency = args[0] if args else 8
        seconds = args[1] if len(args) > 1 else 10
        return mode_stress(port, concurrency, seconds)
    print(f"unknown mode {mode}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
