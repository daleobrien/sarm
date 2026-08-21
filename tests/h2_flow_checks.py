#!/usr/bin/env python3
"""HTTP/2 flow-control wait-path checks (h2c, raw sockets).

The wait path is what h2_write_body does when a response is larger than
the peer's flow-control window: it stops writing DATA, reads frames from
the client until a WINDOW_UPDATE grants credit, and dispatches them —
including serving a request that completes while it waits. Everything
here is about that path, because it is the only place in the server where
one request's I/O runs inside another's.

The checks are frame-level and cleartext on purpose. h2_browser_sim.py
covers the same server over TLS, where unparsed bytes live in the TLS
stage buffer; these run over h2c, where they live in `buf` alongside the
connection loop's own state, which is where the bug below could reach
them.

Usage: h2_flow_checks.py <port>     (started and stopped by test_h2_flow.sh)
Output: one "OK: ..." or "FAIL: ..." line per check.
"""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import h2_browser_sim as sim
from multicore_checks import (BIG_PATH, HOST, H2Conn, h2_encode_request,
                              http1_fetch)

PORT = int(sys.argv[1])

results = []


def report(ok, desc):
    results.append((ok, desc))


def big_settings(entries=2000):
    """A large but entirely legal SETTINGS frame (12000 bytes at the
    default). Every id is in the reserved-for-future-use range, which
    RFC 9113 §6.5.2 says a receiver must ignore, so the only thing this
    exercises is the size of the read that carries it."""
    return sim.frame(sim.FRAME_SETTINGS, 0, 0,
                     b"".join(struct.pack(">HI", 0xF000 + (i & 0xFFF), 0)
                              for i in range(entries)))


def drain(sock, streams, seconds, on_first_data=b""):
    """Read frames until every stream in `streams` ends or time runs out.

    Returns (bodies, headers_seen, goaway). `on_first_data` is sent once,
    immediately before the first window replenishment — the hook the
    clobber check below uses to make the server's wait-path read large.
    """
    buf = b""
    bodies = {sid: 0 for sid in streams}
    headers, done, goaway = set(), set(), None
    pending = on_first_data
    deadline = time.time() + seconds
    while time.time() < deadline and not done >= set(streams):
        sock.settimeout(max(0.05, deadline - time.time()))
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 9:
            length = int.from_bytes(buf[:3], "big")
            if len(buf) < 9 + length:
                break
            ftype, flags = buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            payload = buf[9:9 + length]
            buf = buf[9 + length:]
            if ftype == sim.FRAME_HEADERS:
                headers.add(sid)
            elif ftype == sim.FRAME_DATA:
                bodies[sid] = bodies.get(sid, 0) + length
                if length:
                    sock.sendall(pending + sim.window_update(0, length) +
                                 sim.window_update(sid, length))
                    pending = b""
            elif ftype == sim.FRAME_GOAWAY:
                goaway = int.from_bytes(payload[4:8], "big")
                return bodies, headers, goaway
            elif ftype == sim.FRAME_SETTINGS and not flags & 0x1:
                sock.sendall(sim.frame(sim.FRAME_SETTINGS, 0x1, 0))
            if flags & sim.FLAG_END_STREAM and ftype in (sim.FRAME_DATA,
                                                         sim.FRAME_HEADERS):
                done.add(sid)
    return bodies, headers, goaway


def opening_flight(authority, paths, initial_window=65535):
    """Preface + SETTINGS + one HEADERS per path, as one byte string, so
    the caller can put the whole thing in a single write."""
    out = sim.PREFACE + sim.settings_frame([(0x3, 100), (0x4, initial_window)])
    ids = []
    sid = 1
    for path in paths:
        ids.append(sid)
        out += sim.frame(sim.FRAME_HEADERS,
                         sim.FLAG_END_HEADERS | sim.FLAG_END_STREAM,
                         sid, h2_encode_request(path, authority))
        sid += 2
    return out, ids


# ── the size the whole file depends on ───────────────────────────────

def check_big_path_still_blocks():
    """Everything below needs BIG_PATH to exceed the 65535-byte default
    connection window — otherwise the wait path never runs and the checks
    pass without testing anything."""
    status, body = http1_fetch(PORT, BIG_PATH)
    if status != 200:
        report(False, f"{BIG_PATH} -> HTTP {status}, expected 200")
        return False
    if len(body) <= 65535:
        report(False, f"{BIG_PATH} is {len(body)} bytes, not over the "
                      f"65535-byte default window — the wait path would "
                      f"never run and these checks would be vacuous")
        return False
    report(True, f"{BIG_PATH} is {len(body)} bytes, over the 65535-byte "
                 f"default window (the wait path runs)")
    return True


# ── the checks ───────────────────────────────────────────────────────

def check_queued_request_survives_wait():
    """A second request queued behind a flow-controlled one is still
    served.

    Regression test. h2_write_body's wait loop used to read frames into
    `buf`, the connection loop's own buffer. A single read can deliver
    several frames, so the loop routinely holds bytes it has read but not
    yet parsed there — and the wait loop wrote over them. The connection
    then parsed whatever had landed as its next frame header: the queued
    request was lost and the connection desynchronised, which showed up
    as GOAWAY(FRAME_SIZE_ERROR). Frames read while waiting now land in
    h2_wait_buf.

    The large SETTINGS is what makes the failure deterministic: the
    wait-path read has to be long enough to reach the connection loop's
    parse cursor, and a bare WINDOW_UPDATE (13 bytes) is not.
    """
    sock = socket.create_connection((HOST, PORT), timeout=15)
    try:
        authority = f"{HOST}:{PORT}"
        flight, ids = opening_flight(authority, [BIG_PATH, "/index.html"])
        sock.sendall(flight)          # one write: both requests, one segment
        bodies, headers, goaway = drain(sock, ids, seconds=15,
                                        on_first_data=big_settings())
        big, queued = ids
        if goaway is not None:
            report(False, f"queued request behind a flow-controlled one: "
                          f"GOAWAY error_code={goaway} — the connection "
                          f"desynchronised")
            return
        if queued not in headers or bodies.get(queued, 0) == 0:
            report(False, f"queued request behind a flow-controlled one: "
                          f"stream {queued} got headers={queued in headers} "
                          f"body={bodies.get(queued, 0)} bytes — the request "
                          f"was destroyed while the first one waited")
            return
        report(True, f"a request queued behind a flow-controlled response "
                     f"survives the wait path ({bodies[big]} + "
                     f"{bodies[queued]} bytes, no GOAWAY)")
    finally:
        sock.close()


def check_request_arriving_during_wait():
    """A request that arrives *while* the server is out of credit is
    served from inside the wait loop, not left until the response ends.

    This is the browser pattern the recursion exists for: parallel
    page-load requests issued behind a large response.
    """
    sock = socket.create_connection((HOST, PORT), timeout=15)
    try:
        authority = f"{HOST}:{PORT}"
        flight, ids = opening_flight(authority, [BIG_PATH])
        sock.sendall(flight)
        # queue the second request behind the first DATA, i.e. once the
        # server is already writing and about to run out of window
        late = sim.frame(sim.FRAME_HEADERS,
                         sim.FLAG_END_HEADERS | sim.FLAG_END_STREAM, 3,
                         h2_encode_request("/index.html", authority))
        ids = ids + [3]
        bodies, headers, goaway = drain(sock, ids, seconds=15,
                                        on_first_data=late)
        if goaway is not None:
            report(False, f"request arriving during the wait: "
                          f"GOAWAY error_code={goaway}")
            return
        if 3 not in headers or bodies.get(3, 0) == 0:
            report(False, f"request arriving during the wait: stream 3 got "
                          f"headers={3 in headers} body={bodies.get(3, 0)} "
                          f"bytes — never served")
            return
        report(True, f"a request arriving while the server is out of credit "
                     f"is served from the wait loop ({bodies[3]} bytes)")
    finally:
        sock.close()


def check_large_response_intact():
    """The flow-controlled body itself is byte-for-byte the HTTP/1 body.

    The wait path splits the response across many DATA frames and many
    windows; this is the check that none of that loses or duplicates a
    byte.
    """
    status, want = http1_fetch(PORT, BIG_PATH)
    if status != 200:
        report(False, f"reference fetch of {BIG_PATH} -> HTTP {status}")
        return
    conn = H2Conn(PORT, tls=False)
    try:
        # a 65535 initial window, so the response has to wait for credit
        conn.sock.sendall(sim.settings_frame([(0x4, 65535)]))
        ids = conn.get([BIG_PATH])
        if not conn.pump(ids, seconds=15):
            report(False, f"{BIG_PATH} over h2c never completed "
                          f"(goaway={conn.goaway})")
            return
        got = conn.body[ids[0]]
        if got != want:
            report(False, f"{BIG_PATH} over h2c: {len(got)} bytes, expected "
                          f"{len(want)} — bodies differ")
            return
        report(True, f"a flow-controlled {len(want)}-byte response arrives "
                     f"byte-for-byte identical to the HTTP/1 body")
    finally:
        conn.close()


if check_big_path_still_blocks():
    check_queued_request_survives_wait()
    check_request_arriving_during_wait()
    check_large_response_intact()

for ok, desc in results:
    print(f"{'OK' if ok else 'FAIL'}: {desc}")

sys.exit(0 if all(ok for ok, _ in results) else 1)
