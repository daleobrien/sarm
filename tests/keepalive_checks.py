#!/usr/bin/env python3
"""Raw-socket checks for sarm's HTTP/1 keep-alive (Plan.md Phase 1, Steps 5-6).

Prints one "OK: <description>" or "FAIL: <description>" line per check;
tests/test_keepalive.sh wraps this in the shared ok()/nope() reporting.
Not meant to be run standalone against anything but a freshly started,
otherwise-idle sarm instance -- it relies on exact response byte counts
and on the request budget starting fresh.
"""
import socket
import sys
import threading
import time

PORT = int(sys.argv[1])
HOST = "127.0.0.1"
results = []


def report(ok, desc):
    results.append((ok, desc))


def connect():
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(5)
    return s


def read_until_closed(sock):
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def read_one_response(sock, buf=b""):
    """Read exactly one HTTP/1 response (headers + body) off sock,
    returning (response_bytes, leftover_bytes_after_it)."""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before headers completed")
        buf += chunk
    head_end = buf.index(b"\r\n\r\n") + 4
    headers = buf[:head_end]
    clen = 0
    conn = None
    for line in headers.split(b"\r\n")[1:]:
        low = line.lower()
        if low.startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
        if low.startswith(b"connection:"):
            conn = line.split(b":", 1)[1].strip()
    total_needed = head_end + clen
    while len(buf) < total_needed:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("connection closed before body completed")
        buf += chunk
    return buf[:total_needed], buf[total_needed:], conn


REQ_INDEX = b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
REQ_LOGO_CLOSE = b"GET /logo.png HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"


# ── 1. two pipelined GETs in a single write() ───────────────────────
def check_pipelined_single_write():
    s = connect()
    s.sendall(REQ_INDEX + REQ_LOGO_CLOSE)
    data = read_until_closed(s)
    s.close()
    n = data.count(b"HTTP/1.1 ")
    if n != 2:
        report(False, f"pipelined single write: expected 2 responses, got {n}")
        return None
    if b"HTTP/1.1 200 OK" not in data.split(b"\r\n\r\n", 1)[0]:
        report(False, "pipelined single write: first response not 200")
        return None
    report(True, "two pipelined GETs in one write() -> two responses")
    return data


REFERENCE = check_pipelined_single_write()


# ── 2. the same pipelined pair, split at every byte boundary of req 1 ──
def check_split_boundaries():
    if REFERENCE is None:
        report(False, "split-boundary test skipped (no reference response)")
        return
    mismatches = []
    for boundary in range(len(REQ_INDEX) + 1):
        s = connect()
        s.sendall(REQ_INDEX[:boundary])
        time.sleep(0.005)
        s.sendall(REQ_INDEX[boundary:])
        s.sendall(REQ_LOGO_CLOSE)
        got = read_until_closed(s)
        s.close()
        if got != REFERENCE:
            mismatches.append(boundary)
    if mismatches:
        report(False, f"split-write at every byte boundary: {len(mismatches)} mismatches at {mismatches[:5]}...")
    else:
        report(True, f"split-write at all {len(REQ_INDEX) + 1} byte boundaries of request 1 -> byte-identical to single-write")


check_split_boundaries()


# ── 3. sequential keep-alive + the request budget ───────────────────
def check_budget():
    s = connect()
    count = 0
    closed_at = None
    try:
        for i in range(1, 102):
            s.sendall(REQ_INDEX)
            resp, _, conn = read_one_response(s)
            count += 1
            if not resp.startswith(b"HTTP/1.1 200"):
                report(False, f"budget test: request {i} did not return 200")
                s.close()
                return
            if conn == b"close":
                closed_at = i
                break
    except RuntimeError as e:
        report(False, f"budget test: {e}")
        s.close()
        return

    if closed_at != 100:
        report(False, f"budget test: expected Connection: close at request 100, got {closed_at!r}")
        s.close()
        return

    # the server must actually close after that -- a further read should
    # see EOF, not hang.
    s.settimeout(2)
    try:
        leftover = s.recv(1)
        if leftover:
            report(False, "budget test: connection stayed open past the 100th request")
        else:
            report(True, "request budget: 100th request gets Connection: close, then the socket actually closes")
    except socket.timeout:
        report(False, "budget test: connection neither closed nor sent data after the 100th request")
    s.close()


check_budget()


# ── 4. sequential keep-alive on a fresh connection, several distinct paths ──
def check_sequential_variety():
    paths = [b"/index.html", b"/logo.png", b"/nonexistent", b"/", b"/assets/style.css"]
    s = connect()
    try:
        for i, path in enumerate(paths):
            s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            resp, _, conn = read_one_response(s)
            if not resp.startswith(b"HTTP/1.1 "):
                report(False, f"sequential variety: bad response for {path!r}")
                s.close()
                return
            if i < len(paths) - 1 and conn != b"keep-alive":
                report(False, f"sequential variety: expected keep-alive after {path!r}, got {conn!r}")
                s.close()
                return
        report(True, f"{len(paths)} sequential requests (mixed 200/404) on one connection, all correct")
    except RuntimeError as e:
        report(False, f"sequential variety: {e}")
    s.close()


check_sequential_variety()


# ── 5. concurrent connections, each issuing sequential keep-alive requests ──
# Staggered starts: the listen backlog is still 5 at this point in the plan
# (Phase 2 / Step 7 raises it) so a true 100-at-once burst can drop SYNs --
# that is a pre-existing, separately tracked limitation, not something
# keep-alive changed. Staggering isolates the property this step owns.
def check_concurrent():
    paths = [b"/index.html", b"/logo.png", b"/nonexistent", b"/", b"/assets/style.css"]
    n_conns = 40
    per_conn = 10
    errors = []
    errors_lock = threading.Lock()

    def worker(idx):
        try:
            s = connect()
            for i in range(per_conn):
                path = paths[(idx + i) % len(paths)]
                s.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                resp, _, _ = read_one_response(s)
                if not resp.startswith(b"HTTP/1.1 "):
                    raise RuntimeError(f"conn {idx} req {i} ({path!r}): bad response")
            s.close()
        except Exception as e:  # noqa: BLE001 - reporting to the harness
            with errors_lock:
                errors.append(str(e))

    threads = []
    for i in range(n_conns):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
        time.sleep(0.005)
    for t in threads:
        t.join()

    if errors:
        report(False, f"{n_conns} concurrent connections x {per_conn} sequential requests: {len(errors)} failed, e.g. {errors[0]}")
    else:
        report(True, f"{n_conns} concurrent connections x {per_conn} sequential keep-alive requests each: all correct, no hangs")


check_concurrent()


# ── report ────────────────────────────────────────────────────────
for ok, desc in results:
    print(f"{'OK' if ok else 'FAIL'}: {desc}")

sys.exit(0 if all(ok for ok, _ in results) else 1)
