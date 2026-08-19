#!/usr/bin/env python3
"""Socket-level checks for sarm's pre-forked accept workers.

Plan.md Phase 3, Steps 15-16. Two properties that need real concurrent
connections and real process inspection, so they don't fit in tests/unit/:

  spread    every worker actually accepts -- connections held open at the
            same time must land on more than one worker (Step 15)
  inflight  a connection already being served survives the shutdown of the
            process that forked the workers, and no worker is orphaned by
            it (Step 16)

Driven by tests/test_workers.sh, which starts the server; this script only
ever inspects and signals processes it was told about. Prints the same
OK:/FAIL: lines the other harnesses' Python halves do.
"""

import socket
import subprocess
import sys
import time

REQ = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"


def sarm_processes(port):
    """[(pid, ppid)] for every running sarm serving `port`."""
    out = subprocess.run(["ps", "-eo", "pid,ppid,args"],
                         capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, ppid, args = parts
        if "sarm" in args and f" {port}" in args and "ps -eo" not in args:
            try:
                found.append((int(pid), int(ppid)))
            except ValueError:
                continue
    return found


def ok(msg):
    print(f"OK: {msg}")


def fail(msg):
    print(f"FAIL: {msg}")


def check_spread(port, expected_workers, nconn):
    """Hold nconn connections open at once; count the workers that accepted.

    Each connection is served by a child forked from whichever worker
    accepted it, so the children's parent pids are the sample.
    """
    workers = {pid for pid, _ in sarm_processes(port)}
    if len(workers) != expected_workers:
        fail(f"expected {expected_workers} workers before connecting, saw {len(workers)}")
        return False

    held = []
    try:
        for _ in range(nconn):
            held.append(socket.create_connection(("127.0.0.1", port), timeout=5))
        time.sleep(1.0)  # let every worker get its children forked

        counts = {}
        for pid, ppid in sarm_processes(port):
            if ppid in workers:
                counts[ppid] = counts.get(ppid, 0) + 1

        served = sum(counts.values())
        if served < nconn * 0.8:
            fail(f"only {served} of {nconn} connections had a child process")
            return False
        if len(counts) < expected_workers:
            fail(f"only {len(counts)} of {expected_workers} workers accepted "
                 f"anything (spread: {sorted(counts.values(), reverse=True)})")
            return False
        ok(f"all {expected_workers} workers accept: "
           f"{nconn} held connections spread "
           f"{'/'.join(str(counts[w]) for w in sorted(counts))}")
        return True
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass


def check_inflight(port, parent_pid):
    """A connection mid-session must outlive the shutdown of its worker's parent."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        s.sendall(REQ)
        first = s.recv(4096)
        if b"200" not in first.split(b"\r\n")[0]:
            fail(f"keep-alive connection did not get a 200 (got {first[:40]!r})")
            return False

        subprocess.run(["kill", "-TERM", str(parent_pid)], check=False)
        time.sleep(1.0)

        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        s.settimeout(5)
        try:
            second = s.recv(4096)
        except (socket.timeout, ConnectionResetError):
            second = b""
        if not second:
            fail("in-flight connection was dropped by the shutdown")
            return False
        ok("in-flight connection finishes after shutdown "
           "(per-connection children are not signalled)")

        remaining = [pid for pid, _ in sarm_processes(port) if pid == parent_pid]
        listeners = [pid for pid, ppid in sarm_processes(port) if ppid == parent_pid]
        if remaining or listeners:
            fail(f"shutdown left workers behind: {remaining + listeners}")
            return False
        ok("shutdown left no worker behind while that connection was open")
        return True
    finally:
        try:
            s.close()
        except OSError:
            pass


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode, port = sys.argv[1], int(sys.argv[2])
    if mode == "spread":
        return 0 if check_spread(port, int(sys.argv[3]), int(sys.argv[4])) else 1
    if mode == "inflight":
        return 0 if check_inflight(port, int(sys.argv[3])) else 1
    print(f"unknown mode {mode}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
