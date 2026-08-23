#!/usr/bin/env python3
"""End-to-end workload profiler for sarm (docs/SCRIPTS.md).

Drives the server the way a browser does — TLS 1.3 handshake, HTTP/2
preface and SETTINGS, GETs for the embedded assets, close — and reports
where the *server's* CPU time goes.

The client is `tests/h2_browser_sim.py`'s Connection, reused verbatim, so
the frame patterns are the ones the correctness suite already exercises.

Why server CPU and not wall clock
---------------------------------
The client is Python. On the transfer-heavy scenarios Python's own TLS
record decryption costs an order of magnitude more than sarm's encryption,
so wall clock measures the client, not the server. sarm is run as a child
process and its CPU time is read from `getrusage(RUSAGE_CHILDREN)` after
it exits, which counts only the server. Wall clock is reported too, and
labelled for what it is.

The server is run with the `no_fork` debug flag (`./sarm d`), so every
connection is served in one process and that process's rusage is the whole
workload. That fixes the port at 8080 — main.S only inspects argv[1].

Scenarios
  handshake   N separate connections, each: handshake, one small GET, close
  transfer    one connection, M GETs for the largest embedded asset
  request     one connection, M GETs for the smallest embedded asset
  noise       the handshake scenario's harness with zero connections, to
              establish the floor below which a difference is not real

Usage
  python3 scripts/profile_workload.py                  # all scenarios
  python3 scripts/profile_workload.py --rounds 7 --json out.json
"""

from __future__ import annotations

import argparse
import json
import resource
import socket
import ssl
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))

import h2_browser_sim as sim  # noqa: E402  (path set above)

PORT = 8080                    # forced: `./sarm d` cannot also take a port
LARGE_ASSET = "/assets/index-Q2Xld2VX.js"   # 76739 bytes served
SMALL_ASSET = "/logo.png"                   # 104 bytes served
FLIGHT = 8                     # requests in flight; the stream table holds 32


# ── server lifecycle ─────────────────────────────────────────────────

class Server:
    """`./sarm d` as a child process, with its CPU time measured."""

    def __init__(self, binary: Path):
        self.binary = binary
        self.proc = None
        self.before = None

    def __enter__(self):
        self.before = resource.getrusage(resource.RUSAGE_CHILDREN)
        self.proc = subprocess.Popen(
            [str(self.binary), "d"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(REPO))
        _wait_for_listener(PORT)
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        self.user = after.ru_utime - self.before.ru_utime
        self.sys = after.ru_stime - self.before.ru_stime
        return False

    @property
    def cpu(self) -> float:
        return self.user + self.sys


def _wait_for_listener(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("localhost", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.02)
    raise SystemExit(f"server never listened on :{port}")


# ── client ───────────────────────────────────────────────────────────

class Connection(sim.Connection):
    """The simulator's connection with a completion-aware read loop.

    `sim.Connection.pump` reads until its deadline expires, which is what
    a correctness test wants (it is looking for frames that should *not*
    arrive). A benchmark must return the instant the streams it asked for
    are done, or every measurement is dominated by the timeout."""

    def pump_until(self, ids, seconds=20.0):
        deadline = time.time() + seconds
        pending = set(ids)
        while pending - self.complete and not self.closed:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except (socket.timeout, ssl.SSLError, ConnectionResetError):
                return
            if not chunk:
                self.closed = True
                return
            self.buf += chunk
            if not self._drain(True):
                return


# ── workloads ────────────────────────────────────────────────────────
# Each returns (connections, requests, response_bytes) actually completed,
# so the cost model divides by what happened rather than what was asked.

def workload_handshake(connections: int):
    total_bytes = 0
    for _ in range(connections):
        c = Connection(PORT, conn_window_update=1 << 20)
        ids = c.get([SMALL_ASSET])
        c.pump_until(ids)
        _require(c, ids)
        total_bytes += sum(c.body.values())
        c.close()
    return connections, connections, total_bytes


def workload_stream(requests: int, path: str):
    c = Connection(PORT, conn_window_update=1 << 24)
    done = 0
    while done < requests:
        batch = min(FLIGHT, requests - done)
        ids = c.get([path] * batch)
        c.pump_until(ids)
        _require(c, ids)
        done += batch
    total_bytes = sum(c.body.values())
    c.close()
    return 1, done, total_bytes


def workload_pageload(pages: int):
    """The real thing: one fresh connection per page, document then
    subresources, exactly as tests/h2_browser_sim.py's page-load does.

    This is the closure check on the linear model — handshake + 6 requests
    + 80 kB should predict it."""
    total_bytes = 0
    for _ in range(pages):
        c = Connection(PORT, conn_window_update=1 << 24)
        ids = c.get([sim.DOCUMENT])
        c.pump_until(ids)
        _require(c, ids)
        ids = c.get(sim.SUBRESOURCES)
        c.pump_until(ids)
        _require(c, ids)
        total_bytes += sum(c.body.values())
        c.close()
    return pages, pages * (1 + len(sim.SUBRESOURCES)), total_bytes


def workload_noise(_):
    """Everything the harness does except talk to the server."""
    return 0, 0, 0


def _require(conn, ids):
    missing = [i for i in ids if i not in conn.complete]
    if missing or conn.goaway:
        raise SystemExit(f"workload failed: incomplete streams {missing} "
                         f"goaway={conn.goaway}")


# ── measurement ──────────────────────────────────────────────────────

def run_round(binary: Path, workload, size):
    with Server(binary) as server:
        t0 = time.perf_counter()
        connections, requests, nbytes = workload(size)
        wall = time.perf_counter() - t0
    return {
        "wall_s": wall,
        "cpu_s": server.cpu,
        "user_s": server.user,
        "sys_s": server.sys,
        "connections": connections,
        "requests": requests,
        "bytes": nbytes,
    }


def summarise(name, rounds, size):
    cpu = [r["cpu_s"] for r in rounds]
    wall = [r["wall_s"] for r in rounds]
    user = [r["user_s"] for r in rounds]
    sysd = [r["sys_s"] for r in rounds]
    med = statistics.median(cpu)
    spread = (max(cpu) - min(cpu)) / med * 100 if med else 0.0
    return {
        "scenario": name,
        "size": size,
        "rounds": len(rounds),
        "cpu_median_s": med,
        "cpu_min_s": min(cpu),
        "cpu_max_s": max(cpu),
        "cpu_spread_pct": spread,
        "user_median_s": statistics.median(user),
        "sys_median_s": statistics.median(sysd),
        "wall_median_s": statistics.median(wall),
        "connections": rounds[0]["connections"],
        "requests": rounds[0]["requests"],
        "bytes": rounds[0]["bytes"],
    }


SCENARIOS = {
    "noise":     (workload_noise, [0]),
    "handshake": (workload_handshake, [50, 100, 200]),
    "transfer":  (lambda n: workload_stream(n, LARGE_ASSET), [50, 100, 200]),
    "request":   (lambda n: workload_stream(n, SMALL_ASSET), [500, 1000, 2000]),
    "pageload":  (workload_pageload, [50, 100, 200]),
}


def fit(points):
    """Least-squares slope/intercept of cpu vs workload size.

    The intercept is the fixed cost the scenario pays once (process start,
    and for the single-connection scenarios the TLS handshake); the slope
    is the marginal cost of one more unit. Reading the marginal cost off a
    single size folds the fixed cost into it, which at the sizes here is a
    30-60% error on the per-request number."""
    n = len(points)
    if n < 2:
        return None, None, None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = sum(xs) / n, sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return None, None, None
    slope = sum((x - mx) * (y - my) for x, y in points) / denom
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    resid = sum((y - (slope * x + intercept)) ** 2 for x, y in points)
    r2 = 1 - resid / ss_tot if ss_tot else 1.0
    return slope, intercept, r2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", nargs="*", default=list(SCENARIOS),
                    choices=list(SCENARIOS) + [[]])
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--binary", type=Path, default=REPO / "sarm")
    ap.add_argument("--size", type=int, default=None,
                    help="run this single workload size instead of the sweep")
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    if not args.binary.exists():
        raise SystemExit(f"no binary at {args.binary} — run `make` first")

    names = args.scenario or list(SCENARIOS)
    results = []
    for name in names:
        workload, default_sizes = SCENARIOS[name]
        sizes = [args.size] if args.size is not None else default_sizes
        print(f"\n╔═ {name} ═══════════════════════════════════")
        points = []
        for size in sizes:
            # one discarded warm-up round: first-touch page faults on a
            # 3.5 MB binary are a cost we do not want in the median
            run_round(args.binary, workload, size)
            rounds = [run_round(args.binary, workload, size)
                      for _ in range(args.rounds)]
            summary = summarise(name, rounds, size)
            summary["raw"] = rounds
            results.append(summary)
            report(summary)
            points.append((size, summary["cpu_median_s"]))
        if len(points) > 1:
            slope, intercept, r2 = fit(points)
            print(f"\n  fit over {[p[0] for p in points]}:")
            print(f"    marginal {slope * 1e6:9.2f} us/unit   "
                  f"fixed {intercept * 1e3:7.3f} ms   R^2 {r2:.4f}")
            results.append({"scenario": name, "fit": True,
                            "marginal_us": slope * 1e6,
                            "fixed_ms": intercept * 1e3, "r2": r2,
                            "sizes": [p[0] for p in points]})

    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
        print(f"\nwrote {args.json}")
    return 0


def report(s):
    print(f"\n── {s['scenario']} (size {s['size']}, {s['rounds']} rounds) ──")
    print(f"  server CPU   median {s['cpu_median_s'] * 1e3:9.2f} ms   "
          f"min {s['cpu_min_s'] * 1e3:.2f}  max {s['cpu_max_s'] * 1e3:.2f}  "
          f"spread {s['cpu_spread_pct']:.1f}%")
    print(f"    user {s['user_median_s'] * 1e3:8.2f} ms   "
          f"sys {s['sys_median_s'] * 1e3:8.2f} ms")
    print(f"  wall (client-bound) {s['wall_median_s'] * 1e3:9.2f} ms")
    if s["connections"]:
        print(f"  per connection {s['cpu_median_s'] / s['connections'] * 1e6:9.1f} us")
    if s["requests"]:
        print(f"  per request    {s['cpu_median_s'] / s['requests'] * 1e6:9.1f} us")
    if s["bytes"]:
        print(f"  per byte       {s['cpu_median_s'] / s['bytes'] * 1e9:9.2f} ns "
              f"({s['bytes']} bytes)")


if __name__ == "__main__":
    sys.exit(main())
