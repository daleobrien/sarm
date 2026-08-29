---
name: sarm-load-test
description: How to load-test sarm and read the results — scripts/benchmarks/rps_bench.sh (requests-per-second over HTTP/1.1, h2c, and HTTP/2+TLS against a live server instance) and tests/h2_browser_sim.py for frame-level HTTP/2 correctness under browser-like load. Use whenever asked to load-test, measure throughput/RPS, or check server performance under concurrent connections.
---

# Load-testing sarm

`scripts/benchmarks/rps_bench.sh` is the load test: it builds `make
production`, starts `sarm` on a scratch port, and drives it with `wrk`
(HTTP/1.1), `h2load --no-tls-proto=h2c` (h2c), and `h2load` over TLS
(HTTP/2+TLS against the repo's self-signed `certs/cert.pem`) — all three
against the *same* server instance, since sarm auto-detects protocol per
connection.

```bash
./scripts/benchmarks/rps_bench.sh                              # build + full load test
./scripts/benchmarks/rps_bench.sh --no-build                   # reuse existing binary
./scripts/benchmarks/rps_bench.sh --duration 15 --connections 100 --threads 4
./scripts/benchmarks/rps_bench.sh --path /pretty/index.html
./scripts/benchmarks/rps_bench.sh --workers 4                  # N pre-forked accept workers
./scripts/benchmarks/rps_bench.sh --json                       # machine-readable summary
./scripts/benchmarks/rps_bench.sh --target 10.0.1.7:8080       # server on another machine
./scripts/benchmarks/rps_bench.sh --target host:8080 --only h2tls
```

Requires `curl`, plus `wrk` for the HTTP/1.1 leg and `h2load` for the two
HTTP/2 legs — the script checks only what the selected protocols need and
exits 2 with a clear message if any are missing. `make` is required only
when it is doing the build.

**A same-box number is a floor, not a ceiling.** Without `--target`, the
client and the server share the machine, and `h2load` costs roughly 4x
what sarm costs per request — so the figure describes the split, not the
server. `--target HOST:PORT` drives a server running elsewhere: nothing is
built, nothing is started, and every core here belongs to the client.
`--server-cpus` is rejected with `--target` (that pinning is the other
box's job); `--only h1,h2c,h2tls` selects protocols.

For a throughput number worth quoting, rent the two machines:

```bash
./scripts/aws/rps_two_box_ec2.sh --yes       # small sarm box + large load box
```

It puts sarm on a `c7g.2xlarge` (8 vCPU) and the load on a box sized
`--load-ratio` (default 8) times that, in one availability zone and one
cluster placement group, over private addresses — the zone and the
RFC1918 address are re-checked after launch, so no cross-zone or egress
traffic is billed.

It samples `/proc/stat` on **both** boxes across each protocol's window.
Read the verdict before any req/s figure:

- `CLIENT-BOUND` — the load box peaked above 85%; the figures are the
  load generator's ceiling. Re-run with a higher `--load-ratio`.
- `SERVER SATURATED` — the server stayed busy and the client had room to
  spare. Only then are the numbers sarm's.
- a percentage — the server never saturated; raise `--max-streams` or
  `--conns-per-core`, or use a smaller `--server-type`.

`--max-streams` stops helping at 32: that is `MAX_CONCURRENT_STREAMS` in
`src/defs.S`, which sarm advertises in SETTINGS and h2load obeys, so
`-m128` opens the same 32 streams per connection that `-m32` does. It is
the default for that reason. Past it the only ways up are raising that
constant and rebuilding, or adding connections — and connections past the
core count oversubscribe the one-process-per-connection server. The
summary says which case you are in.

Use duration mode (the default; `--duration`), not a fixed request count:
a fixed-request-count mode undercounts once more clients are configured
than requests are needed.

**Connection count is part of the result.** sarm runs one process per
connection, so `--connections` above the machine's logical CPU count
measures oversubscription, not the server: 282k req/s h2c at `-c4` down to
93k at `-c50` on a 12-core box, same binary. Past the core count the metric
also goes bimodal (P-core vs E-core placement), so one run can read 170k or
290k for the same build. Compare builds at half the core count or below,
with `--repeat` (median of N passes, printed with the spread). The script
warns when the connection count is too high for the machine.

**Read a single sweep with suspicion.** Stage-to-stage differences on this
machine have been as large as the background load moving underneath them.
Run at least three repeats, quote the spread, and when comparing two builds
interleave them and alternate which goes first — otherwise drift lands
entirely on whichever ran last. The Phase 4 measurements in
`docs/MULTICORE-BASELINE.md` show what that changes.

`--workers` only shows up in a benchmark that opens connections. `wrk` and
`h2load` both hold their connections open, so worker count is invisible
here by design; the accept path is measured by connection rate instead.

## Frame-level correctness under load

For HTTP/2 correctness under realistic browser patterns (not throughput),
use `tests/h2_browser_sim.py` instead:

```bash
./tests/h2_browser_sim.py all              # every scenario
./tests/h2_browser_sim.py burst --streams 20 -v
```

Scenarios: `page-load`, `burst`, `no-credit`, `reload`, `late-wu`,
`settings-resize`, `all`. Knobs: `--paths`, `--no-indexing`, `--reloads`,
`--streams`, `--conn-window`, `-v`. Exits non-zero on any incomplete stream.

## Related skills

- General build/test → [sarm-build-test](../sarm-build-test/SKILL.md)
- Per-function micro-benchmarks (not end-to-end load) → [sarm-benchmark](../sarm-benchmark/SKILL.md)
- Where a connection's CPU time actually goes → [sarm-profile](../sarm-profile/SKILL.md)
