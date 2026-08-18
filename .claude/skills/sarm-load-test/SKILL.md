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
./scripts/benchmarks/rps_bench.sh --json                       # machine-readable summary
```

Requires `wrk`, `h2load`, and `curl` on PATH — the script checks and exits
2 with a clear message if any are missing.

Use duration mode (the default; `--duration`), not a fixed request count:
sarm serves one connection at a time, so a fixed-request-count mode
undercounts once more clients are configured than requests are needed.

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
