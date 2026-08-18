# Requests-per-second benchmark — HTTP/1.1, HTTP/2, HTTP/2+TLS

`scripts/benchmarks/rps_bench.sh` measures sustained throughput for all
three protocol paths sarm serves, against one running instance on one
port. sarm auto-detects the protocol per connection by peeking the
first byte (`src/sarm/main.S`): `0x16` → TLS handshake, `PRI *
HTTP/2.0` preface → HTTP/2 prior knowledge (h2c), anything else →
HTTP/1.1 (see `tests/test_protocols.sh`, `src/tls/server/README.md`).

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback.

---

## The one-line answer

Plaintext HTTP/2 is ~14x HTTP/1.1's throughput on this server, and TLS
1.3 costs almost nothing on top of that once connections are warm:

| Protocol | Req/s |
|---|---:|
| HTTP/1.1 | 16,806.64 |
| HTTP/2 (h2c, plaintext) | 247,442.00 |
| HTTP/2 + TLS 1.3 | 238,297.80 |

(4 threads, 20 connections, 5 s, `GET /`, all zero failed/errored
requests except HTTP/1.1's own socket churn — see §3.)

---

## 1. Tools

- **HTTP/1.1** — [`wrk`](https://github.com/wg/wrk), duration-based
  (`-d`), keep-alive.
- **HTTP/2 (h2c)** — [`h2load`](https://nghttp2.org/) with
  `--no-tls-proto=h2c`: RFC 9113 §3.4 prior knowledge, no TLS
  involved.
- **HTTP/2 + TLS** — `h2load` against `https://`, same host/port. TLS
  1.3, ALPN `h2` is negotiated automatically (sarm's cert is the
  self-signed `certs/cert.pem`, CN `localhost`); `h2load` doesn't
  verify server certificates, so no `-k`/`--insecure` equivalent is
  needed.

Both `h2load` runs use `-D<seconds>` (timing-based mode) rather than a
fixed request count (`-n`) — `-n` is silently ignored once `-D` is
set, and a duration match lets all three benchmarks report throughput
over the same wall-clock window.

## 2. Running it

```bash
./scripts/benchmarks/rps_bench.sh                                   # build + benchmark, defaults
./scripts/benchmarks/rps_bench.sh --no-build                        # reuse existing ./sarm binary
./scripts/benchmarks/rps_bench.sh --duration 15 --connections 100 --threads 4
./scripts/benchmarks/rps_bench.sh --path /pretty/index.html
./scripts/benchmarks/rps_bench.sh --json                            # machine-readable summary line
```

The script builds `sarm` (`make production`), starts it on a scratch
port derived from the PID (or `--port`), waits for it to answer, runs
the three benchmarks in sequence against that one instance, then kills
it. Full tool output goes to stderr; the summary (or `--json` line)
goes to stdout.

## 3. Notes on the numbers

- sarm is single-process, connection-per-loop (no fork) — one
  connection is serviced at a time. This mostly matters for benchmark
  *configuration*, not results: `h2load`'s fixed-request-count mode
  (`-n`) can undercount successes when more clients are configured
  than requests needed, because clients get torn down mid-flight at
  the connection level; duration-based mode (`-D`) doesn't hit this
  and is what the script uses.
- The HTTP/1.1 `wrk` run reports nonzero socket read errors under
  concurrent keep-alive load (e.g. ~10k errors over ~90k requests at
  `-c 20`) that don't appear in the HTTP/2 runs. `Requests/sec` from
  `wrk` already nets these out; they're flagged here as a known
  characteristic of the HTTP/1.1 path worth a closer look separately,
  not a benchmark-script artifact.
- TLS's overhead in the table above (~4%) is per-request throughput at
  steady state (warm connections, `-D` duration mode) — it does not
  include the one-time handshake cost per new connection, which is a
  separate, per-connection fixed cost (see `docs/ENTROPY-SOURCE.md`
  and `docs/P256-FIXED-BASE-COMB.md` for what's currently on sarm's
  handshake hot path).
