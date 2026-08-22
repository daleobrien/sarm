---
name: sarm-build-test
description: How to build sarm and run its test suites — make / make production, make test, the individual test_files.sh / test_security.sh / test_protocols.sh scripts, the tests/unit C suite, the tests/security guard-page, differential, integer-overflow and fuzzing suites (make test-security, including the TLS record and handshake fuzzers and the socket-fragmentation suites), and tests/h2_browser_sim.py. Use whenever asked to build the server, run tests, or check whether a change broke anything, before reaching for an ad-hoc build/test invocation.
---

# Building and testing sarm

Run from the repo root (`sarm.nosync/`). Full rationale: [docs/SCRIPTS.md](../../../docs/SCRIPTS.md).

## Build

```bash
make                 # debug build -> ./sarm
make production       # strip -x'd release build
make clean            # remove sarm, build/, generated embedded assets
```

`make` regenerates `src/embedded.S` (from `www/`) and `src/tls/cert_data.S`
(from `certs/`) automatically when their inputs change — no separate asset
step needed for a normal build.

## Tests

```bash
make test                       # everything: unit + files + security + protocols
make -C tests/unit              # unit suite alone (~4,300 assertions, C drivers vs the real .S files)
make test-security              # tests/security — bounds + differential + overflow + fuzz + fragmentation (docs/SECURITY.md)
./tests/test_files.sh           # asset integrity, ranges, MIME, ETag, gzip
./tests/test_security.sh        # traversal, encoding, oversize, malformed input (live binary, curl)
./tests/test_protocols.sh       # HTTP/1.1, h2c, HTTP/2-over-TLS end to end
./tests/test_workers.sh         # --workers parsing, accept spread, shutdown
./tests/test_leak.sh            # secret-leak probe (SECURITY.md Step 10)
./tests/test_syscalls.sh        # syscall allowlist + filesystem non-access (Step 11)
./tests/test_multicore.sh       # concurrent multi-protocol load across workers
./tests/h2_browser_sim.py all   # frame-level browser simulator (NOT part of `make test`, run separately)
```

`tests/test_multicore.sh` takes `--workers N`, `--iterations N` and
`--stress-seconds S`; `make test` runs it at 1, 2 and 4 workers with short
settings, and the long soaks are run by hand.

`tests/test_leak.sh` fires deterministic malformed traffic
(`tests/hostile_workload.py`) at a live server in both fork and `no_fork` mode,
captures every byte returned, and scans it for the embedded private scalar, any
12-byte run of it, certificate-adjacent memory, file content and the
per-connection request markers; it also asserts the server writes nothing to
stdout/stderr, leaves no core dump and never dies on a signal. `--cases N` /
`SARM_LEAK_CASES=N` scales it (default 150 per mode); `python3
tests/leak_checks.py --self-test` checks the scanner itself.

`tests/test_syscalls.sh` runs `scripts/syscall_audit.py` (every `svc` site in
the built binary and every `SCWINUM` in `src/`, against
`tests/syscall_allowlist.txt`) and then, where a tracer exists — `strace` on
Linux, `dtruss` as root on macOS — traces the same hostile workload and checks
no filesystem syscall appears. On macOS the trace is *skipped*, not passed; the
static audit is the platform-independent half and is the stronger claim. Both
are documented in [docs/security/leak-and-containment.md](../../../docs/security/leak-and-containment.md).

`make test` builds `sarm` first, so it's always the safe default after a
source change. The individual `test_*.sh` scripts accept `--no-build
--quiet` to reuse an existing binary — that's what `make test` passes
internally.

`tests/security/` is the newer, lower-level suite: guarded (guard-page)
buffers around individual assembly routines, so an out-of-bounds access traps
in hardware rather than silently landing in the next global, plus differential
suites that run each crypto routine and an independent C reference over
hundreds of thousands of random vectors, and overflow suites that feed a
hostile length corpus to the real HPACK and HKDF entry points with a guard page
immediately after the input, and fuzzers that run millions of generated TLS
records through the record layer, millions of generated ClientHellos,
flights and client Finished messages through the handshake and its driver, and
millions of generated HTTP/1 request headers through the parse module, the path
filters and the keep-alive predicate, and fragmentation suites that deliver the
same bytes to a real socket twice — once whole, once split at arbitrary
positions by a feeder thread — and compare every result and every delivered
byte. The differential suites take a seed and a
multiplier — `SARM_DIFF_SEED=0x1234` to replay a run, `SARM_DIFF_ITERS=100 make
test-security` for a long soak; the overflow suites need no environment at all.
The fuzz and fragmentation suites (`test_fuzz_tls_record`,
`test_fuzz_tls_handshake`, `test_fuzz_http`, `test_frag_socket`,
`test_frag_http`) take
`SARM_FUZZ_MULT=100` for a long soak, `SARM_FUZZ_STATS=1`
for the outcome histogram that shows which branches the corpus is reaching, and
`SARM_FUZZ_SEED=<s> SARM_FUZZ_CASE=<i>` to replay one case in-process under a
debugger — the reproducer every failure prints.
It links no part of the server and needs no built binary. Don't confuse it with
`tests/test_security.sh`, which probes a *running* server with `curl`. See
[tests/security/README.md](../../../tests/security/README.md),
[docs/security/threat-model.md](../../../docs/security/threat-model.md) and
[docs/security/length-audit.md](../../../docs/security/length-audit.md) and
[docs/security/fuzzing.md](../../../docs/security/fuzzing.md).

`tests/unit/` is generated in large part by the `scripts/*_derivation.py`
crypto scripts — see [verified-asm-crypto](../verified-asm-crypto/SKILL.md)
before hand-editing anything under `tests/unit/test_p256*`.

`tests/h2_browser_sim.py` simulates real browser HTTP/2 frame patterns
(stdlib `ssl`/`socket` + its own frame writer and encode-side HPACK) — this
is how flow-control bugs `curl`/`nghttp` both hid were found. Scenarios:
`page-load`, `burst`, `no-credit`, `reload`, `late-wu`, `settings-resize`,
`all`. Knobs: `--paths`, `--no-indexing`, `--reloads`, `--streams`,
`--conn-window`, `-v`. Exits non-zero on any incomplete stream.

## Related skills

- Load testing (throughput/RPS) → [sarm-load-test](../sarm-load-test/SKILL.md)
- Per-function micro-benchmarks → [sarm-benchmark](../sarm-benchmark/SKILL.md)
- Touching `src/crypto/` → [verified-asm-crypto](../verified-asm-crypto/SKILL.md)
