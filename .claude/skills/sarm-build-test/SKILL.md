---
name: sarm-build-test
description: How to build sarm and run its test suites — make / make production, make test, the individual test_files.sh / test_security.sh / test_protocols.sh scripts, the tests/unit C suite, and tests/h2_browser_sim.py. Use whenever asked to build the server, run tests, or check whether a change broke anything, before reaching for an ad-hoc build/test invocation.
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
./tests/test_files.sh           # asset integrity, ranges, MIME, ETag, gzip
./tests/test_security.sh        # traversal, encoding, oversize, malformed input
./tests/test_protocols.sh       # HTTP/1.1, h2c, HTTP/2-over-TLS end to end
./tests/h2_browser_sim.py all   # frame-level browser simulator (NOT part of `make test`, run separately)
```

`make test` builds `sarm` first, so it's always the safe default after a
source change. The individual `test_*.sh` scripts accept `--no-build
--quiet` to reuse an existing binary — that's what `make test` passes
internally.

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
