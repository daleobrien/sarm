# Optimization prompt series

A sequence of self-contained task prompts for making `sarm` run faster. Each
file is a complete brief for one AI coding agent session: context, objective,
constraints, method, deliverables, acceptance criteria.

## The workload these are written for

`sarm` serves **a small, fixed set of embedded static files over HTTP/2 with
TLS 1.3**. Assets are compiled into the binary and pre-compressed at build
time. There is no filesystem I/O and no runtime compression.

That shape determines where time goes, and it is not where the assembly's
*size* suggests:

| Cost | Paid | Dominated by |
|---|---|---|
| TLS 1.3 handshake | once per connection | P-256 scalar mult, ECDSA sign, X25519 |
| Response encryption | per byte served | AES-GCM (`aes128_encrypt` + `ghash`) |
| Transcript / key schedule | per connection | SHA-256, HKDF |
| Request parsing | per request | HPACK decode, H2 framing |
| Register save/restore | per call | prologue/epilogue traffic |

Two structural findings drive the ordering below, both verified in the source:

- `aes_gcm_encrypt` calls `aes128_encrypt` **once per 16-byte block**
  (`src/crypto/gcm/encrypt.S:100-112`), serializing the AESE dependency chain.
- `p256_point_mul` uses **naive double-and-add** over 256 bits
  (`src/crypto/p256_point/mul.S`), with no precomputed tables.

Both are order-of-magnitude opportunities. The register-pressure work
documented in `docs/REGISTER-PRESSURE.MD` is worth roughly 160 instructions
repo-wide — real, but a rounding error next to the two above. The series is
ordered accordingly, and prompt 00 exists to confirm that ordering with
measurement before anything is changed.

## Order

Run in sequence. 00 → 02 are prerequisites; nothing after them is trustworthy
without them.

| # | Prompt | Purpose |
|---|---|---|
| 00 | `00-workload-profile.md` | Measure where time actually goes. Gates everything else. |
| 01 | `01-analysis-tooling-correctness.md` | Fix the analyzer/ABI-checker defects. Safety prerequisite. |
| 02 | `02-benchmark-substrate.md` | Per-function benchmarks that can resolve a change. |
| 03 | `03-aes-gcm-throughput.md` | Multi-block AES-GCM. Largest per-byte win. |
| 04 | `04-p256-scalar-multiplication.md` | Precomputed comb tables. Largest per-connection win. |
| 05 | `05-register-overhead-experiment.md` | Is prologue/epilogue removal measurable? Decides 06/07. |
| 06 | `06-optimizer-strategy-framework.md` | Generalize the harness to pluggable strategies. |
| 07 | `07-register-transformations.md` | Automate the register transformation family. |
| 08 | `08-precomputed-response-path.md` | Precompute more of the response at build time. |
| 09 | `09-regression-protection.md` | Make every accepted win reproducible and permanent. |
| 10 | `10-embedded-lookup.md` | Resolve the half-built asset lookup. Small, independent. |

Prompt 10 is independent of the rest and can run at any point after 00 — it is
a good first task for validating the workflow, since it is small, well-bounded
and has a clear right answer.

Prompts 06 and 07 are **conditional**: run them only if 05 shows the overhead
is measurable. If it is not, say so and stop — that is a valid outcome.

## Invariants every prompt inherits

These hold for all work in this repository. Each prompt restates the ones it
most risks violating, but they always apply.

1. **Self-contained.** No external libraries, no dynamic allocation, no libc
   dependency beyond what the existing build uses.
2. **ABI.** AAPCS64, plus a repo convention: **36 functions return status in
   the carry flag** ("carry clear = success"). NZCV is part of the ABI. Never
   let a flag-setting instruction move between a status-setting site and `ret`.
   `strlen` takes its argument in **x1**, not x0.
3. **Constant time.** All of `src/crypto/p256*`, `x25519`, and the AES/GHASH
   paths must stay free of secret-dependent branches and secret-dependent
   memory addressing. Table lookups must scan every entry. This constraint
   outranks performance, always.
4. **Tests must pass.** `make -C tests/unit test`, plus `tests/test_files.sh`,
   `tests/test_security.sh`, `tests/test_protocols.sh`, and
   `tests/h2_browser_sim.py`.
5. **No stack or heap growth.** An optimization that trades registers for
   memory traffic is a regression.
6. **Both platforms.** `src/defs.S` branches on `#ifdef __linux__`; macOS uses
   `svc #0x80` and x16, Linux `svc #0` and x8. Do not break either.
7. **Measurement is the authority.** Never accept a change on static
   instruction count alone unless the prompt explicitly permits it and says why.

## Tooling reality on this machine

- Target: Apple M3 Pro, arm64, macOS. Results do not transfer to
  Cortex/Neoverse — record the target with every result.
- **No `perf`**, **no `llvm-mca`**. Hardware counters are unavailable. Use
  wall-clock with noise discipline plus `objdump` instruction counts.
- Available: `objdump`, `llvm-objdump`, `xctrace`, `ollama`.
- `python3 scripts/regpressure.py` — register-pressure report (read-only).
- `scripts/arm-optimize.py` — existing optimization harness.
