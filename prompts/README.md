# Optimization prompt series

A sequence of self-contained task prompts for making `sarm` run faster. Each
file is a complete brief for one AI coding agent session: context, objective,
constraints, method, deliverables, acceptance criteria.

## This is a feedback loop, not a fixed roadmap

**`00-workload-profile.md` is the source of truth for optimization
priorities.** Subsequent prompts must not assume that a particular function
or subsystem is hot merely because it looks expensive, appears in a static
ranking, or was a target in an earlier version of this plan. After any major
algorithmic optimization, **re-run the workload profile** and use the new
measurements to select the next target — that re-profiling step is itself a
numbered prompt (05), and the discipline of repeating it is made permanent by
prompt 09.

Two things make this practical rather than aspirational: prompt 01
establishes analysis tooling trustworthy enough to reason about a candidate
change, and prompt 02 establishes benchmarks credible enough to judge one.
Prompt 06 turns the optimization harness itself into a pluggable-strategy
architecture so that *which* metric a candidate is judged against — GHASH
throughput, handshake latency, end-to-end request time — is declared per
target rather than fixed in advance. The workload results tell us that
target selection has to happen after every major optimization, not once at
the start.

## The workload as currently measured

`sarm` serves **a small, fixed set of embedded static files over HTTP/2 with
TLS 1.3**. Assets are compiled into the binary and pre-compressed at build
time. There is no filesystem I/O and no runtime compression.

`docs/PROFILE.MD` (prompt 00's output) is the authoritative breakdown. As of
that profile:

| Workload | Current finding | Optimization direction |
|---|---|---|
| TLS handshake | P-256 / X25519 crypto dominate | Profile-driven |
| AES-GCM | GHASH ≈ 79% of cost | Prompt 03 |
| AES block encryption | ≈ 9% of AES-GCM cost | Secondary |
| P-256 field multiply | `p256_reduce` ≈ 73% of `p256_fe_mul` | Prompt 04 |
| `p256_bn_mul` | Hot, but a leaf with no frame | Do not target for register overhead |
| standalone `ghash` symbol | Not on the AES-GCM call path (`.Lgcm_ghash_run` is) | Do not optimize |
| Register save/restore overhead | Not yet demonstrated as a major bottleneck | Re-evaluate after 03/04 (prompt 05) |
| Response path | Cost relative to crypto not yet established | Prompt 08, evidence-gated |
| Embedded asset lookup | Six-entry table | Prompt 10, only if measurable |

Treat every row as a snapshot, not a permanent fact. `docs/PROFILE.MD`
predates the GHASH and P-256-reduction work; `docs/PROFILE-POST.MD` (prompt
05) supersedes it once that work lands, and the chain continues from there
(prompt 09). If a prompt's context section cites a percentage, check it
against the latest profile before trusting it for a new decision.

## Order

Run in sequence. 00 → 02 are prerequisites; nothing after them is trustworthy
without them.

| # | Prompt | Purpose |
|---|---|---|
| 00 | `00-workload-profile.md` | Measure where time actually goes. Gates everything else. |
| 01 | `01-analysis-tooling-correctness.md` | Fix the analyzer/ABI-checker defects; extend to local-label regions like `.Lgcm_ghash_run`. Safety prerequisite. |
| 02 | `02-benchmark-substrate.md` | Benchmarks for the functions the profile actually names, distinguishing microbenchmark from workload effect. |
| 03 | `03-aes-gcm-throughput.md` | GHASH restructuring — the measured ~79% of AES-GCM cost. |
| 04 | `04-asymmetric-crypto-algorithms.md` | Solinas-style P-256 reduction, replacing Barrett — the measured ~73% of field multiply cost. |
| 05 | `05-register-overhead-experiment.md` | Re-profile after 03/04. Determine the next target on evidence, not assumption. |
| 06 | `06-optimizer-strategy-framework.md` | Generalize the harness into workload-declared, pluggable strategies. |
| 07 | `07-register-transformations.md` | Automate register transformations — only for whatever prompt 05 (or a later re-profile) shows is actually hot. |
| 08 | `08-precomputed-response-path.md` | Precompute more of the response at build time — evidence-gated against crypto cost. |
| 09 | `09-regression-protection.md` | Make every accepted win reproducible, and make re-profiling a standing discipline. |
| 10 | `10-embedded-lookup.md` | Resolve the half-built asset lookup. Small, independent, explicitly low priority. |

Prompt 10 is independent of the rest and can run at any point after 00 — it is
a good first task for validating the workflow, since it is small, well-bounded
and has a clear right answer.

Prompts 06 and 07 are **conditional on measurement, not on sequence position**:
07 runs only if the *current* profile (from 05, or a later re-profile) shows
a hot function with a genuine register-pressure opportunity. "Register
optimization is not currently worthwhile" is a valid outcome of 05 or 07 —
it means the series stops there, not that something went wrong.

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
