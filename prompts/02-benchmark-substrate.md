# 02 — Build a benchmark substrate that can resolve the real bottlenecks

**Prerequisite for prompts 03–04.** Without this, no optimization can be
accepted on evidence, and the harness will accept noise. Its target list is
set by the workload profile (`docs/PROFILE.MD`), not by which functions old
plans happened to mention.

## Context

The existing harness (`scripts/optimizer.py`) is built around the correct
principle: the LLM and the mutations propose, the benchmark decides. But the
benchmark barely exists.

- **1 of 165 functions has a real benchmark** —
  `scripts/benchmarks/bench_memcpy.c`.
- `scripts/arm-optimize.py:136-141` falls back to running a unit-test binary
  ten times under wall clock. Measured: **0.02 s at 0.01 s resolution**,
  dominated by process startup. It cannot resolve a change to a function that
  runs in nanoseconds — but `optimizer.py` will happily accept a candidate on
  it.
- **No `perf`** (macOS) and **no `llvm-mca`**, so `scripts/perf.py` and
  `scripts/mca.py` produce nothing. The evidence block handed to the LLM is
  mostly empty.

## Objective

Give every function prompts 03–04 will actually touch a microbenchmark that
can resolve the change being attempted, and make it impossible for the
harness to accept a candidate on a measurement that cannot.

**Do not build a benchmark merely because an earlier version of this plan
mentioned the function.** Build the ones the workload profile justifies.

## Required benchmarks

### AES-GCM

The workload profile shows GHASH accounts for ~79% of AES-GCM cost and
`aes128_encrypt` for ~9%. The benchmark set must reflect that, and must be
able to attribute cost correctly rather than assuming the encryption chain
dominates:

- `aes_gcm_encrypt` — complete AES-GCM, across realistic record sizes (16 B to
  16 KB, the TLS record limit).
- **The actual GHASH implementation used by `aes_gcm_encrypt`** — that is
  `.Lgcm_ghash_run` (`src/crypto/gcm/data.S:131`), exercised through the real
  call path, not the standalone `ghash` symbol (`src/crypto/gcm/ghash.S:38`),
  which `aes_gcm_encrypt` never calls. A benchmark of the standalone `ghash`
  function tells you nothing about server behavior — do not build one and
  treat its result as representative.
- GHASH per 16-byte block, isolated from AES, so multi-block GHASH work
  (prompt 03) can be measured independently of AES throughput work.

The benchmark set must **distinguish AES-only work, GHASH work, and complete
AES-GCM work** as three separate numbers. This is the only way to confirm
prompt 03's changes actually target the ~79% component rather than the ~9%
one.

### P-256

- `p256_reduce` (`src/crypto/p256/sqr_mul.S:37`) — isolated, since this is the
  prompt 04 target.
- `p256_fe_mul` (`src/crypto/p256/sqr_mul.S:188`) — so reduction cost can be
  separated from multiplication cost. `p256_fe_mul` is schoolbook multiply
  (`p256_bn_mul`) followed by `p256_reduce`; the benchmark must let you compute
  what fraction of `p256_fe_mul`'s time is reduction versus multiplication,
  both before and after prompt 04's change.
- `p256_bn_mul` (`src/crypto/p256/bn_mul.S:38`) — isolated, per-call. This is
  needed to isolate multiplication cost from reduction cost, not as a register
  optimization target (`p256_bn_mul` is a hot leaf function with no frame —
  see prompt 05).
- `p256_point_mul`, ECDSA signing, and complete P-256 handshake operations
  where practical, so the end-to-end effect of the reduction change is
  measurable, not just the microbenchmark effect.

## Do not benchmark yet

**Do not select a general-purpose register-optimization benchmark target in
this prompt.** The previous plan picked `x25519_fe_mul`/the X25519 ladder
before measuring whether register overhead was worth chasing at all. That
target must be selected in prompt 05, after the algorithmic work in 03/04 and
a fresh workload profile — not here, and not by assumption.

## Method

### 1. Extend the microbenchmark pattern

`scripts/benchmarks/bench_memcpy.c` is the reference implementation of the
protocol: a C driver links the function's own `.S`, times it, and emits
`{"function": ..., "runtime_ns": ...}`. `scripts/benchmarks/Makefile` extends
naturally — one object rule plus one link rule per function.

For the GHASH benchmark specifically, the driver must call into
`.Lgcm_ghash_run` through the same entry conditions `aes_gcm_encrypt` sets up
(H' in v19, the running accumulator in v20, the nibble/zero constants in
v16–v18) — read `src/crypto/gcm/data.S:107-130` for the documented calling
convention of that region before writing the driver. Faking a different
calling convention would measure a different, unrepresentative code path.

Requirements for each benchmark:

- Inner loop of ≥10⁵ iterations where practical; **best-of-N** over ≥7 rounds
  (memcpy's driver already does this — follow it).
- A warmup pass before timing.
- Representative inputs that defeat constant folding.
- Emit JSON on stdout, nothing else.

### 2. Establish the noise floor

For each benchmark, measure the same unchanged binary ≥20 times and report the
spread. **The noise floor is the number every later prompt compares against.**
An improvement smaller than it is not an improvement.

Record it in the benchmark's own output or a companion file so the harness can
enforce it rather than relying on the operator to remember.

A benchmark that cannot distinguish the expected improvement must **fail
closed** — refuse to report a pass/fail verdict — rather than silently
accepting a result inside the noise band.

### 3. Fix the harness's acceptance path

Two changes in `scripts/`:

- **Neuter the wall-clock fallback.** Either delete it
  (`arm-optimize.py:136-141`) or mark its result as non-gating, so a candidate
  can never be accepted on it. Failing closed — refusing to run without a real
  benchmark — is better than silently accepting noise.
- **Enforce the noise floor** in `optimizer.py:444`, where acceptance is
  currently a bare `runtime < best`. A candidate inside the noise band is not
  an improvement and must not become the new best.

### 4. Replace the missing evidence

With `perf` and `llvm-mca` unavailable, substitute what does work:

- **Static instruction counts** from `objdump` on the assembled object —
  exact, zero-noise, and the right tool for "did this actually remove
  instructions".
- **Structural disassembly diff** between baseline and candidate.
- Optionally `xctrace` for sampled counters.

Do not fabricate counter data or leave the LLM prompt claiming counters exist.
`scripts/prompts/optimize.txt` interpolates `{perf}` and `{mca}` — make those
say plainly that the data is unavailable.

## Deliverables

- `scripts/benchmarks/bench_<function>.c` for each function listed above, plus
  Makefile rules.
- A documented noise floor per benchmark.
- Harness changes so acceptance requires a real benchmark and a
  beyond-noise improvement.

## Acceptance criteria

- Each benchmark's round-to-round variance is **< 2%** on an otherwise idle
  machine. If it is not, the benchmark is not yet usable — fix it before
  moving on.
- Re-running a benchmark on an unchanged binary never reports an improvement
  that would be accepted.
- The AES-GCM benchmark set can report AES-only, GHASH-only, and complete
  AES-GCM numbers separately, and the GHASH number is measured through
  `.Lgcm_ghash_run`, not the standalone `ghash` symbol.
- The P-256 benchmark set can isolate `p256_reduce` cost from `p256_bn_mul`
  cost within `p256_fe_mul`.
- `scripts/arm-optimize.py --function memcpy --mutate-only` still runs
  end-to-end, proving the harness was not broken by the changes.

## Constraints

- **Do not modify any `.S` file.**
- Benchmarks are host tooling, not shipped code. They may use libc freely.
- Measure on the stated target (Apple M3 Pro, arm64) and record it. Results do
  not transfer to Cortex or Neoverse.
- A benchmark that cannot resolve the change it exists to measure is worse
  than none, because it produces confident wrong answers. Prove the resolution
  before trusting it.
