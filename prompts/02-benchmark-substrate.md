# 02 — Build a benchmark substrate that can resolve a change

**Prerequisite for prompts 03–07.** Without this, no optimization can be
accepted on evidence, and the harness will accept noise.

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

Give every function targeted by prompts 03–07 a microbenchmark that can
resolve the change being attempted, and make it impossible for the harness to
accept a candidate on a measurement that cannot.

## Method

### 1. Extend the microbenchmark pattern

`scripts/benchmarks/bench_memcpy.c` is the reference implementation of the
protocol: a C driver links the function's own `.S`, times it, and emits
`{"function": ..., "runtime_ns": ...}`. `scripts/benchmarks/Makefile` extends
naturally — one object rule plus one link rule per function.

Write benchmarks for the functions prompt 00 ranked as hot. At minimum:

- `aes128_encrypt` and `aes_gcm_encrypt` — across realistic record sizes
  (16 B to 16 KB, the TLS record limit), since prompt 03 changes throughput.
- `p256_point_mul`, `p256_ecdsa_sign_with_k` — per-operation, since prompt 04
  changes the algorithm.
- `sha256_compress`, `ghash` — per block.
- Whichever function prompt 05 selects for the register experiment.

Requirements for each:

- Inner loop of ≥10⁵ iterations; **best-of-N** over ≥7 rounds (memcpy's
  driver already does this — follow it).
- Inputs that defeat constant folding and are representative in size.
- A warmup pass before timing.
- Emit JSON on stdout, nothing else.

### 2. Establish the noise floor

For each benchmark, measure the same unchanged binary ≥20 times and report the
spread. **The noise floor is the number every later prompt compares against.**
An improvement smaller than it is not an improvement.

Record it in the benchmark's own output or a companion file so the harness can
enforce it rather than relying on the operator to remember.

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

- `scripts/benchmarks/bench_<function>.c` for each hot function, plus Makefile
  rules.
- A documented noise floor per benchmark.
- Harness changes so acceptance requires a real benchmark and a
  beyond-noise improvement.

## Acceptance criteria

- Each benchmark's round-to-round variance is **< 2%** on an otherwise idle
  machine. If it is not, the benchmark is not yet usable — fix it before
  moving on.
- Re-running a benchmark on an unchanged binary never reports an improvement
  that would be accepted.
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
