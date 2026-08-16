# 09 — Make every win reproducible and permanent

Run after any prompt that lands an optimization. Can also run continuously
alongside 03–08.

## Context

Hand-tuned assembly optimizations are fragile in a specific way: they are
correct for reasons that live in the author's head and nowhere else. Six months
later nobody remembers why `x25519_fe_mul` uses that register assignment, or
that a "harmless" reordering breaks the carry-flag return convention.

`scripts/optimizer.py` already archives every candidate under `.arm-optimize/`
with full source, disassembly and benchmark evidence. That machinery exists for
automated runs. Hand-applied optimizations from prompts 03, 04, 05 and 08 get
none of it.

## Objective

Ensure every accepted optimization carries enough evidence to be re-verified,
and that regressions are caught mechanically rather than by memory.

## Tasks

### 1. Optimization records

For each accepted change, produce a record capturing:

```
function / subsystem
commit
what changed and why
benchmark before / after (with noise floor)
instruction count before / after
load/store count before / after
save/restore count before / after
peak register pressure before / after
stack usage before / after
binary size before / after
tests run
constant-time argument (for anything under src/crypto/)
```

Store these in the repository, not in `.arm-optimize/` — that directory is
scratch and is regenerated. `docs/optimizations/` is a reasonable home.

### 2. Performance regression tests

Turn the benchmarks from prompt 02 into a gate:

- A script running every benchmark and comparing against recorded baselines.
- Failure threshold set from the measured noise floor, not a guess.
- Runnable as `make bench` or similar, alongside `make test`.

Baselines must be updated deliberately, with a recorded reason — never
automatically, or the gate silently ratchets away.

### 3. Invariant tests for the things that bit us

Each of these was a real defect or near-miss during investigation. Encode them
so they cannot recur:

- **NZCV / carry-flag ABI** — a test asserting the carry-flag return
  convention for the 36 functions using it, exercising both success and
  failure paths. This is the invariant most likely to be broken silently by a
  future reordering, and the one least likely to be caught by data-only
  assertions.
- **Syscall clobbers** — a test or static check that functions using
  `SCWISVC` preserve values across it. Four functions looked like removable
  leaf cases until macros were expanded.
- **Clobber-header accuracy** — wire prompt 01's `validate_clobbers.py` into
  the test suite so the 207 documented headers cannot drift from reality.
- **Constant time** — for `src/crypto/`, at minimum a static check for
  secret-dependent branches and secret-dependent memory addressing in the
  scalar-multiplication and tag-comparison paths.

### 4. Document the reasoning, not just the result

For each optimization, record what makes it *safe*, not only what makes it
fast: which registers are provably dead, why a table lookup is oblivious, why
a reordering cannot move a flag-setting instruction across a status site.
Future changes need the invariant, not the outcome.

## Acceptance criteria

- Every optimization landed by prompts 03–08 has a record.
- The benchmark gate runs green against recorded baselines and detects an
  injected regression when tested with one — verify this deliberately rather
  than trusting it.
- The carry-flag ABI test fails when a flag-clobbering instruction is
  deliberately inserted before a `ret`. An invariant test that has never been
  seen to fail is not known to work.
- `make -C tests/unit test` and all shell suites still pass.

## Constraints

- Regression tests must be fast enough to run routinely, or they will not be
  run. Separate a quick gate from an exhaustive nightly one if needed.
- Do not add runtime logging or instrumentation to the shipped binary. The
  project deliberately logs nothing — see commit `8830940`.
- Benchmark results are target-specific (Apple M3 Pro, arm64). Record the
  target in every baseline; do not compare across machines.
