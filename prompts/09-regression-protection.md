# 09 — Make every optimization reproducible and permanent

Run after any prompt that lands an optimization. Can also run continuously
alongside 03–08.

## Context

Hand-tuned assembly optimizations are fragile in a specific way: they are
correct for reasons that live in the author's head and nowhere else. Six
months later nobody remembers why `p256_reduce` folds limbs in that order, or
that a "harmless" reordering breaks the carry-flag return convention.

`scripts/optimizer.py` already archives every candidate under `.arm-optimize/`
with full source, disassembly and benchmark evidence. That machinery exists
for automated runs. Hand-applied optimizations from prompts 03, 04, 05 and 08
get none of it, and this series now includes algorithmic changes — GHASH
restructuring, a P-256 reduction rewrite — whose correctness argument is
mathematical, not just structural, and needs to be recorded as such.

## Objective

Ensure every accepted optimization carries enough evidence to be re-verified,
and that regressions are caught mechanically rather than by memory. Extend
the record format to cover algorithmic optimizations, not just register/
instruction-level ones.

## Tasks

### 1. Optimization records

For each accepted change, produce a record capturing:

```text
function/subsystem
commit
workload motivating the change
what changed
why it was selected
benchmark before
benchmark after
noise floor
instruction count
load/store count
save/restore count
register pressure
stack usage
binary size
end-to-end workload impact
tests
constant-time argument
```

**For crypto optimizations, additionally record:**

```text
mathematical/reference implementation
known-good cross-check
constant-time reasoning
test-vector coverage
random differential testing
```

This directly matches the `verified-asm-crypto` workflow prompts 03 and 04
already require — this task is where that evidence gets permanently filed
rather than living only in a session transcript. For prompt 04 specifically,
the record should point at the Python reference derivation and state how many
random cases it was cross-checked against.

Store these in the repository, not in `.arm-optimize/` — that directory is
scratch and is regenerated. `docs/optimizations/` is a reasonable home.

### 2. The benchmark gate must distinguish microbenchmark from workload improvement

```text
microbenchmark improvement
```

is not the same claim as

```text
end-to-end workload improvement
```

**An optimization that improves a microbenchmark but has no measurable
effect on the actual server should be documented as such, and should not
automatically be treated as a successful workload optimization.** This is
the same distinction prompt 08 must apply to response-path work, and prompt
03/04 must apply to GHASH/reduction work — record both numbers separately for
every accepted change, never just the more flattering one.

### 3. Performance regression tests

Turn the benchmarks from prompt 02 into a gate:

- A script running every benchmark and comparing against recorded baselines.
- Failure threshold set from the measured noise floor, not a guess.
- Runnable as `make bench` or similar, alongside `make test`.

Baselines must be updated deliberately, with a recorded reason — never
automatically, or the gate silently ratchets away.

### 4. Invariant tests for the things that bit us

Each of these was a real defect or near-miss during investigation. Encode
them so they cannot recur:

- **NZCV / carry-flag ABI** — a test asserting the carry-flag return
  convention for the 36 functions using it, including `p256_reduce`'s dense
  carry chains, exercising both success and failure paths.
- **Syscall clobbers** — a test or static check that functions using
  `SCWISVC` preserve values across it.
- **Clobber-header accuracy** — wire prompt 01's `validate_clobbers.py` into
  the test suite so the 207 documented headers cannot drift from reality.
- **Constant time** — for `src/crypto/`, at minimum a static check for
  secret-dependent branches and secret-dependent memory addressing in the
  scalar-multiplication, reduction, GHASH, and tag-comparison paths.

### 5. Maintain a historical workload profile

```text
baseline profile
→ optimization
→ new profile
→ identify next bottleneck
```

After every major optimization stage, archive the profile that motivated it
and the profile that followed it, alongside the optimization record. This is
what prompt 05 already does once; this task makes it a standing discipline
so the series does not go stale the way the original register-overhead
assumptions did. `docs/PROFILE.MD` (baseline), `docs/PROFILE-POST.MD` (after
03/04), and subsequent dated snapshots form the chain.

### 6. Document the reasoning, not just the result

For each optimization, record what makes it *safe*, not only what makes it
fast: which registers are provably dead, why a table lookup is oblivious, why
a reordering cannot move a flag-setting instruction across a status site, why
a reduction folding sequence is mathematically equivalent to the modulus it
targets. Future changes need the invariant, not the outcome.

## Acceptance criteria

- Every optimization landed by prompts 03–08 has a record, with the crypto
  fields populated for anything under `src/crypto/`.
- Every record states both the microbenchmark result and the end-to-end
  workload result, and does not conflate them.
- The benchmark gate runs green against recorded baselines and detects an
  injected regression when tested with one — verify this deliberately rather
  than trusting it.
- The carry-flag ABI test fails when a flag-clobbering instruction is
  deliberately inserted before a `ret`. An invariant test that has never been
  seen to fail is not known to work.
- The historical profile chain (`docs/PROFILE.MD` → `docs/PROFILE-POST.MD` →
  …) exists and each entry names the optimization that produced it.
- `make -C tests/unit test` and all shell suites still pass.

## Constraints

- Regression tests must be fast enough to run routinely, or they will not be
  run. Separate a quick gate from an exhaustive nightly one if needed.
- Do not add runtime logging or instrumentation to the shipped binary. The
  project deliberately logs nothing — see commit `8830940`.
- Benchmark results are target-specific (Apple M3 Pro, arm64). Record the
  target in every baseline; do not compare across machines.
