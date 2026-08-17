# 07 — Automate only the register transformations the current profile justifies

**Not automatically enabled.** This prompt is no longer enabled merely by
following prompt 06 in sequence. Run it only if the **latest** workload
profile (prompt 05's re-profile, or a later one) identifies a hot function
where register allocation is demonstrably contributing to execution cost.

## Objective

Build safe register transformations that can be applied to a measured hot
target, using the strategy architecture from prompt 06.

**Do not start from a repository-wide list of functions with removable
registers.** `scripts/regpressure.py`'s static ranking is an input to
analysis, not a target list. Start from:

```text
workload profile
→ hot function
→ register analysis
→ measurable opportunity
→ transformation
```

If no function in the current profile clears that bar, the correct outcome
of this prompt is to say so and stop — do not manufacture a target to justify
running it.

## Candidate transformations

Retain the following transformation families, each declining cleanly when its
preconditions do not hold:

### 1. Callee-saved register elimination

Useful only when:

- the function actually saves/restores the register;
- the register can be safely renamed;
- the replacement does not increase pressure;
- the function remains ABI-correct.

Fully mechanical in a leaf function with no `bl`/`blr`/`svc` and pressure
within the caller-saved budget.

### 2. Callee-saved register demotion

Move a value to a caller-saved register when its lifetime does not cross a
call/clobber boundary. Requires interference checking against the call-clobber
set — including syscall clobbers (`SCWISVC` expands to `svc`, which clobbers
caller-saved registers; four functions looked like leaves until this was
accounted for during the prompt-01 investigation).

### 3. Prologue/epilogue reduction

Only where the register analysis proves the saved register is unnecessary.
Never increases stack; shrinks `sub sp, sp, #N` to the still-needed size,
preserving 16-byte alignment.

### 4. Register move elimination

Remove unnecessary ABI shuffles caused by register allocation — `arg ← arg`
moves that vanish under renaming, as opposed to `callee ↔ arg` shuffles
around calls, which are inherent and should not be chased.

### 5. Live-range shortening

Sink a definition toward its use. **Highest risk.** Allow only after prompt
01's NZCV modelling is proven correct — a reordering here is exactly the kind
of change that can move a flag-setting instruction across a status-setting
site and silently corrupt a carry-flag return value.

Transformations 1–4 are pure renaming plus deletion and never move a
flag-setting instruction, so they are safe under the NZCV constraint on their
own. Transformation 5 is not, and must stay disabled until the NZCV liveness
analysis is validated.

## Important restriction

**Do not apply register transformations to a function merely because
`regpressure.py` ranks it highly.**

For each candidate, show:

```text
function
workload contribution
current runtime
register opportunity
estimated removable instructions
expected maximum speedup
```

**If the maximum possible saving is below the benchmark noise floor, reject
the target before generating candidates.** Do not generate candidates for a
function and then discover afterward that none could pass.

## In particular

**Do not target `p256_bn_mul`** (`src/crypto/p256/bn_mul.S:38`) merely
because it represents a large percentage of a connection's runtime. It is a
leaf function with no frame and no save/restore overhead — there is nothing
for a register-pressure transformation to remove. "Large share of runtime"
and "register-optimization opportunity" are different claims; only the second
justifies this prompt.

**Do not target the standalone `ghash` symbol** (`src/crypto/gcm/ghash.S:38`)
as an independent function unless call-graph analysis proves it is actually
executed by the server. The actual GCM implementation is `.Lgcm_ghash_run`
(`src/crypto/gcm/data.S:131`); optimizing `ghash` in isolation does not
change server behavior.

## AI-assisted transformations

The local LLM may propose register transformations, but only after the
static analyzer (prompt 01) provides:

```text
CFG
live ranges
interference
caller/callee clobbers
NZCV liveness
stack frame
actual call sites
```

**The LLM must never be allowed to determine whether a candidate is
correct.** The automated pipeline decides:

```text
parse
→ validate
→ assemble
→ ABI analysis
→ differential test
→ benchmark
→ accept/reject
```

A **structural verification gate** is the strongest available check for a
pure renaming transformation: the candidate's disassembly should differ from
the baseline only in register numbers and the removed prologue/epilogue.
Implement that diff and make it a hard gate — it catches an entire class of
errors without executing anything.

## Success criterion

A register transformation is successful only if it produces one of:

1. measurable hot-path speedup;
2. measurable end-to-end speedup;
3. removal of meaningful save/restore or other instruction overhead with no
   measurable regression.

**Reducing the numerical register count by itself is not a success
criterion.**

## Tasks

1. `scripts/mutations/registers.py` implementing transformations 1–4, each
   declining cleanly (returning `None`) when preconditions do not hold — the
   convention the existing mutations follow.
2. Register them with the register-pressure `Strategy` from prompt 06,
   including its declared target-selection rule (workload-profile-driven,
   not static-ranking-driven).
3. Implement the structural verification gate described above and make it a
   hard gate for every renaming-family candidate.
4. Apply only to functions the current workload profile identifies as hot
   **and** where the analytic ceiling (removable instructions × call
   frequency) clears the noise floor from prompt 02.

## Acceptance criteria

- Every accepted candidate traces to a specific line in the current workload
  profile showing the target is hot.
- Each mutation declines safely on every function where its preconditions
  fail — in particular, it must **not** fire on syscall-using functions
  (`raw_read_exact`, `h2_verify_preface`, `crypto_random_bytes`,
  `raw_write_all`) via transformation 1, and must **not** fire on
  `p256_bn_mul` or the standalone `ghash` symbol at all.
- No accepted candidate increases stack usage, loads, or stores.
- Full test suite passes for every accepted candidate: `make -C tests/unit
  test`, `tests/test_files.sh`, `tests/test_security.sh`,
  `tests/test_protocols.sh`, `tests/h2_browser_sim.py`.
- Constant-time properties preserved for anything under `src/crypto/`.

## Constraints

- Apply to one function at a time, with the full gate chain per candidate.
- Do not touch functions the current profile has not shown to be hot, even if
  a static analyzer ranks them highly.
- The set of functions this prompt touches is bounded by measured
  opportunity, not by exhausting a list. Stop when measured gains stop.
