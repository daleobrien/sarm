# 07 — Automate the register transformation family

**Conditional.** Run only after prompts 05 and 06, and only if 05 showed the
overhead is worth automating.

## Context

`scripts/regpressure.py` ranks every function by removable register overhead.
`docs/REGISTER-PRESSURE.MD` records the result: **35 of 165 functions** have
opportunity, worth ~160 of the repo's 589 save/restore instructions; 130 are
already tight and should not be touched.

This prompt turns the hand-applied transformation from prompt 05 into a
deterministic mutation the harness can apply and verify.

## The transformations

Ordered by safety. Each changes one function and one conceptual thing —
the candidate protocol the existing `mutations/` package already follows.

1. **Leaf callee-saved elimination.** In a function with no `bl`/`blr`/`svc`,
   rewrite x19–x28 to unused caller-saved registers and delete the prologue,
   epilogue and frame. Legal when peak pressure ≤ available caller-saved count.
   Fully mechanical and the largest single win where it applies.
2. **Unjustified callee-saved demotion.** In a non-leaf function, a value never
   live across *any* call site can move to a free caller-saved register,
   dropping its save/restore pair. Requires interference checking against the
   call-clobber set.
3. **Frame-size reduction.** After 1 or 2, shrink `sub sp, sp, #N` to the
   still-needed size, preserving 16-byte alignment. Never increases stack.
4. **ABI-shuffle mov elimination.** 105 of the repo's 837 register-to-register
   movs are `arg ← arg` shuffles; some vanish under renaming. The other 69% are
   `callee ↔ arg` around calls and are inherent — do not chase them.
5. **Live-range shortening / rescheduling.** Sink a definition toward its use.
   **Highest risk — see below.**

Transformations 1–4 are pure renaming plus deletion: they never move a
flag-setting instruction, so they are safe under the NZCV constraint.
Transformation 5 is not, and must stay disabled until prompt 01's NZCV
liveness is in place and proven.

## The hazards

Every one of these has already produced a wrong answer during investigation.

- **Syscalls are calls.** `SCWISVC` is a macro expanding to `svc`, which
  clobbers caller-saved registers. Four functions (`raw_read_exact`,
  `h2_verify_preface`, `crypto_random_bytes`, `raw_write_all`) look like leaves
  until macros are expanded. Applying transformation 1 to them miscompiles.
- **Local labels.** Before prompt 01's fix, `.L…` labels were invisible to the
  parser, so loops were never detected and liveness was wrong. Verify the fix
  is in place before trusting any analysis.
- **NZCV is part of the ABI** in 36 functions. See prompt 01.
- **`strlen` has a non-standard ABI** — argument in x1, not x0. Any assumption
  that x0 holds the first argument is wrong there.
- **Documented clobber headers.** 207 functions carry
  `// Clobbered Registers:` comments. A transformation that changes the
  register set must update the header, or it silently becomes misleading
  documentation. Make this part of the mutation, not a follow-up.

## Tasks

1. `scripts/mutations/registers.py` implementing transformations 1–4, each
   declining cleanly (returning `None`) when preconditions do not hold — the
   convention the existing mutations follow.
2. Register them with `RegisterStrategy` from prompt 06.
3. **Structural verification gate**: for a renaming transformation the
   candidate's disassembly should differ from the baseline only in register
   numbers and the removed prologue/epilogue. Implement that diff and make it a
   hard gate. It catches an entire class of errors without executing anything,
   and it is stronger than any benchmark here.
4. Run against the ranked list from `regpressure.py`, highest opportunity
   first.

## Acceptance criteria

- The transformation reproduces prompt 05's hand-applied result automatically,
  with the same measured outcome.
- Each mutation declines safely on every function where its preconditions fail
  — in particular, it must **not** fire on the four syscall-using functions.
- No accepted candidate increases stack usage, loads, or stores.
- Full test suite passes for every accepted candidate: `make -C tests/unit
  test`, `tests/test_files.sh`, `tests/test_security.sh`,
  `tests/test_protocols.sh`, `tests/h2_browser_sim.py`.
- Constant-time properties preserved for anything under `src/crypto/`.

## Constraints

- Apply to one function at a time, with the full gate chain per candidate.
- Do not touch the 130 functions the analyzer ranks as already tight, or the 9
  whose save/restore traffic is fully justified across calls.
- The 35-function opportunity set is the *ceiling*, not a target. Stop when
  measured gains stop, not when the list is exhausted.
