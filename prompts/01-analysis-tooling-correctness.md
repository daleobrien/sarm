# 01 — Make the analysis tooling correct

**Prerequisite for every prompt that modifies assembly.** The static safety
gate is currently unsound in ways that produce confidently wrong answers, and
it must also be able to see the specific code prompts 03 and 04 will touch.

## Context

`scripts/abi.py` is the static ABI checker that every candidate passes through
before it is compiled (`scripts/optimizer.py:376`). It builds a control-flow
graph and runs a forward dataflow to prove that callee-saved registers are
restored on every path to `ret`.

Three defects, all found during the investigation in
`docs/REGISTER-PRESSURE.MD`:

### Defect 1 — local labels are invisible

`scripts/abi.py:129` discards every line beginning with `.` *before* it tests
for a label:

```python
if line.startswith("#") or line.startswith("."):
    continue
```

All **393** `.L…` local labels in `src/` are therefore never recorded. Branch
targets do not resolve, back edges vanish, and no loop is ever detected. The
checker's central claim — "restored on *every* path" — rests on a CFG that,
for most functions in this repo, has almost no edges.

`scripts/regpressure.py` already contains a corrected parser
(`parse_instructions` / `resolve_target`, which match labels before
directives). Port that fix back, or factor the parser into a shared module.

### Defect 2 — macros are never expanded

`src/defs.S` defines 13 macros used ~500 times across 82 files. Two matter:

- `ldr_l` / `str_l` write a **hidden scratch register** (`x9` by default).
- `SCWISVC` expands to `svc`, which clobbers the caller-saved registers.

Unexpanded, liveness misses those writes and every syscall site looks like
straight-line code. During the investigation this made four syscall-using
functions (`raw_read_exact`, `h2_verify_preface`, `crypto_random_bytes`,
`raw_write_all`) appear to be leaf functions whose callee-saved registers were
removable. Applying that "optimization" would have miscompiled all four.

`scripts/regpressure.py` has a working platform-aware expander
(`parse_macros` / `expand_macros`). Note it must select the correct
`#ifdef __linux__` branch: Linux puts the syscall number in x8, macOS in x16.

### Defect 3 — NZCV is not modelled

**36 functions return their status in the carry flag** ("carry clear =
success / carry set = failure"), a convention spanning 55 source files. The
condition flags are live-out values and part of the ABI. `abi.py` does not
model them at all.

Consequence: any transformation that reorders instructions can move a
flag-setting instruction (`adds`, `subs`, `cmp`, `ccmp`, or an `add` changed to
`adds`) between the status-setting site and the `ret`, silently corrupting the
return value while the returned *data* still looks correct. Unit tests that
check only returned data will not catch it.

This matters concretely for prompt 04: `p256_reduce` is built almost entirely
out of `adds`/`adcs`/`subs`/`sbcs` carry chains, and a Solinas-style rewrite
will be judged partly by whether the analyzer can track those chains
correctly.

## Additional requirement — the tooling must reach the actual optimization targets

The workload profile (`docs/PROFILE.MD`, from prompt 00) identified the real
bottlenecks: GHASH dominates AES-GCM, and `p256_reduce` dominates P-256 field
multiplication. Neither is a plain top-level function symbol in the way
`abi.py`/`regpressure.py` currently assume:

- **`p256_reduce`** (`src/crypto/p256/sqr_mul.S:37`) and **`p256_fe_mul`**
  (`src/crypto/p256/sqr_mul.S:188`) are ordinary global symbols, but
  `p256_reduce` is file-local (no `.global`) and calls `p256_bn_mul`
  (`src/crypto/p256/bn_mul.S:38`) twice — the analyzer must resolve that call
  correctly, including `p256_bn_mul`'s status as a hot leaf with no frame.
- **The real GHASH implementation is not the `ghash` symbol.** `ghash.S:38`
  exports a `.global ghash`, but AES-GCM never calls it. Both
  `src/crypto/gcm/encrypt.S` and `src/crypto/gcm/decrypt.S` call
  `.Lgcm_ghash_run` (`src/crypto/gcm/data.S:131`), a **local label**, directly
  by `bl`. Because of defect 1, the current tooling cannot even see this as a
  callable unit — it has no `.global`, and local-label call targets are
  exactly what the broken parser drops.

**Do not assume that a function symbol is the correct optimization unit.**
`.Lgcm_ghash_run` is the actual executed implementation; the standalone
`ghash` function is dead weight for this workload and optimizing it would not
change server behavior at all.

## Objective

Make `abi.py` and `regpressure.py` sound enough that a transformation gated on
them can be trusted, and capable of analyzing an inlined/local-label region
such as `.Lgcm_ghash_run` in the context of its real callers, not just
top-level `.global` functions.

## Tasks

1. **Fix the label bug.** Share one parser between `abi.py` and
   `regpressure.py` rather than maintaining two. Verify loops are now detected:
   before the fix, `regpressure.py` reported `Loop 0` for every function.
2. **Add macro expansion to `abi.py`**, platform-aware, defaulting to the host.
3. **Model NZCV liveness.** Track the flags as a value: which instructions
   define them, which use them (`b.cond`, `ccmp`, `csel`, `adc`, `sbc`), and
   whether they are live at `ret`. Report an error when a candidate inserts a
   flag-clobbering instruction into a live flag range. Validate this
   specifically against `p256_reduce`'s carry chains — they are the densest
   ADDS/ADCS/SUBS/SBCS sequence in the repo and the best stress test available.
4. **Extend the analyzer to local-label regions.** `.L…`-prefixed labels that
   are called via `bl` from outside their containing function (as
   `.Lgcm_ghash_run` is, from `ghash.S`, `encrypt.S`, and `decrypt.S`) must be
   treated as analyzable units in their own right: register pressure,
   liveness, and clobber set computed for the region actually reached at
   runtime, not for the enclosing `.global` symbol if there is a mismatch.
   Do this generally — do not special-case `.Lgcm_ghash_run` by name — but use
   it as the concrete test case, since it is the region prompt 03 will modify.
5. **Do not let a `.global` symbol shadow the real implementation.**
   Specifically: the analyzer must not report `ghash` as hot or as the
   GHASH implementation, and must not report `.Lgcm_ghash_run` as unreachable
   or unanalyzable merely because it lacks a `.global` directive.
6. **Validate `regpressure.py` against ground truth.** 207 functions carry a
   hand-written `// Clobbered Registers:` header. Write a checker comparing the
   analyzer's computed clobber set against the documented one. Every
   disagreement is either an analyzer bug or a stale comment — triage each and
   report the split. This is the strongest available correctness signal for the
   analyzer, and it costs nothing to run.

## Deliverables

- Corrected `scripts/abi.py` and shared parser.
- Analyzer support for local-label call targets, demonstrated on
  `.Lgcm_ghash_run` in its real caller context (`aes_gcm_encrypt`/
  `aes_gcm_decrypt`).
- `scripts/validate_clobbers.py` (or equivalent) implementing task 6.
- A short report: how many of the 207 headers agree, how many revealed
  analyzer bugs, how many revealed stale documentation, plus the register
  pressure and liveness result for `.Lgcm_ghash_run`, `p256_reduce`, and
  `p256_fe_mul`.

## Acceptance criteria

- Loops are detected: `regpressure.py` reports non-zero `Loop` for functions
  that visibly have loops (`raw_read_exact`, `parse_path`, `h2_huffman_decode`,
  and `.Lgcm_ghash_run`'s own block loop).
- `raw_read_exact` reports all three of x19/x20/x21 as **justified** — they are
  live across the syscall. Reporting any of them removable means the syscall
  clobber model is still wrong.
- The 36 carry-ABI functions report flags live at `ret`, including
  `p256_reduce`.
- The analyzer can identify `.Lgcm_ghash_run` as a distinct callable region
  and compute register pressure for it in its real caller context.
- The analyzer does not treat the standalone `ghash` symbol as the hot GHASH
  implementation.
- `p256_reduce` and `p256_fe_mul` produce complete and trustworthy
  register/liveness information, cross-checked against their documented
  clobber headers.
- Existing tests still pass: `make -C tests/unit test`.

## Constraints

- **Do not modify any `.S` file.** This prompt changes analysis tooling only.
- Prefer fixing the shared parser over special-casing. Two divergent parsers is
  how defect 1 survived.
- The checker must stay conservative: a false "this is safe" is far worse than
  a false warning.
