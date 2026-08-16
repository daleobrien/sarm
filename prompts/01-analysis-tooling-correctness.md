# 01 — Make the analysis tooling correct

**Prerequisite for every prompt that modifies assembly.** The static safety
gate is currently unsound in ways that produce confidently wrong answers.

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

## Objective

Make `abi.py` and `regpressure.py` sound enough that a transformation gated on
them can be trusted.

## Tasks

1. **Fix the label bug.** Share one parser between `abi.py` and
   `regpressure.py` rather than maintaining two. Verify loops are now detected:
   before the fix, `regpressure.py` reported `Loop 0` for every function.
2. **Add macro expansion to `abi.py`**, platform-aware, defaulting to the host.
3. **Model NZCV liveness.** Track the flags as a value: which instructions
   define them, which use them (`b.cond`, `ccmp`, `csel`, `adc`, `sbc`), and
   whether they are live at `ret`. Report an error when a candidate inserts a
   flag-clobbering instruction into a live flag range.
4. **Validate `regpressure.py` against ground truth.** 207 functions carry a
   hand-written `// Clobbered Registers:` header. Write a checker comparing the
   analyzer's computed clobber set against the documented one. Every
   disagreement is either an analyzer bug or a stale comment — triage each and
   report the split. This is the strongest available correctness signal for the
   analyzer, and it costs nothing to run.

## Deliverables

- Corrected `scripts/abi.py` and shared parser.
- `scripts/validate_clobbers.py` (or equivalent) implementing task 4.
- A short report: how many of the 207 headers agree, how many revealed
  analyzer bugs, how many revealed stale documentation.

## Acceptance criteria

- Loops are detected: `regpressure.py` reports non-zero `Loop` for functions
  that visibly have loops (`raw_read_exact`, `parse_path`, `h2_huffman_decode`).
- `raw_read_exact` reports all three of x19/x20/x21 as **justified** — they are
  live across the syscall. Reporting any of them removable means the syscall
  clobber model is still wrong.
- The 36 carry-ABI functions report flags live at `ret`.
- Existing tests still pass: `make -C tests/unit test`.

## Constraints

- **Do not modify any `.S` file.** This prompt changes analysis tooling only.
- Prefer fixing the shared parser over special-casing. Two divergent parsers is
  how defect 1 survived.
- The checker must stay conservative: a false "this is safe" is far worse than
  a false warning.
