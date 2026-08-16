# 05 — Call-boundary overhead on hot inner loops

**The decisive experiment.** Its result determines whether prompts 06 and 07
are worth running at all.

## Context

`docs/REGISTER-PRESSURE.MD` established that this codebase does not spill:
peak simultaneously-live GPRs is median 6, max 25, against 31 available. The
classic payoff for reducing register pressure — eliminating spills — is not
available, because there are no spills.

What remains is **fixed per-call overhead**: AAPCS64 requires that a function
touching x19–x28 preserve them, so each costs an `stp`/`ldp` pair plus stack
frame setup, paid once per call regardless of what the function does. Across
the repo that is 589 save/restore instructions, ~160 of them removable.

Repo-wide that is a rounding error. **But it concentrates spectacularly in one
place.** The X25519 Montgomery ladder (`src/crypto/x25519/main.S`) makes ~18
field-operation calls per bit over 255 bits — roughly **4,600 calls per
handshake**, of which ~1,275 are `x25519_fe_mul`. That function carries ~12
instructions of prologue/epilogue, so it alone spends on the order of
**15,000 instructions per handshake** purely preserving registers.

That reframes the question. It is not "can we tidy up register allocation
repo-wide" but "what does the call boundary cost on the hottest inner loop in
the program".

## The bigger idea: these functions do not need the ABI

`x25519_fe_mul`, `x25519_fe_sqr`, `x25519_fe_add`, `x25519_fe_sub` are
**internal helpers**, called only from the ladder. Nothing external depends on
their calling convention. AAPCS64 is a contract with the outside world, and
these functions have no outside world.

Three escalating options, cheapest first:

1. **Register reallocation** — move values into caller-saved registers where
   pressure permits, dropping some save/restore pairs. `x25519_fe_mul` has peak
   pressure 25, so it cannot shed all ten callee-saved registers, but it can
   shed some. Partial win, fully mechanical.
2. **A private calling convention** — since the callers are known, agree a
   fixed register assignment across the ladder and its helpers and drop
   preservation entirely. Removes prologue and epilogue completely.
3. **Inlining the field operations into the ladder** — removes the `bl`/`ret`
   and the prologue/epilogue both. Largest win, largest code-size cost, and the
   hardest to keep readable.

Option 2 or 3 is likely worth far more than option 1. Note that any of them
requires the callers to be updated in lockstep, and that these symbols may also
be referenced by the unit tests — check before changing their convention.

## Objective

Determine empirically what call-boundary overhead costs on the X25519 ladder,
and decide on evidence whether automating register transformations (prompts 06
and 07) is justified.

## Method

1. **Confirm the target with data.** Use prompt 00's profile. If the handshake
   does not use X25519 in practice, pick the hottest inner-loop function it
   *does* use and say so. Do not proceed on the assumption above without
   checking it.
2. **Benchmark `x25519` end-to-end** and `x25519_fe_mul` per call (prompt 02).
3. **Establish the ceiling analytically first.** Count the preservation
   instructions per call from `objdump`, multiply by measured call count, and
   express it as a fraction of total handshake instructions. If the ceiling is
   below the noise floor, stop here and report that — it is a complete and
   valuable answer, obtained cheaply.
4. **Apply option 1 by hand** to `x25519_fe_mul`. Measure.
5. **If option 1 measures, try option 2** on the ladder's helpers. Measure.
6. **Report.**

## Why this is worth doing before prompts 06 and 07

The entire search-and-automate architecture rests on the benchmark being able
to *see* these wins. If removing preservation instructions sits below the noise
floor, an automated optimizer cannot distinguish a real improvement from
jitter, and it will either reject everything or accept noise — a random walk
with a correctness gate.

This prompt buys that information for roughly a day's work. Prompts 06 and 07
are weeks. **A negative result here is a success**: it saves the weeks and
redirects effort to prompts 03, 04 and 08.

Note the amortization trap that makes this genuinely uncertain. In
`h2_huffman_decode` the removable overhead is 23.5% of the *static* instruction
count, but the function is a bit-at-a-time decode loop running ~8 iterations
per input byte — so the prologue is well under 2% of *executed* instructions.
Static share is not time share. `x25519_fe_mul` is the interesting case
precisely because it is called in a tight outer loop rather than containing one.

## Constraints

- **All invariants in `prompts/README.md` apply**, especially constant time:
  X25519 and P-256 must remain free of secret-dependent branches and
  addressing. Register reallocation does not change timing behaviour; option 3
  inlining must not introduce data-dependent control flow.
- **Prompt 01 must be complete first.** Without the fixed CFG parser, macro
  expansion and NZCV liveness, the analysis backing any of these changes is
  unsound — and the four functions that initially looked like removable leaf
  cases were miscompilations waiting to happen.
- If you change a helper's calling convention, **update its documented
  `// Clobbered Registers:` header** and check whether `tests/unit/` links
  against it directly.
- Verify structurally: the disassembly should differ only in register numbers
  and the removed prologue/epilogue. A structural diff catches an entire class
  of errors without executing anything.

## Acceptance criteria

- A number: what call-boundary overhead costs per handshake, measured, with the
  noise floor stated alongside it.
- All crypto tests pass, including differential and RFC vectors.
- A clear recommendation: **run prompts 06 and 07, or do not**, with the
  evidence for it.

## Deliverable

A report in `docs/` covering: analytic ceiling, measured result for each option
attempted, instruction counts before and after, stack usage before and after,
and the recommendation. Update `docs/REGISTER-PRESSURE.MD` with the finding —
particularly if it contradicts that document's static ranking, which put
`h2_huffman_decode` first on static grounds without accounting for call
frequency.
