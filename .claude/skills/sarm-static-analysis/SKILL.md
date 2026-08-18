---
name: sarm-static-analysis
description: How to run sarm's static analysis / pre-compile gates on hand-written ARM64 assembly — abi.py (callee-saved regs, x30, SP, NZCV legality), regpressure.py (register pressure and callee-saved traffic), and validate_clobbers.py (checks hand-written "Clobbered Registers" headers). Use whenever asked to check if an assembly change is legal/safe, before considering a .S file change done, or when comparing a candidate against the function it replaces.
---

# Static analysis on ARM64 assembly

```bash
python3 scripts/regpressure.py                                    # ranked report, read-only
python3 scripts/regpressure.py --callers .Lgcm_ghash_run
python3 scripts/abi.py --source src/crypto/p256/sqr_mul.S --function p256_reduce --flags
python3 scripts/validate_clobbers.py --verdict OVERSTATES
```

- **`abi.py`** — the pre-compile gate to run before considering any
  hand-written assembly change done: callee-saved GPRs/SIMD not restored on
  some path, `bl` without saving `x30`, SP not restored or misaligned, and
  **NZCV** — dozens of functions return status in the carry flag, so the
  flags are a live-out ABI value. The NZCV check is differential against the
  function being replaced, since only that comparison shows which flag write
  was intended.
- **`regpressure.py`** — read-only. Reports pressure, callee-saved traffic
  and register moves. The metric that matters is *not* register count —
  nothing in this repo spills. It's fixed prologue/epilogue traffic that
  isn't earned.
- **`validate_clobbers.py`** — checks the analyzer against the 200+
  hand-written `// Clobbered Registers:` headers. Where they disagree,
  exactly one is wrong. This is the cheapest strong oracle in the repo; it
  has found real bugs in both directions.

`asmparse.py` is the single AArch64 parser all three of these build on
(labels including `.L`, macro expansion, regions, call graph,
`--linux`-aware). It exists because there used to be two parsers and their
divergence hid a soundness bug for a long time — don't add a third.

## Related skills

- Prototyping/proving crypto arithmetic before writing the assembly at all → [verified-asm-crypto](../verified-asm-crypto/SKILL.md)
- Automated candidates run through `abi.py` as part of a larger pipeline → [sarm-optimizer](../sarm-optimizer/SKILL.md)
