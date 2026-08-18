---
name: sarm-optimizer
description: How to run sarm's automated optimization harness (arm-optimize.py) that proposes, checks, builds, tests, and benchmarks candidate assembly rewrites of a function, keeping or rejecting each one. Use whenever asked to let a machine try optimizations, search for a faster version of a function automatically, or run/interpret the .arm-optimize/ candidate archive.
---

# The optimization harness

```bash
python3 scripts/arm-optimize.py --list-functions --source src/util/memcpy.S
python3 scripts/arm-optimize.py --function memcpy --mutate-only
python3 scripts/arm-optimize.py --function memcpy --llm ollama --llm-model qwen2.5-coder:7b
python3 scripts/arm-optimize.py --function p256_reduce --strategy crypto --apply
```

Pipeline: **propose → ABI check → build → tests → differential → benchmark →
keep/reject**, with every candidate and its evidence archived under
`.arm-optimize/`.

The important flag is `--strategy`. It decides *what a candidate is judged
against* — e.g. a GHASH candidate is judged by AES-GCM throughput, not its
own microbenchmark. Every non-`speed` strategy **fails closed at
construction** unless its target is a measured line item in the profile
table in [docs/HISTORY.md](../../../docs/HISTORY.md) — the "never justify a
target by register or instruction count alone" rule, enforced structurally.

Supporting modules, if you need to modify the harness itself rather than
just run it: `strategy.py` (accept/score rules), `optimizer.py` (the loop),
`common.py`, `compiler.py` (build/test), `benchmark.py` (the authority on
whether a candidate is faster), `differential.py` (reference vs. candidate
over random inputs), `disassembler.py` (`.asm`/`.dis`/`diff.asm`
artifacts), `mca.py` (llvm-mca, absent on this toolchain), `perf.py`
(Linux only — no PMU access on macOS), `llm.py` (Ollama HTTP or any
subprocess command), `mutations/` (rule-based `neon`/`scheduling`/`unroll`
transforms), `prompts/*.txt` (analyst / optimizer / judge prompts).

## Related skills

- Full design + module breakdown → see `OPTIMISATION.MD` referenced from [docs/SCRIPTS.md](../../../docs/SCRIPTS.md)
- The ABI gate every candidate must pass → [sarm-static-analysis](../sarm-static-analysis/SKILL.md)
- The per-function benchmark used as the judge → [sarm-benchmark](../sarm-benchmark/SKILL.md)
- Prototype-then-prove workflow before touching crypto `.S` by hand → [verified-asm-crypto](../verified-asm-crypto/SKILL.md)
