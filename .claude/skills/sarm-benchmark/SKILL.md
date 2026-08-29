---
name: sarm-benchmark
description: How to micro-benchmark a single assembly function in sarm — the scripts/benchmarks/bench_<fn>.c harness and measure_noise_floor.py. Use whenever asked to benchmark a specific function, check if a candidate implementation is faster, or measure a function's runtime in isolation (not end-to-end server throughput — that's the load-test skill).
---

# Benchmarking a single function

```bash
cd scripts/benchmarks
make bench_p256_fe_mul && ./_bench_bin/bench_p256_fe_mul     # prints JSON: {"function", "runtime_ns", "sizes"}
python3 measure_noise_floor.py bench_p256_fe_mul              # writes the paired .noise.json
```

The benchmark Makefile builds in parallel by default (all cores); pass
`JOBS=1` for a serial build. Never add `-j` — it's already set. This
affects build time only: the benchmark binaries are always run one at a
time, so timings are unaffected.

Each `bench_<fn>.c` links the function's own `.S` file directly, so a
candidate installed by `arm-optimize.py` (see
[sarm-optimizer](../sarm-optimizer/SKILL.md)) is picked up automatically
without rebuilding the whole server.

The paired `.noise.json` from `measure_noise_floor.py` records the
round-to-round noise floor a candidate must beat before it's considered a
real improvement — `arm-optimize.py` reads it to decide keep/reject.

`scripts/benchmark.py` (`BenchmarkResult`, `run_workload_benchmark`,
`workload_benchmark_cmd`) is the library these use internally and that the
optimizer harness calls programmatically — reach for the CLI above rather
than calling it directly unless you're modifying the harness itself.

## Related skills

- End-to-end server throughput (RPS) → [sarm-load-test](../sarm-load-test/SKILL.md)
- Where a connection's time goes across functions → [sarm-profile](../sarm-profile/SKILL.md)
- Automated candidate search using this benchmark as the judge → [sarm-optimizer](../sarm-optimizer/SKILL.md)
