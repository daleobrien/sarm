#!/usr/bin/env python3
"""Establish and record a benchmark's noise floor.

prompts/02-benchmark-substrate.md: "For each benchmark, measure the same
unchanged binary >=20 times and report the spread. The noise floor is the
number every later prompt compares against. An improvement smaller than it
is not an improvement." This script does that measurement and writes the
companion ``bench_<function>.noise.json`` file ``scripts/arm-optimize.py``
and ``scripts/optimizer.py`` read to enforce it: a benchmark with no
calibrated noise floor makes the harness fail closed rather than judge
candidates against an unknown noise band.

The noise floor is the round-to-round spread relative to the median, over
independent process invocations (not just in-process rounds -- process
startup, scheduling and frequency-scaling noise are exactly what this needs
to catch): the 10th-90th percentile band, ``(p90 - p10) / median * 100``,
not raw min/max. Raw min/max over independent process launches on a
general-purpose OS is dominated by the rare scheduler-preemption outlier
and gets *worse*, not better, as --rounds increases, which would make this
script punish exactly the machines/CI runners it should tolerate. The
trimmed band is what "the same unchanged binary's" typical round-to-round
spread actually is; min/max are still recorded in the output JSON for
anyone who wants the untrimmed view.

Usage:
    python3 scripts/benchmarks/measure_noise_floor.py --function memcpy
    python3 scripts/benchmarks/measure_noise_floor.py \\
        --function p256_reduce --rounds 30

    # Explicit command, for benchmarks not named bench_<function>.c (e.g.
    # local-label targets like .Lgcm_ghash_run, which have no --function
    # -safe filename):
    python3 scripts/benchmarks/measure_noise_floor.py \\
        --benchmark "make -s -C scripts/benchmarks bench_gcm_ghash_run" \\
                    "&&" "./scripts/benchmarks/_bench_bin/bench_gcm_ghash_run" \\
        --out scripts/benchmarks/bench_gcm_ghash_run.noise.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # scripts/

from benchmark import Benchmark  # noqa: E402


def measure(command, rounds: int) -> list[float]:
    samples: list[float] = []
    for i in range(rounds):
        result = Benchmark(command, rounds=1).run()
        if result is None:
            raise SystemExit(
                f"benchmark failed on independent run {i + 1}/{rounds}"
            )
        samples.append(result.runtime_ns)
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--function",
                        help="bench_<function> convention "
                             "(scripts/benchmarks/bench_<function>.c)")
    parser.add_argument("--benchmark", nargs="+", default=None,
                        help="explicit benchmark command; overrides "
                             "--function's default command (still used "
                             "to name the output file unless --out is "
                             "given)")
    parser.add_argument("--rounds", type=int, default=20,
                        help="independent process invocations (prompt 02 "
                             "requires >=20)")
    parser.add_argument("--out", type=Path, default=None,
                        help="where to write the noise-floor JSON "
                             "(default: bench_<function>.noise.json next "
                             "to this script)")
    parser.add_argument("--max-pct", type=float, default=2.0,
                        help="fail if the measured spread is not below "
                             "this (prompt 02 acceptance: <2%%)")
    args = parser.parse_args()

    if not args.benchmark and not args.function:
        parser.error("pass --function or --benchmark")

    function = args.function or "unknown"
    if args.benchmark:
        command = args.benchmark
    else:
        # Build once, up front, then invoke the unchanged binary directly
        # for every round -- "measure the same unchanged binary >=20
        # times" (prompt 02). Re-running `make` per round adds its own
        # process-spawn/stat noise on top of whatever the benchmark
        # itself has, inflating the spread with noise that has nothing to
        # do with the code being measured.
        build = subprocess.run(
            ["make", "-s", "-C", str(HERE), f"bench_{function}"],
            capture_output=True, text=True,
        )
        if build.returncode != 0:
            raise SystemExit(
                f"build failed for bench_{function}:\n{build.stdout}"
                f"{build.stderr}"
            )
        command = [str(HERE / "_bench_bin" / f"bench_{function}")]

    if args.rounds < 20:
        print(f"warning: prompt 02 requires >=20 rounds; using "
              f"{args.rounds}", file=sys.stderr)

    print(f"Measuring noise floor for {function!r}: {args.rounds} "
          "independent process invocations...")
    samples = measure(command, args.rounds)
    median = statistics.median(samples)
    lo, hi = min(samples), max(samples)
    p10, p90 = lo, hi
    if len(samples) >= 10:
        deciles = statistics.quantiles(samples, n=10, method="inclusive")
        p10, p90 = deciles[0], deciles[-1]
    spread_pct = (p90 - p10) / median * 100.0 if median else float("inf")

    print(f"  samples     : {[f'{s:.3f}' for s in samples]}")
    print(f"  median      : {median:.3f} ns")
    print(f"  min / max   : {lo:.3f} / {hi:.3f} ns "
          f"({(hi - lo) / median * 100.0 if median else float('inf'):.3f}% "
          "untrimmed)")
    print(f"  p10 / p90   : {p10:.3f} / {p90:.3f} ns")
    print(f"  spread      : {spread_pct:.3f}% (trimmed, this is the "
          "noise floor)")

    out = args.out or (HERE / f"bench_{function}.noise.json")
    payload = {
        "function": function,
        "noise_floor_pct": round(spread_pct, 4),
        "rounds": args.rounds,
        "median_ns": median,
        "p10_ns": p10,
        "p90_ns": p90,
        "min_ns": lo,
        "max_ns": hi,
        "measured_on": "Apple M3 Pro, arm64, macOS",
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"  written   : {out}")

    if spread_pct >= args.max_pct:
        print(f"\nFAIL: spread {spread_pct:.3f}% >= {args.max_pct}% -- "
              "this benchmark cannot yet distinguish a real improvement "
              "from noise (prompts/02-benchmark-substrate.md). Fix it "
              "(more iterations per round, more rounds, a quieter "
              "machine) before trusting it; the harness will still read "
              "the noise floor just written and gate on it, so a bad "
              "number here directly weakens acceptance.")
        raise SystemExit(1)
    print(f"\nOK: spread {spread_pct:.3f}% < {args.max_pct}%")


if __name__ == "__main__":
    main()
