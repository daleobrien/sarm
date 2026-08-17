#!/usr/bin/env python3
"""arm-optimize.py -- automated AArch64 optimization harness for sarm.

Implements OPTIMISATION.MD: LLM/mutation proposes -> assembler builds ->
tests prove correctness -> differential checks -> benchmark measures ->
keep only improvements, with ABI/register static checks, perf counters,
llvm-mca analysis and full artifact archiving.

Examples
--------
List the functions in a source file::

    ./scripts/arm-optimize.py --list-functions --source src/util/memcpy.S

Optimize memcpy with the local mutations (no LLM needed)::

    ./scripts/arm-optimize.py --function memcpy --source src/util/memcpy.S \
        --iterations 3 --mutate-only \
        --tests "make -C tests/unit build && ./tests/unit/_obj/test_memcpy"

Optimize with an Ollama model (the recommended local setup)::

    ./scripts/arm-optimize.py --function memcpy --source src/util/memcpy.S \
        --llm ollama --llm-model qwen2.5-coder:7b --candidates 4 \
        --iterations 20 --differential

The source file is optional: if omitted, the harness searches `src/**/*.S`
for the requested `.global` symbol. The default tests command is the
dedicated unit-test binary (`tests/unit/_obj/test_<function>`) when it
exists, otherwise the full unit suite. The default benchmark is
`scripts/benchmarks/bench_<function>` when one exists; otherwise the
dedicated unit-test binary is timed repeatedly as a wall-clock fallback.
Every candidate is archived under `.arm-optimize/` and the original
source is restored at the end unless --apply is given.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from llm import LLM  # noqa: E402
from optimizer import Optimizer  # noqa: E402

DEFAULT_WORKDIR = HERE.parent

_GLOBAL_RE = re.compile(r"(?m)^[ \t]*\.globa?l[ \t]+([A-Za-z0-9_.]+)")


def list_functions(source: Path) -> None:
    text = source.read_text()
    functions = _GLOBAL_RE.findall(text)
    if not functions:
        raise SystemExit(f"no .global functions found in {source}")
    print(f"functions in {source}:")
    for name in functions:
        print(f"  {name}")


def find_source_for_function(workdir: Path, function: str) -> Path:
    """Locate the .S file defining ``function`` under ``workdir/src``."""
    pattern = re.compile(
        rf"(?m)^[ \t]*\.globa?l[ \t]+{re.escape(function)}\b"
    )
    matches: list[Path] = []
    for source in sorted(workdir.glob("src/**/*.S")):
        try:
            text = source.read_text(errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            matches.append(source)

    if not matches:
        raise SystemExit(
            f"could not find function {function!r} in {workdir / 'src'}; "
            "pass --source to specify its file"
        )
    if len(matches) > 1:
        listed = "\n".join(f"  {m.relative_to(workdir)}" for m in matches)
        raise SystemExit(
            f"function {function!r} is defined in multiple files:\n{listed}\n"
            "pass --source to disambiguate"
        )
    return matches[0]


def unit_test_source(workdir: Path, function: str) -> Path | None:
    """The dedicated ``tests/unit/test_<function>.c`` when present."""
    path = workdir / "tests" / "unit" / f"test_{function}.c"
    return path if path.exists() else None


def benchmark_source(workdir: Path, function: str) -> Path | None:
    """The dedicated ``scripts/benchmarks/bench_<function>.c`` when present."""
    path = workdir / "scripts" / "benchmarks" / f"bench_{function}.c"
    return path if path.exists() else None


def default_tests(
    workdir: Path, function: str, explicit: list[str] | None
) -> list[str]:
    """Use the function's dedicated unit test when it has one."""
    if explicit:
        return explicit
    if unit_test_source(workdir, function):
        return [
            f"make -C tests/unit build && ./tests/unit/_obj/test_{function}"
        ]
    return ["make -C tests/unit test"]


def default_benchmark(
    workdir: Path, function: str
) -> list[str] | str | None:
    """The dedicated microbenchmark, or None.

    There used to be a fallback here that timed the function's unit test
    binary under wall clock as a cheap proxy. Measured resolution: 0.02 s
    at 0.01 s granularity, dominated by process startup -- it cannot
    resolve a change to a function that runs in nanoseconds, but the
    optimizer would accept a candidate on it anyway
    (prompts/02-benchmark-substrate.md). Failing closed here -- refusing
    to run without a real benchmark -- is better than silently accepting
    noise as an improvement. Add scripts/benchmarks/bench_<function>.c to
    unlock a function for optimization.
    """
    if benchmark_source(workdir, function):
        return [
            f"make -s -C scripts/benchmarks bench_{function}",
            "&&",
            f"./scripts/benchmarks/_bench_bin/bench_{function}",
        ]
    return None


def noise_floor_source(workdir: Path, function: str) -> Path | None:
    """The dedicated ``bench_<function>.noise.json`` when present."""
    path = (
        workdir / "scripts" / "benchmarks" / f"bench_{function}.noise.json"
    )
    return path if path.exists() else None


def default_noise_floor(workdir: Path, function: str) -> float | None:
    """The calibrated noise floor (percent) for ``function``'s benchmark.

    Produced by ``scripts/benchmarks/measure_noise_floor.py``. A benchmark
    with no calibrated noise floor cannot tell a real improvement from
    measurement noise, so ``Optimizer`` refuses to run against it rather
    than silently accepting anything faster than the current best
    (prompts/02-benchmark-substrate.md, "fail closed").
    """
    source = noise_floor_source(workdir, function)
    if source is None:
        return None
    try:
        data = json.loads(source.read_text())
        return float(data["noise_floor_pct"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def default_differential() -> list[str]:
    return ["python3", "scripts/differential.py", "--cases", "400"]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arm-optimize.py",
        description="Automated AArch64 assembly optimization loop for sarm",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--function", help="assembly function to optimize")
    parser.add_argument("--source", type=Path,
                        help=".S file containing it (default: auto-discovered)")
    parser.add_argument("--list-functions", action="store_true",
                        help="print the .global functions in --source and exit")
    parser.add_argument("--workdir", type=Path, default=DEFAULT_WORKDIR,
                        help="project root (default: parent of scripts/)")
    parser.add_argument("--out", type=Path, default=None,
                        help="archive dir (default: <workdir>/.arm-optimize)")
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--candidates", type=int, default=1,
                        help="independent LLM candidates per round")
    parser.add_argument("--rounds", type=int, default=5,
                        help="benchmark rounds per measurement (median used)")
    parser.add_argument("--tests", nargs="+", default=None,
                        help="correctness test command(s); default: "
                             "dedicated test_<function> if present, else "
                             "make -C tests/unit test")
    parser.add_argument("--benchmark", nargs="+", default=None,
                        help="benchmark command emitting JSON runtime_ns; "
                             "default: bench_<function> (required -- there "
                             "is no wall-clock fallback)")
    parser.add_argument("--noise-floor", type=float, default=None,
                        help="round-to-round noise floor (%%) for the "
                             "benchmark; default: read from "
                             "bench_<function>.noise.json (see "
                             "scripts/benchmarks/measure_noise_floor.py). "
                             "A candidate must beat best by more than this "
                             "to be accepted")
    parser.add_argument("--differential", nargs="?", const="default", default=None,
                        help="run differential testing after tests pass; "
                             "default: scripts/differential.py --cases 400")
    parser.add_argument("--llm", nargs="+", default=None,
                        help="LLM backend: a command (e.g. `ollama run "
                             "qwen2.5-coder:7b`) or the keyword `ollama`")
    parser.add_argument("--llm-model", default="qwen2.5-coder:7b",
                        help="model name for the Ollama HTTP backend")
    parser.add_argument("--llm-url", default="http://localhost:11434")
    parser.add_argument("--judge-model", default=None,
                        help="second model used as the judge/reviewer "
                             "(split LLM roles; default: deterministic gate)")
    parser.add_argument("--mutate-only", action="store_true",
                        help="use only rule-based mutations, never the LLM")
    parser.add_argument("--no-mutations", action="store_true",
                        help="disable rule-based mutations")
    parser.add_argument("--min-improvement", type=float, default=0.0,
                        help="minimum %% improvement over the best to accept")
    parser.add_argument("--target", default="apple-silicon",
                        help="scheduling target hint (apple-m2, cortex-a76, ...)")
    parser.add_argument("--abi-check", dest="abi_check", action="store_true",
                        default=True)
    parser.add_argument("--no-abi-check", dest="abi_check", action="store_false")
    parser.add_argument("--apply", action="store_true",
                        help="keep the best candidate in the source file "
                             "after the run (default restores the original)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.list_functions:
        if not args.source:
            parser.error("--list-functions requires --source")
        workdir = args.workdir.resolve()
        source = args.source if args.source.is_absolute() else workdir / args.source
        list_functions(source)
        return

    if not args.function:
        parser.error("--function is required")

    workdir = args.workdir.resolve()
    if not (workdir / "src").is_dir():
        raise SystemExit(f"--workdir {workdir} does not look like the sarm root")

    if args.source:
        source = args.source if args.source.is_absolute() else workdir / args.source
        if not source.exists():
            raise SystemExit(f"source file not found: {source}")
        source = source.resolve()
    else:
        source = find_source_for_function(workdir, args.function)

    outdir = (args.out or workdir / ".arm-optimize").resolve()

    # --- LLM setup --------------------------------------------------
    llm = None
    judge = None
    if args.mutate_only:
        use_mutations = True
    else:
        use_mutations = not args.no_mutations
        if args.llm:
            llm_command = args.llm
            if llm_command[0] == "ollama":
                llm = LLM(
                    backend="ollama-http",
                    model=args.llm_model,
                    url=args.llm_url,
                )
            else:
                llm = LLM(backend="command", command=llm_command)
            if not llm.available():
                print(f"⚠  LLM backend not reachable: {llm_command}")
                print("   Falling back to rule-based mutations only.")
                llm = None
        elif not use_mutations:
            parser.error(
                "nothing to propose candidates with: pass --llm or remove "
                "--no-mutations"
            )

    if args.judge_model and llm:
        judge = LLM(
            backend="ollama-http" if llm.backend == "ollama-http" else "command",
            model=args.judge_model,
            url=args.llm_url,
            command=llm.command,
        )

    # --- commands ----------------------------------------------------
    tests_cmds = default_tests(workdir, args.function, args.tests)
    benchmark_cmd = args.benchmark or default_benchmark(workdir, args.function)
    if benchmark_cmd is None:
        parser.error(
            f"no benchmark available for {args.function!r}; pass --benchmark, "
            "or add scripts/benchmarks/bench_<function>.c "
            "(prompts/02-benchmark-substrate.md -- there is no wall-clock "
            "fallback; a candidate can never be accepted on one)"
        )

    noise_floor_pct = args.noise_floor
    if noise_floor_pct is None:
        noise_floor_pct = default_noise_floor(workdir, args.function)
    if noise_floor_pct is None:
        parser.error(
            f"no calibrated noise floor for {args.function!r}; pass "
            "--noise-floor <pct>, or run "
            "scripts/benchmarks/measure_noise_floor.py first to write "
            f"scripts/benchmarks/bench_{args.function}.noise.json "
            "(prompts/02-benchmark-substrate.md -- a benchmark that cannot "
            "distinguish the expected improvement must fail closed, not "
            "silently accept a result inside the noise band)"
        )

    differential_cmd = None
    if args.differential:
        if args.differential == "default":
            differential_cmd = default_differential()
        else:
            differential_cmd = [args.differential]

    optimizer = Optimizer(
        source=source,
        function=args.function,
        workdir=workdir,
        outdir=outdir,
        iterations=args.iterations,
        candidates_per_round=args.candidates,
        llm=llm,
        judge=judge,
        tests_cmds=tests_cmds,
        benchmark_cmd=benchmark_cmd,
        noise_floor_pct=noise_floor_pct,
        rounds=args.rounds,
        abi_check=args.abi_check,
        differential_cmd=differential_cmd,
        use_mutations=use_mutations,
        min_improvement=args.min_improvement,
        target=args.target,
        apply=args.apply,
        quiet=args.quiet,
    )

    try:
        optimizer.optimize()
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
