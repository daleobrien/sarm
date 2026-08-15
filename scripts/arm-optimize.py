#!/usr/bin/env python3
"""arm-optimize.py -- automated AArch64 optimization harness for ymawky.

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

The default tests command is the full unit suite (`make -C tests/unit
test`); the default benchmark is `scripts/benchmarks/bench_<function>`
when one exists. Every candidate is archived under `.arm-optimize/` and
the original source is restored at the end unless --apply is given.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from llm import LLM  # noqa: E402
from optimizer import Optimizer  # noqa: E402

DEFAULT_WORKDIR = HERE.parent


def list_functions(source: Path) -> None:
    text = source.read_text()
    functions = re.findall(r"(?m)^[ \t]*\.globa?l[ \t]+([A-Za-z0-9_.]+)", text)
    if not functions:
        raise SystemExit(f"no .global functions found in {source}")
    print(f"functions in {source}:")
    for name in functions:
        print(f"  {name}")


def default_benchmark(function: str) -> list[str]:
    return [
        f"make -s -C scripts/benchmarks bench_{function}",
        "&&",
        f"./scripts/benchmarks/bench_{function}",
    ]


def default_differential() -> list[str]:
    return ["python3", "scripts/differential.py", "--cases", "400"]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arm-optimize.py",
        description="Automated AArch64 assembly optimization loop for ymawky",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--function", help="assembly function to optimize")
    parser.add_argument("--source", type=Path, help=".S file containing it")
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
                             "make -C tests/unit test")
    parser.add_argument("--benchmark", nargs="+", default=None,
                        help="benchmark command emitting JSON runtime_ns; "
                             "default: scripts/benchmarks/bench_<function>")
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
                        help="minimum % improvement over the best to accept")
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
        list_functions(args.source)
        return

    if not args.function or not args.source:
        parser.error("--function and --source are required "
                     "(or use --list-functions)")

    workdir = args.workdir.resolve()
    if not (workdir / "src").is_dir():
        raise SystemExit(f"--workdir {workdir} does not look like the ymawky root")

    source = args.source if args.source.is_absolute() else workdir / args.source
    if not source.exists():
        raise SystemExit(f"source file not found: {source}")
    source = source.resolve()

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
    tests_cmds = args.tests or ["make -C tests/unit test"]
    benchmark_cmd = args.benchmark or default_benchmark(args.function)
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
