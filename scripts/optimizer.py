#!/usr/bin/env python3
"""The optimization loop (OPTIMISATION.MD, "The final optimization loop").

The loop the whole harness exists to run::

    baseline -> propose (LLM + mutations) -> install -> ABI check
             -> build/tests -> differential -> benchmark -> keep/reject

The LLM (and the mutations) propose; the assembler, the test suite, the
differential harness and the benchmark decide. Every accepted optimization
is reproducible: each candidate's full source, its disassembly and the
benchmark evidence are archived under ``.arm-optimize/``, and the run
history is written to ``history.json``.

Artifact layout (mirrors the doc's "Directory structure"):

    .arm-optimize/
        baseline/      baseline function, disassembly, mca, perf
        candidates/    every candidate full source
        accepted/      accepted candidates (function + disassembly)
        rejected/      rejected candidates (function + disassembly)
        history.json   structured run history
        summary.txt    human-readable run summary
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import sys
from pathlib import Path

from abi import check_function
from benchmark import Benchmark, BenchmarkResult
from common import Result, run_command, to_command
from compiler import Compiler
from disassembler import Disassembler
from llm import LLM, LLMCandidate
from mca import MCA
from mutations import MutationCandidate, apply_mutations
from perf import Perf

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


class CandidateError(Exception):
    """A candidate could not be installed."""


def load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text()


class Optimizer:
    def __init__(
        self,
        *,
        source: Path,
        function: str,
        workdir: Path,
        outdir: Path,
        iterations: int = 20,
        candidates_per_round: int = 1,
        llm: LLM | None = None,
        judge: LLM | None = None,
        tests_cmds: list | None = None,
        benchmark_cmd=None,
        noise_floor_pct: float | None = None,
        rounds: int = 5,
        abi_check: bool = True,
        differential_cmd=None,
        use_mutations: bool = True,
        min_improvement: float = 0.0,
        target: str = "apple-silicon",
        apply: bool = False,
        quiet: bool = False,
    ) -> None:
        self.source = source
        self.function = function
        self.workdir = workdir
        self.outdir = outdir
        self.iterations = max(0, iterations)
        self.candidates_per_round = max(1, candidates_per_round)
        self.llm = llm
        self.judge = judge
        self.tests_cmds = tests_cmds or ["make -C tests/unit test"]
        self.benchmark_cmd = benchmark_cmd
        self.noise_floor_pct = noise_floor_pct
        self.rounds = max(1, rounds)
        self.abi_check = abi_check
        self.differential_cmd = differential_cmd
        self.use_mutations = use_mutations
        self.min_improvement = min_improvement
        self.target = target
        self.apply = apply
        self.quiet = quiet

        self.original_source = self.source.read_text()
        self.history: list[dict] = []

        self.compiler = Compiler(workdir)
        self.disassembler = Disassembler()
        self.perf = Perf(workdir)
        self.mca = MCA(mcpu=None)

        for sub in ("baseline", "candidates", "accepted", "rejected"):
            (outdir / sub).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Function extraction / installation
    # ------------------------------------------------------------------

    def extract_function(self, source_text: str) -> str:
        """The text of ``self.function`` (from its .global to the next one)."""
        pattern = re.compile(
            rf"(?ms)"
            rf"^[ \t]*\.globa?l[ \t]+{re.escape(self.function)}\b.*?"
            rf"(?=^[ \t]*\.globa?l[ \t]+|\Z)"
        )
        match = pattern.search(source_text)
        if not match:
            raise RuntimeError(f"could not locate function {self.function}")
        return match.group(0)

    def install_candidate(self, original_source: str, replacement: str) -> str:
        """Swap the function text in ``original_source`` for ``replacement``."""
        function_text = self.extract_function(original_source)
        if function_text not in original_source:
            raise CandidateError("function text not found while installing")

        repl = replacement.strip()
        # Tolerate models that drop the directives: re-add the .global line.
        if not re.search(
            rf"^[ \t]*\.globa?l[ \t]+{re.escape(self.function)}\b", repl, re.M
        ):
            repl = f".global {self.function}\n" + repl
        if not re.search(rf"^{re.escape(self.function)}:", repl, re.M):
            raise CandidateError(
                "replacement does not define the expected function label"
            )
        return original_source.replace(function_text, repl + "\n", 1)

    # ------------------------------------------------------------------
    # Context for the LLM
    # ------------------------------------------------------------------

    def signature(self, source_text: str) -> str:
        """Pull the doc-comment header above the function as a signature."""
        lines = source_text.splitlines()
        global_idx = None
        for i, line in enumerate(lines):
            if re.match(rf"^[ \t]*\.globa?l[ \t]+{re.escape(self.function)}\b", line):
                global_idx = i
                break
        if global_idx is None:
            return "(no header comment found)"
        header: list[str] = []
        for line in reversed(lines[:global_idx]):
            stripped = line.strip()
            if stripped.startswith("//"):
                header.append(line.strip().lstrip("/").strip())
            elif stripped in (".text", ".align", ""):
                continue
            elif stripped.startswith("#include"):
                break
            else:
                break
        header.reverse()
        kept = [
            h for h in header
            if any(key in h for key in (
                "Function Name", "Description", "Input", "Output",
                "Clobbered", "Returns",
            ))
        ]
        return "\n".join(kept) if kept else "(no header comment found)"

    def call_sites(self) -> str:
        """Where the function is referenced across the repo (src + tests)."""
        names = {self.function, "_" + self.function}
        matches: list[str] = []
        pattern = re.compile(rf"\b{re.escape(self.function)}\b")
        for base in (self.workdir / "src", self.workdir / "tests"):
            if not base.exists():
                continue
            for path in sorted(base.rglob("*.S")) + sorted(base.rglob("*.c")):
                text = path.read_text(errors="replace")
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if not pattern.search(line):
                        continue
                    rel = path.relative_to(self.workdir)
                    if str(rel) == str(self.source.relative_to(self.workdir)):
                        continue  # skip the definition itself
                    matches.append(f"{rel}:{lineno}: {line.strip()[:120]}")
        if not matches:
            return "(no other call sites found)"
        return "\n".join(matches[:25])

    # ------------------------------------------------------------------
    # Evidence pipeline
    # ------------------------------------------------------------------

    def compile_object(self, tag: str) -> Path | None:
        """Assemble the current source into a fresh object for disassembly."""
        obj = self.outdir / ".build" / f"{tag}.o"
        obj.parent.mkdir(parents=True, exist_ok=True)
        result = self.compiler.compile_object(self.source, obj)
        return obj if result.success else None

    def gather_evidence(self, function_text: str) -> dict:
        """Disassembly + objdump instruction count for the current source;
        mca/perf if available (they are not, on macOS -- see
        prompts/02-benchmark-substrate.md, "Replace the missing evidence").
        """
        evidence: dict = {
            "disassembly": None, "mca": None, "perf": None,
            "instructions": None,
        }
        obj = self.compile_object("current")
        if obj and self.disassembler.available():
            dis = self.disassembler.disassemble(obj)
            evidence["disassembly"] = self.disassembler.extract_function(
                dis or "", self.function
            )
            if evidence["disassembly"]:
                evidence["instructions"] = self._instruction_count(
                    evidence["disassembly"]
                )
        if self.mca.available():
            evidence["mca"] = self.mca.analyze(function_text)
        return evidence

    @staticmethod
    def _instruction_count(dis: str) -> int:
        """Static instruction count from objdump output: exact, zero-noise
        (prompts/02-benchmark-substrate.md) -- what a plain instruction
        count buys when perf/llvm-mca aren't available to say anything
        about scheduling or throughput.
        """
        lines = Disassembler.normalize(dis).splitlines()
        return sum(
            1 for line in lines
            if line and not line.rstrip().endswith(":")
        )

    def _disassembly_diff(self, base_dis: str | None,
                          cand_dis: str | None) -> str:
        """Structural diff between two disassemblies, addresses/bytes
        stripped so only real machine-code changes show
        (prompts/02-benchmark-substrate.md, "structural disassembly diff
        between baseline and candidate").
        """
        if not base_dis or not cand_dis:
            return "(disassembly diff unavailable -- is objdump installed?)"
        base = Disassembler.normalize(base_dis).splitlines()
        cand = Disassembler.normalize(cand_dis).splitlines()
        diff = "\n".join(
            difflib.unified_diff(
                base, cand, fromfile="best-so-far", tofile="candidate",
                lineterm="",
            )
        )
        return diff or "(no instruction-level change)"

    def benchmark(self) -> BenchmarkResult | None:
        if not self.benchmark_cmd:
            return None
        return Benchmark(self.benchmark_cmd, rounds=self.rounds).run()

    def run_tests(self) -> Result:
        if not self.quiet:
            print("  Running correctness tests...")
        result = self.compiler.test(self.tests_cmds)
        if result.success:
            if not self.quiet:
                print("  ✓ tests passed")
        else:
            print("  ✗ tests failed")
            print(result.summary())
        return result

    def run_differential(self) -> bool:
        if not self.differential_cmd:
            return True
        if not self.quiet:
            print("  Running differential tests...")
        result = self.compiler.run(self.differential_cmd, timeout=1800)
        if result.success:
            if not self.quiet:
                print("  ✓ differential passed")
        else:
            print("  ✗ differential failed")
            print(result.summary())
        return result.success

    # ------------------------------------------------------------------
    # Archiving
    # ------------------------------------------------------------------

    def save_candidate(self, name: str, source_text: str, function_text: str,
                       subdir: str, disassembly: str | None = None) -> None:
        dir_path = self.outdir / subdir
        dir_path.mkdir(parents=True, exist_ok=True)
        (dir_path / f"{name}.S").write_text(source_text)
        (dir_path / f"{name}.function.S").write_text(function_text)
        if disassembly:
            (dir_path / f"{name}.dis").write_text(disassembly)

    def write_history(self) -> None:
        (self.outdir / "history.json").write_text(
            json.dumps(self.history, indent=2) + "\n"
        )

    # ------------------------------------------------------------------
    # The loop
    # ------------------------------------------------------------------

    def optimize(self) -> None:
        print()
        print("=" * 60)
        print("AArch64 optimizer")
        print("=" * 60)
        print()
        print(f"Function : {self.function}")
        print(f"Source   : {self.source}")
        print(f"Workdir  : {self.workdir}")
        print(f"Out      : {self.outdir}")
        print()

        # A benchmark that cannot distinguish the expected improvement from
        # noise must fail closed rather than let a candidate inside the
        # noise band become the new best (prompts/02-benchmark-substrate.md).
        if self.benchmark_cmd and self.noise_floor_pct is None:
            raise RuntimeError(
                "no noise floor calibrated for this benchmark -- refusing "
                "to judge candidates against it. Run "
                "scripts/benchmarks/measure_noise_floor.py, or pass "
                "--noise-floor explicitly."
            )
        print(f"Noise floor: {self.noise_floor_pct:.3f}% "
              "(candidates must beat best by more than this)")
        print()

        # ---------------------------------------------------------- baseline
        print("BASELINE")
        baseline_text = self.extract_function(self.original_source)
        self.save_candidate(
            "baseline", self.original_source, baseline_text, "baseline"
        )

        tests = self.run_tests()
        if not tests.success:
            raise RuntimeError("baseline does not pass the correctness tests")

        baseline_bench = self.benchmark()
        if baseline_bench is None:
            raise RuntimeError(
                "could not establish a baseline benchmark; pass --benchmark"
            )
        baseline = baseline_bench.runtime_ns
        best = baseline
        best_bench = baseline_bench

        evidence = self.gather_evidence(baseline_text)
        (self.outdir / "baseline" / "baseline.dis").write_text(
            evidence["disassembly"] or "(disassembly unavailable)"
        )
        (self.outdir / "baseline" / "mca.txt").write_text(
            evidence["mca"].summary() if evidence["mca"] else "(llvm-mca unavailable)"
        )
        (self.outdir / "baseline" / "benchmark.json").write_text(
            json.dumps(best_bench.to_dict(), indent=2) + "\n"
        )

        print()
        print(f"Baseline: {best:.2f} ns")
        if best_bench.instructions is not None:
            print(
                f"          {best_bench.instructions:.0f} instructions, "
                f"{best_bench.cycles:.0f} cycles"
            )
        print()

        accepted_count = 0
        rejected_count = 0
        accepted_summaries: list[str] = []

        for iteration in range(1, self.iterations + 1):
            print("=" * 60)
            print(f"ITERATION {iteration}")
            print("=" * 60)

            current_source = self.source.read_text()
            function_text = self.extract_function(current_source)

            # ------------------------------------------------ candidates
            candidates: list[tuple[str, str, str]] = []  # (origin, source, explanation)
            if self.llm and self.llm.available():
                if not self.quiet:
                    print(f"  Asking LLM for {self.candidates_per_round} candidate(s)...")
                context = self._build_context(
                    function_text, best_bench, evidence
                )
                prompt = load_prompt("optimize.txt").format(**context)
                llm_results = self.llm.generate(prompt, self.candidates_per_round)
                if llm_results:
                    for c in llm_results:
                        candidates.append(("llm", c.assembly, c.explanation))
                else:
                    print("  (LLM produced no candidates this round)")

            if self.use_mutations:
                for m in apply_mutations(function_text):
                    candidates.append((f"mutation:{m.name}", m.source, m.explanation))

            if not candidates:
                print("  (no candidates this round -- stopping)")
                break

            # -------------------------------------------------- evaluate
            for index, (origin, candidate_src, explanation) in enumerate(
                candidates, start=1
            ):
                print()
                print(f"  Candidate {index}/{len(candidates)} [{origin}]")
                if explanation:
                    print(f"  Proposal: {explanation}")

                label = f"iter{iteration}-cand{index}"

                # ABI static check first: never even compile a broken ABI.
                if self.abi_check:
                    # Pass the function being replaced: NZCV is a return value
                    # for the carry-ABI functions here, and only a comparison
                    # against the original can show that a candidate moved a
                    # flag-setting instruction into a live flag range.
                    abi_warnings = check_function(candidate_src,
                                                  original=current_source)
                    abi_errors = [w for w in abi_warnings if w.severity == "error"]
                    if abi_errors:
                        for w in abi_errors:
                            print(w.render())
                        print("  → rejected: ABI violation")
                        self.save_candidate(
                            label, current_source, candidate_src, "rejected"
                        )
                        self.history.append(self._history_entry(
                            iteration, index, origin, explanation,
                            result="rejected", reason="ABI violation",
                        ))
                        rejected_count += 1
                        continue

                # Install.
                try:
                    new_source = self.install_candidate(
                        current_source, candidate_src
                    )
                except CandidateError as exc:
                    print(f"  → rejected: {exc}")
                    self.save_candidate(
                        label, current_source, candidate_src, "rejected"
                    )
                    self.history.append(self._history_entry(
                        iteration, index, origin, explanation,
                        result="rejected", reason=str(exc),
                    ))
                    rejected_count += 1
                    continue

                backup = current_source
                self.source.write_text(new_source)

                # Correctness.
                tests = self.run_tests()
                if not tests.success:
                    print("  → rejected: correctness failure")
                    self._revert(backup, label, iteration, index, origin,
                                 explanation, candidate_src, "correctness failure")
                    rejected_count += 1
                    continue

                # Differential testing (when configured).
                if not self.run_differential():
                    print("  → rejected: differential mismatch")
                    self._revert(backup, label, iteration, index, origin,
                                 explanation, candidate_src,
                                 "differential mismatch")
                    rejected_count += 1
                    continue

                # Benchmark.
                runtime_bench = self.benchmark()
                if runtime_bench is None:
                    print("  → rejected: benchmark failure")
                    self._revert(backup, label, iteration, index, origin,
                                 explanation, candidate_src, "benchmark failure")
                    rejected_count += 1
                    continue
                runtime = runtime_bench.runtime_ns
                improvement = (best - runtime) / best * 100.0
                print(f"  Runtime: {runtime:.2f} ns "
                      f"(improvement vs best: {improvement:+.3f}%, "
                      f"noise floor: {self.noise_floor_pct:.3f}%)")

                # A candidate inside the noise band is not a demonstrated
                # improvement (prompts/02-benchmark-substrate.md): require
                # beating best by more than both the noise floor and any
                # explicit --min-improvement, not a bare `runtime < best`.
                required_improvement = max(
                    self.min_improvement, self.noise_floor_pct
                )
                # Compiled once and reused for both the judge's diff and
                # the archived disassembly below.
                cand_dis = self._current_disassembly()

                # Optional LLM judge.
                keep = runtime < best * (1.0 - required_improvement / 100.0)
                judge_reason = None
                if keep and self.judge and self.judge.available():
                    verdict = self._ask_judge(
                        label, explanation, evidence, tests, runtime_bench,
                        improvement, cand_dis,
                    )
                    if verdict is not None:
                        keep, judge_reason = verdict

                if keep:
                    print("  ✓ NEW BEST")
                    best = runtime
                    best_bench = runtime_bench
                    accepted_count += 1
                    accepted_summaries.append(
                        f"{label} [{origin}]: {improvement:+.3f}% "
                        f"({runtime:.2f} ns) -- {explanation}"
                    )
                    # Archive: full source + function + fresh disassembly.
                    self.save_candidate(
                        label, new_source, candidate_src, "accepted",
                        cand_dis,
                    )
                    self.history.append(self._history_entry(
                        iteration, index, origin, explanation,
                        runtime_ns=runtime,
                        improvement_percent=improvement,
                        result="accepted",
                        reason=judge_reason or "benchmark improvement",
                    ))
                    # Evidence refreshes against the new best.
                    evidence = self.gather_evidence(
                        self.extract_function(new_source)
                    )
                else:
                    reason = "no improvement" if not judge_reason else judge_reason
                    print(f"  → rejected: {reason}")
                    self._revert(backup, label, iteration, index, origin,
                                 explanation, candidate_src, reason)
                    rejected_count += 1

            self.write_history()

        # ----------------------------------------------------------- final
        print()
        print("=" * 60)
        print("RESULT")
        print("=" * 60)
        total_improvement = (baseline - best) / baseline * 100.0
        print(f"Baseline : {baseline:.2f} ns")
        print(f"Best     : {best:.2f} ns")
        print(f"Improvement: {total_improvement:.3f}%")
        print(f"Accepted optimizations: {accepted_count}")
        print(f"Rejected candidates: {rejected_count}")
        print(f"History: {self.outdir / 'history.json'}")

        summary = self._summary_text(
            baseline, best, total_improvement,
            accepted_count, rejected_count, accepted_summaries,
        )
        (self.outdir / "summary.txt").write_text(summary)
        print()
        print(summary)

        # Restore the original source unless the user asked to keep results.
        if not self.apply:
            self.source.write_text(self.original_source)
            print(f"Restored original {self.source} "
                  "(pass --apply to keep the best candidate in place)")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_context(self, function_text, bench: BenchmarkResult,
                       evidence: dict) -> dict:
        instructions = evidence.get("instructions")
        return {
            "function": self.function,
            "signature": self.signature(self.source.read_text()),
            "call_sites": self.call_sites(),
            "source": function_text,
            "disassembly": evidence["disassembly"]
            or "(disassembly unavailable -- is objdump installed?)",
            "instruction_count": (
                f"{instructions} instructions (objdump on the assembled "
                "object -- exact, zero-noise; not a throughput or "
                "scheduling estimate, just a count)"
                if instructions is not None
                else "(unavailable -- is objdump installed?)"
            ),
            "benchmark": f"runtime {bench.runtime_ns:.2f} ns (median of "
                         f"{bench.rounds} rounds, noise floor "
                         f"{self.noise_floor_pct:.3f}%)",
            # No `perf` on macOS (docs/ANALYSIS-TOOLING.MD, "Tooling
            # reality on this machine") -- say so plainly rather than
            # fabricate counter data (prompts/02-benchmark-substrate.md).
            "perf": "(perf stat unavailable on this platform -- no `perf` "
                    "command; the objdump instruction count and "
                    "disassembly above substitute for it)"
            if not self.perf.available()
            else bench.evidence(),
            "mca": evidence["mca"].summary()
            if evidence["mca"]
            else "(llvm-mca unavailable on this platform -- not installed; "
                 "the objdump instruction count above substitutes for it)",
            "target": self.target,
        }

    def _ask_judge(self, label, explanation, evidence, tests, bench,
                   improvement, candidate_dis=None) -> tuple[bool, str] | None:
        prompt = load_prompt("review.txt").format(
            function=self.function,
            explanation=explanation,
            diff=self._disassembly_diff(evidence.get("disassembly"),
                                        candidate_dis),
            tests_result="PASS" if tests.success else "FAIL",
            benchmark=bench.evidence(),
            improvement_percent=f"{improvement:+.3f}%",
        )
        results = self.judge.generate(prompt, 1)
        if not results:
            return None
        from llm import _extract_json

        data = _extract_json(results[0].raw)
        if not data:
            return None
        keep = bool(data.get("keep", True))
        reason = str(data.get("reason", "judge rejected"))
        return keep, reason

    def _current_disassembly(self) -> str | None:
        obj = self.compile_object("candidate")
        if not obj or not self.disassembler.available():
            return None
        dis = self.disassembler.disassemble(obj)
        return self.disassembler.extract_function(dis or "", self.function)

    def _revert(self, backup: str, label: str, iteration, index,
                origin, explanation: str, candidate_src: str,
                reason: str) -> None:
        self.source.write_text(backup)
        self.save_candidate(label, backup, candidate_src, "rejected")
        self.history.append(self._history_entry(
            iteration, index, origin, explanation,
            result="rejected", reason=reason,
        ))

    @staticmethod
    def _history_entry(iteration, index, origin, explanation, *,
                       result, reason, runtime_ns=None,
                       improvement_percent=None) -> dict:
        entry: dict = {
            "iteration": iteration,
            "candidate": index,
            "origin": origin,
            "explanation": explanation,
            "result": result,
            "reason": reason,
        }
        if runtime_ns is not None:
            entry["runtime_ns"] = runtime_ns
        if improvement_percent is not None:
            entry["improvement_percent"] = improvement_percent
        return entry

    def _summary_text(self, baseline, best, improvement, accepted,
                      rejected, accepted_summaries) -> str:
        lines = [
            "ARM OPTIMIZER",
            "=============",
            f"Function: {self.function}",
            "",
            f"Baseline: {baseline:.2f} ns",
            f"Best:     {best:.2f} ns",
            f"Improvement: {improvement:.3f}%",
            "",
            f"Accepted optimizations: {accepted}",
            f"Rejected candidates: {rejected}",
            "",
            "Accepted:",
        ]
        lines += [f"  - {s}" for s in accepted_summaries] or ["  (none)"]
        lines.append("")
        lines.append("Correctness tests: PASS (gate for every candidate)")
        lines.append("ABI checks: static, before compile")
        lines.append("Differential tests: "
                     + ("enabled" if self.differential_cmd else "not configured"))
        return "\n".join(lines)
