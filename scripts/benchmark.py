#!/usr/bin/env python3
"""Benchmark runner for the optimization harness.

The benchmark is the *authority* on whether a candidate is an improvement
(OPTIMISATION.MD: "the LLM never gets to decide whether its optimization
worked"). A good benchmark program emits machine-readable JSON, e.g.::

    {"function": "memcpy", "runtime_ns": 12.34, "cycles": 8.1,
     "instructions": 16, "branches": 3, "branch_misses": 0,
     "l1_misses": 1}

`scripts/benchmarks/bench_memcpy.c` is the reference implementation of that
protocol. The runner also accepts the prototype's ``RESULT_NS=123.45``
format and, failing both, falls back to wall-clock time.

Multiple rounds are run and the median runtime is used so scheduler noise
does not flip keep/reject decisions.
"""

from __future__ import annotations

import json
import re
import statistics
import time
from dataclasses import dataclass, field

from common import run_command

# Keys that the optimizer feeds back to the LLM (OPTIMISATION.MD, perf
# counters section).
_COUNTER_KEYS = (
    "cycles",
    "instructions",
    "branches",
    "branch_misses",
    "l1_misses",
)


@dataclass
class BenchmarkResult:
    runtime_ns: float
    cycles: float | None = None
    instructions: float | None = None
    branches: float | None = None
    branch_misses: float | None = None
    l1_misses: float | None = None
    extra: dict = field(default_factory=dict)
    rounds: int = 0
    raw_output: str = ""

    def merge_counters(self, other: "BenchmarkResult") -> None:
        """Fill in counters from another measurement (e.g. perf stat)."""
        for key in _COUNTER_KEYS:
            value = getattr(other, key)
            if value is not None:
                setattr(self, key, value)

    def evidence(self) -> str:
        """The evidence block handed to the LLM (OPTIMISATION.MD L733-749)."""
        lines = [f"runtime             {self.runtime_ns:8.2f} ns"]
        if self.cycles is not None:
            lines.append(f"cycles              {self.cycles:8.1f}")
        if self.instructions is not None:
            lines.append(f"instructions        {self.instructions:8.1f}")
        if self.branches is not None:
            lines.append(f"branches            {self.branches:8.1f}")
        if self.branch_misses is not None:
            lines.append(f"branch-misses       {self.branch_misses:8.1f}")
        if self.l1_misses is not None:
            lines.append(f"L1-dcache-misses    {self.l1_misses:8.1f}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        data: dict = {"runtime_ns": self.runtime_ns}
        for key in _COUNTER_KEYS:
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        data["rounds"] = self.rounds
        return data


class Benchmark:
    """Runs the benchmark command and parses its output."""

    def __init__(
        self,
        command,
        rounds: int = 5,
        timeout: int = 600,
    ) -> None:
        self.command = command
        self.rounds = max(1, rounds)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_output(output: str, wall_ns: float) -> BenchmarkResult | None:
        """Extract a measurement from benchmark stdout.

        Priority: JSON object containing ``runtime_ns`` (the ymawky
        protocol) -> ``RESULT_NS=...`` (the OPTIMISATION.MD prototype) ->
        wall-clock time of the whole command.
        """
        # Look for a JSON object with a runtime_ns key.
        start = output.find("{")
        while start != -1:
            depth = 0
            in_string = False
            escape = False
            for i in range(start, len(output)):
                ch = output[i]
                if in_string:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            data = json.loads(output[start : i + 1])
                        except json.JSONDecodeError:
                            break
                        if isinstance(data, dict) and "runtime_ns" in data:
                            return Benchmark._from_dict(data, output)
                        break
            start = output.find("{", start + 1)

        match = re.search(r"RESULT_NS\s*=\s*([0-9.]+)", output)
        if match:
            return BenchmarkResult(
                runtime_ns=float(match.group(1)),
                raw_output=output,
            )

        return BenchmarkResult(runtime_ns=wall_ns, raw_output=output)

    @staticmethod
    def _from_dict(data: dict, output: str) -> BenchmarkResult:
        kwargs = {"extra": data}
        for key in _COUNTER_KEYS:
            if key in data:
                try:
                    kwargs[key] = float(data[key])
                except (TypeError, ValueError):
                    pass
        try:
            runtime = float(data["runtime_ns"])
        except (TypeError, ValueError):
            runtime = float("nan")
        return BenchmarkResult(runtime_ns=runtime, raw_output=output, **kwargs)

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------

    def run(self) -> BenchmarkResult | None:
        """Run the benchmark ``rounds`` times; return the median result."""
        samples: list[float] = []
        last: BenchmarkResult | None = None

        for _ in range(self.rounds):
            start = time.perf_counter_ns()
            result = run_command(self.command, timeout=self.timeout)
            elapsed = time.perf_counter_ns() - start

            if not result.success:
                print("  ✗ benchmark failed")
                print(result.summary())
                return None

            measured = self.parse_output(result.output, float(elapsed))
            if measured is None or measured.runtime_ns != measured.runtime_ns:
                print("  ✗ benchmark output unparseable")
                print(result.output[:2000])
                return None
            samples.append(measured.runtime_ns)
            last = measured

        assert last is not None
        median = statistics.median(samples)
        merged = BenchmarkResult(
            runtime_ns=median,
            extra=last.extra,
            rounds=len(samples),
            raw_output=last.raw_output,
        )
        merged.merge_counters(last)
        return merged
