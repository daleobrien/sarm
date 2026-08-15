#!/usr/bin/env python3
"""Linux ``perf stat`` wrapper (OPTIMISATION.MD, "The really important
addition: perf counters").

Feeds the LLM real hardware counters -- instructions, cycles, branches,
branch-misses, L1 misses -- instead of just a wall-clock runtime, so it can
reason about *why* a candidate is slow. On macOS there is no ``perf``; the
wrapper degrades gracefully and the harness simply runs on runtime alone
(Apple Silicon benchmarks still work fine through the benchmark module).
"""

from __future__ import annotations

import json
from pathlib import Path

from common import detect_tool, run_command

DEFAULT_EVENTS = [
    "cycles",
    "instructions",
    "branches",
    "branch-misses",
    "l1-dcache-loads",
    "l1-dcache-misses",
]


class Perf:
    def __init__(
        self,
        workdir: Path,
        events: list[str] | None = None,
        tool: str | None = None,
    ) -> None:
        self.workdir = workdir
        self.events = events or DEFAULT_EVENTS
        self.tool = tool or detect_tool("perf")

    def available(self) -> bool:
        return self.tool is not None

    def stat(self, command, timeout: int = 900) -> dict | None:
        """Run ``command`` under ``perf stat -j`` and return counters.

        Returns a dict keyed by event name with float values, or None if
        perf is unavailable / the run failed. Counter values are per-run
        totals; divide by a known iteration count in the benchmark program
        to get per-call numbers.
        """
        if not self.tool:
            return None
        argv = [self.tool, "stat", "-j"]
        for event in self.events:
            argv += ["-e", event]
        argv += ["--", *list(command)]
        result = run_command(argv, cwd=str(self.workdir), timeout=timeout)
        if not result.success:
            return None

        try:
            data = json.loads(result.output)
        except json.JSONDecodeError:
            # Older perf -j output: {"event": {"value": n, ...}, ...}
            try:
                start = result.output.find("{")
                data = json.loads(result.output[start:])
            except json.JSONDecodeError:
                return None

        counters: dict[str, float] = {}
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and "value" in value:
                    try:
                        counters[key] = float(value["value"])
                    except (TypeError, ValueError):
                        pass
                elif isinstance(value, (int, float)):
                    counters[key] = float(value)
        return counters or None
