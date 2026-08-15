#!/usr/bin/env python3
"""llvm-mca wrapper (OPTIMISATION.MD, "Use Compiler Explorer-style analysis
locally").

Runs LLVM's machine code analyzer over a single function and extracts the
throughput summary (Instructions / Total Cycles / IPC / Dispatch Width /
Block RThroughput) that is handed to the LLM alongside the benchmark, so it
can see the *scheduling* quality of its candidate, not just the runtime.

``llvm-mca`` ships with Xcode's command line tools on macOS and with most
Linux toolchains, but is not always installed; the harness treats a missing
tool as "no data" rather than a failure.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from common import Result, detect_tool, run_command


@dataclass
class MCAReport:
    instructions: int | None = None
    total_cycles: int | None = None
    ipc: float | None = None
    dispatch_width: int | None = None
    block_rt: str | None = None
    raw: str = ""

    def summary(self) -> str:
        lines = ["LLVM-MCA"]
        if self.instructions is not None:
            lines.append(f"Instructions:      {self.instructions}")
        if self.total_cycles is not None:
            lines.append(f"Total Cycles:      {self.total_cycles}")
        if self.ipc is not None:
            lines.append(f"IPC:               {self.ipc:.2f}")
        if self.dispatch_width is not None:
            lines.append(f"Dispatch Width:    {self.dispatch_width}")
        if self.block_rt:
            lines.append(f"Block RThroughput: {self.block_rt}")
        return "\n".join(lines)


# Apple Silicon cores vary by toolchain; try the requested target first,
# then a small list of known-good mcpu names.
_MCPU_CANDIDATES = ["apple-m2", "apple-m1", "apple-a14", "cortex-a76", "generic"]


class MCA:
    def __init__(
        self,
        tool: str | None = None,
        mcpu: str | None = None,
        iterations: int = 100,
    ) -> None:
        self.tool = tool or detect_tool("llvm-mca")
        self.mcpu = mcpu
        self.iterations = iterations

    def available(self) -> bool:
        return self.tool is not None

    def analyze(self, function_source: str) -> MCAReport | None:
        """Analyze a single function body; None if the tool is missing."""
        if not self.tool:
            return None

        with tempfile.TemporaryDirectory() as tmp:
            asm_path = Path(tmp) / "function.s"
            asm_path.write_text(".text\n" + function_source + "\n")

            for mcpu in self._mcpus():
                argv = [
                    self.tool,
                    "-mtriple=arm64-apple-macosx",
                    f"-mcpu={mcpu}",
                    f"-iterations={self.iterations}",
                    str(asm_path),
                ]
                result = run_command(argv, timeout=300)
                if result.success:
                    return self._parse(result.output)
                if "error" in result.error.lower() and "no such cpu" in result.error.lower():
                    continue
                # Any other failure: report it as a failed analysis.
                return None
        return None

    def _mcpus(self) -> list[str]:
        if self.mcpu:
            return [self.mcpu] + [c for c in _MCPU_CANDIDATES if c != self.mcpu]
        return list(_MCPU_CANDIDATES)

    @staticmethod
    def _parse(output: str) -> MCAReport:
        report = MCAReport(raw=output)

        def grab(pattern: str) -> str | None:
            match = re.search(pattern, output)
            return match.group(1) if match else None

        if (v := grab(r"Instructions:\s+(\d+)")):
            report.instructions = int(v)
        if (v := grab(r"Total Cycles:\s+(\d+)")):
            report.total_cycles = int(v)
        if (v := grab(r"IPC:\s+([0-9.]+)")):
            report.ipc = float(v)
        if (v := grab(r"Dispatch Width:\s+(\d+)")):
            report.dispatch_width = int(v)
        if (v := grab(r"Block RThroughput:\s+([0-9.]+)")):
            report.block_rt = f"{v} cycles"
        return report
