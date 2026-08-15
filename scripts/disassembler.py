#!/usr/bin/env python3
"""Disassembly wrapper (OPTIMISATION.MD, "Compiler Explorer-style
analysis locally").

Produces the evidence artifacts the LLM sees and the harness archives:

* ``<name>.asm``   -- source assembly
* ``<name>.dis``   -- actual generated machine code (``objdump -d``)
* ``diff.asm``     -- unified diff between baseline and candidate machine
                      code, so a "clever" source change that produces
                      identical bytes is exposed immediately.

``objdump`` handles both Mach-O (macOS) and ELF (Linux); the symbol name is
matched with or without the Mach-O leading underscore.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

from common import Result, detect_tool, run_command

_SYMBOL_HEADER = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
# objdump instruction lines: "<addr>: <bytes>\t<text>"
_INSN_LINE = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2,8}\s+)*\s*(.*)$")


class Disassembler:
    def __init__(self, tool: str | None = None) -> None:
        self.tool = tool or detect_tool("llvm-objdump", "objdump")

    def available(self) -> bool:
        return self.tool is not None

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------

    def disassemble(self, obj: Path) -> str | None:
        """Full ``objdump -d`` output for a file, or None on failure."""
        if not self.tool:
            return None
        result = run_command([self.tool, "-d", str(obj)])
        if not result.success:
            return None
        return result.output

    def extract_function(self, dis: str, function: str) -> str | None:
        """The disassembly of one function (``<func>:`` ... next symbol)."""
        lines = dis.splitlines()
        start = end = None
        for i, line in enumerate(lines):
            match = _SYMBOL_HEADER.match(line.strip())
            if not match:
                continue
            name = match.group(1)
            if name == function or name == "_" + function:
                start = i
                continue
            if start is not None:
                end = i
                break
        if start is None:
            return None
        return "\n".join(lines[start:end])

    @staticmethod
    def normalize(dis: str) -> str:
        """Strip addresses/bytes, keep only the instruction text.

        Lets the diff show *semantic* machine-code changes instead of the
        noise of addresses shifting.
        """
        lines = []
        for line in dis.splitlines():
            match = _INSN_LINE.match(line)
            if match:
                lines.append(match.group(1).strip())
            elif _SYMBOL_HEADER.match(line.strip()):
                lines.append(line.strip())
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def write_artifacts(
        self,
        outdir: Path,
        name: str,
        baseline_src: str,
        candidate_src: str,
        baseline_dis: str,
        candidate_dis: str,
    ) -> None:
        """Write baseline.asm / candidate.asm / baseline.dis / candidate.dis
        / diff.asm into ``outdir``."""
        outdir.mkdir(parents=True, exist_ok=True)

        (outdir / f"{name}.asm").write_text(baseline_src)
        (outdir / f"candidate.asm").write_text(candidate_src)

        if baseline_dis:
            (outdir / f"{name}.dis").write_text(baseline_dis)
        if candidate_dis:
            (outdir / f"candidate.dis").write_text(candidate_dis)

        if baseline_dis and candidate_dis:
            base = Disassembler.normalize(baseline_dis).splitlines()
            cand = Disassembler.normalize(candidate_dis).splitlines()
            diff = "\n".join(
                difflib.unified_diff(
                    base,
                    cand,
                    fromfile=f"{name}.dis (normalized)",
                    tofile="candidate.dis (normalized)",
                    lineterm="",
                )
            )
            (outdir / "diff.asm").write_text(diff + "\n")
