"""Rule-based candidate mutations (OPTIMISATION.MD, "Even better:
mutation + LLM").

Three sources of candidates feed the loop: the LLM, rule-based
transformations, and (as inspiration) existing implementations. This
package is the rule-based source -- deterministic, dependency-preserving
transforms that either apply cleanly (returning a new function body) or
decline (returning None), so the harness can fall back to LLM proposals
without hand-holding.

Every mutation follows the candidate protocol: it rewrites *one* function
and changes *one* conceptual thing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# ----------------------------------------------------------------------
# Shared parsing helpers (must precede the mutation imports below: the
# mutation modules import these names from the package).
# ----------------------------------------------------------------------

def split_function(function_text: str) -> tuple[list[str], str, list[str]] | None:
    """Split function text into (preamble, label_line, body_lines)."""
    lines = function_text.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"^[A-Za-z0-9_.$]+:\s*$", line.strip()):
            return lines[:i], lines[i], lines[i + 1 :]
    return None


def strip_insn(line: str) -> str:
    """Remove comments and whitespace from an assembly line."""
    for marker in ("//", "/*"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def fresh_numeric_labels(body_lines: list[str], count: int) -> list[int]:
    """Pick numeric local-label numbers not already used in the body."""
    used: set[int] = set()
    for line in body_lines:
        match = re.match(r"^\s*(\d+):", line)
        if match:
            used.add(int(match.group(1)))
    start = 1
    while start in used:
        start += 1
    out: list[int] = []
    for _ in range(count):
        while start in used:
            start += 1
        out.append(start)
        used.add(start)
    return out


from .neon import neon_32b
from .scheduling import remove_redundant_mov, reschedule
from .unroll import unroll_2x

MUTATIONS: list[tuple[str, str, object]] = [
    ("scheduling:remove-redundant-mov", "drop `mov X, X` no-ops", remove_redundant_mov),
    ("scheduling:reschedule", "dependency-preserving instruction reorder", reschedule),
    ("unroll:2x", "unroll the 16-byte ldp/stp loop by 2", unroll_2x),
    ("neon:ld1-st1-32b", "32-byte NEON (ld1/st1) main loop", neon_32b),
]


@dataclass
class MutationCandidate:
    name: str
    source: str
    explanation: str


def list_mutations() -> list[str]:
    return [name for name, _, _ in MUTATIONS]


def apply_mutations(function_text: str) -> list[MutationCandidate]:
    """Try every mutation; return those that produced a new function."""
    candidates: list[MutationCandidate] = []
    for name, explanation, fn in MUTATIONS:
        try:
            result = fn(function_text)
        except Exception as exc:  # defensive: a bad mutation must not kill the run
            print(f"  ✗ mutation {name} errored: {exc}")
            continue
        if result is not None and result.strip() != function_text.strip():
            candidates.append(
                MutationCandidate(name=name, source=result, explanation=explanation)
            )
    return candidates
