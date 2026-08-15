"""Instruction-scheduling mutations.

Two rule-based transforms:

``remove_redundant_mov``
    Drops obvious no-ops (``mov X, X``, ``add/sub X, X, #0``). Purely
    cosmetic but shrinks the instruction stream and occasionally removes a
    false dependency on cores with scoreboards.

``reschedule``
    A tiny dependency-preserving list scheduler. Within each basic block
    it computes def/use sets, builds dependency edges (including
    same-base-pointer memory ordering), and re-emits the block with a
    fixed priority: loads first, then the counter ALU chain, then stores,
    then flag-setters (``cmp``/``adds``/...), then the branch. Only a
    single block is rescheduled per call, and only if the new order
    differs -- one conceptual change per candidate, per the protocol.

    Assumes the standard ``memcpy``-style contract: buffers do not
    overlap (overlap is UB), so loads may move ahead of stores as long as
    the base pointers differ.
"""

from __future__ import annotations

import heapq
import re

from abi import (COND_BRANCH, LOAD_MNEMONICS, STORE_MNEMONICS, Instruction,
                 effect, normalise_reg, strip_comment)

from . import split_function, strip_insn

_MOV_NOOP = re.compile(r"^(?:mov)\s+(x\d+|w\d+),\s*\1$")
_ALU_NOOP = re.compile(r"^(?:add|sub)\s+(x\d+|w\d+),\s*\1,\s*#0$")

_FLAG_MNEMONICS = {"cmp", "cmn", "tst", "fcmp", "fcmpe", "fccmp", "fccmpe"}
_BASE = re.compile(r"\[(x\d+|w\d+|sp)\]")


def remove_redundant_mov(function_text: str) -> str | None:
    parts = split_function(function_text)
    if parts is None:
        return None
    preamble, label, body = parts

    out: list[str] = []
    removed = False
    for line in body:
        stripped = strip_insn(line)
        if _MOV_NOOP.match(stripped) or _ALU_NOOP.match(stripped):
            removed = True
            continue
        out.append(line)
    if not removed:
        return None
    return "\n".join(preamble + [label] + out) + "\n"


# ----------------------------------------------------------------------
# Dependency-based list scheduling
# ----------------------------------------------------------------------

def _priority_class(mnemonic: str) -> int:
    if mnemonic in LOAD_MNEMONICS:
        return 0
    if mnemonic in {"b", "br", "ret"} or mnemonic in COND_BRANCH:
        return 5
    if mnemonic in STORE_MNEMONICS:
        return 2
    if mnemonic in _FLAG_MNEMONICS or (
        mnemonic.endswith("s") and mnemonic not in STORE_MNEMONICS
    ):
        return 4
    return 1


def _memory_base(instruction: Instruction) -> str | None:
    for operand in instruction.operands:
        match = _BASE.search(operand)
        if match:
            return match.group(1)
    return None


def _schedule_block(block: list[tuple[int, Instruction]]) -> list[str] | None:
    """Reschedule one basic block; return new line texts or None."""
    insns = [insn for _, insn in block]
    n = len(insns)
    if n < 2:
        return None

    defs: list[set[str]] = []
    uses: list[set[str]] = []
    is_store = [insn.mnemonic in STORE_MNEMONICS for insn in insns]
    is_load = [insn.mnemonic in LOAD_MNEMONICS for insn in insns]
    bases = [_memory_base(insn) for insn in insns]

    for insn in insns:
        info = effect(insn)
        d = {normalise_reg(r) for r in info["loads"] + info["dirtied"]}
        u = {normalise_reg(r) for r in insn.regs()} - d
        defs.append(d)
        uses.append(u)

    # Edges only go forward (i < j) so the graph is acyclic by construction.
    edges: set[tuple[int, int]] = set()
    for i in range(n):
        for j in range(i + 1, n):
            if uses[j] & defs[i] or defs[i] & defs[j]:
                edges.add((i, j))
            # Memory ordering: same base pointer between a store and a
            # load/store keeps their relative order (conservative).
            if bases[i] and bases[j] and bases[i] == bases[j] and (
                is_store[i] or is_store[j]
            ) and (is_load[i] or is_load[j]):
                edges.add((i, j))

    preds = {i: set() for i in range(n)}
    succs = {i: set() for i in range(n)}
    for i, j in edges:
        succs[i].add(j)
        preds[j].add(i)

    heap: list[tuple[int, int, int]] = []
    for i in range(n):
        if not preds[i]:
            heapq.heappush(heap, (_priority_class(insns[i].mnemonic), i, i))
    result: list[int] = []
    while heap:
        _, i, _ = heapq.heappop(heap)
        result.append(i)
        for j in sorted(succs[i]):
            preds[j].discard(i)
            if not preds[j]:
                heapq.heappush(
                    heap, (_priority_class(insns[j].mnemonic), j, j)
                )

    if result == list(range(n)):
        return None
    return [insns[i].text for i in result]


def reschedule(function_text: str) -> str | None:
    parts = split_function(function_text)
    if parts is None:
        return None
    preamble, label, body = parts
    body_out = list(body)
    changed = False

    block: list[tuple[int, Instruction]] = []

    def flush() -> None:
        nonlocal changed, block
        if len(block) >= 2:
            new_lines = _schedule_block(block)
            if new_lines is not None:
                for (bidx, _), text in zip(block, new_lines):
                    body_out[bidx] = text
                changed = True
        block = []

    for idx, line in enumerate(body):
        stripped = strip_insn(line)
        if (
            not stripped
            or stripped.startswith(".")
            or stripped.startswith("#")
            or re.match(r"^[A-Za-z0-9_.$]+:", stripped)
        ):
            flush()
            if changed:
                break
            continue
        tokens = stripped.split(None, 1)
        mnemonic = tokens[0]
        operands = (
            [op.strip() for op in tokens[1].split(",")] if len(tokens) > 1 else []
        )
        block.append((idx, Instruction(idx + 1, line, mnemonic, operands)))
        if mnemonic in {"b", "br", "ret"} or mnemonic in COND_BRANCH:
            flush()
            if changed:
                break

    if not changed:
        return None
    return "\n".join(preamble + [label] + body_out) + "\n"
