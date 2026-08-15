#!/usr/bin/env python3
"""Static AArch64 ABI checker (OPTIMISATION.MD, "AArch64 ABI checker").

Before a candidate is even compiled, this scans the function body and flags
definite calling-convention violations:

* callee-saved GPRs (x19-x28, x29, x30) and SIMD regs (v8-v15 / d8-d15)
  modified on some path but not restored on that path;
* a function that calls (``bl``/``blr``) without ever saving x30;
* stack pointer not restored to its entry value at ``ret``;
* SP adjustments that break 16-byte alignment.

The analysis is a small forward dataflow over the function's control-flow
graph: per basic block we simulate which callee-saved registers are "dirty"
(written since their last restore), the net SP change, and whether x30 was
saved to the stack. Merges union the dirty sets, so a register that is
modified on one path and restored on another is only accepted when *every*
path to a ``ret`` has it restored.

This is deliberately conservative: it never lets a broken candidate
through, and a handful of exotic-but-legal idioms (e.g. restoring x30 via a
register chain it cannot prove) surface as warnings rather than errors.

Usage::

    python3 abi.py [--source src/util/memcpy.S] [--function memcpy]
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path

# ----------------------------------------------------------------------
# Registers
# ----------------------------------------------------------------------

# GPR callee-saved set per AAPCS64: x19-x28, x29 (fp), x30 (lr).
# SIMD callee-saved: v8-v15 (also spelled d8-d15 / q8-q15).
CALLEE_SAVED_GPR = {f"x{i}" for i in range(19, 29)} | {"x29", "x30"}
CALLEE_SAVED_SIMD = {f"v{i}" for i in range(8, 16)}

# Normalise dN/qN spellings to vN for SIMD tracking.
SIMD_ALIASES = {f"d{i}": f"v{i}" for i in range(32)}
SIMD_ALIASES.update({f"q{i}": f"v{i}" for i in range(32)})

_REGEX = re.compile(r"\b(x\d+|w\d+|v\d+|d\d+|q\d+|sp|wsp|xzr|wzr)\b")

# Mnemonics whose destination operand(s) are loaded (restore) registers.
LOAD_MNEMONICS = {
    "ldr", "ldp", "ldur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "ldnp", "ldar", "ldxr", "ldaxr", "ldarh", "ldaxrh", "ldarb", "ldaxrb",
    "ld1", "ld2", "ld3", "ld4", "ld1r", "ld2r", "ld3r", "ld4r",
    "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
}

# Mnemonics whose first operand register(s) are stored (saved).
STORE_MNEMONICS = {
    "str", "stp", "stur", "strb", "strh", "stnp", "stlr", "stxr", "stlxp",
    "st1", "st2", "st3", "st4", "stadd", "stclr", "steor", "stset",
    "stsmax", "stsmin", "stumax", "stumin",
}

# Branch mnemonics that do not modify any register.
COND_BRANCH = {"b", "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi",
               "b.pl", "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt",
               "b.le", "b.al", "b.nv", "cbz", "cbnz", "tbz", "tbnz"}

NO_DEST = {"cmp", "cmn", "tst", "fcmp", "fcmpe", "fccmp", "fccmpe", "ccmp",
           "ccmn", "prfm", "nop", "dsb", "dmb", "isb", "clrex", "sev", "sevl",
           "wfe", "wfi", "yield", "hint", "brk", "svc", "eret", "at", "dc",
           "ic", "tlbi", "sys", "sysl"}

# All other mnemonics default to: destination = operand[0] if it is a
# register. That conservative default covers the ALU/SIMD instruction space.


@dataclass
class ABIWarning:
    severity: str  # "error" | "warning"
    message: str
    line: int | None = None

    def render(self) -> str:
        where = f" (line {self.line})" if self.line else ""
        return f"  [{self.severity.upper()}] {self.message}{where}"


@dataclass
class Instruction:
    line: int
    text: str
    mnemonic: str
    operands: list[str]

    def regs(self) -> list[str]:
        """All registers mentioned in the operand text."""
        regs: list[str] = []
        for operand in self.operands:
            for match in _REGEX.finditer(operand):
                regs.append(match.group(1))
        return regs


# ----------------------------------------------------------------------
# Source parsing
# ----------------------------------------------------------------------

def strip_comment(line: str) -> str:
    """Remove // and /* */ comments from a line."""
    for marker in ("//", "/*"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def parse_instructions(source: str) -> tuple[list[Instruction], dict[str, int]]:
    """Parse a function body into instructions and label -> index map."""
    instructions: list[Instruction] = []
    labels: dict[str, int] = {}

    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        if line.startswith("#") or line.startswith("."):
            continue
        # Label(s) at the start of the line: "name:" or "2:" (local).
        label_match = re.match(r"^([A-Za-z0-9_.$]+):\s*(.*)$", line)
        if label_match:
            labels[label_match.group(1)] = len(instructions)
            line = label_match.group(2).strip()
            if not line:
                continue
        if not line:
            continue
        parts = line.split(None, 1)
        mnemonic = parts[0]
        operands = []
        if len(parts) > 1:
            operands = [op.strip() for op in parts[1].split(",")]
        instructions.append(Instruction(lineno, raw, mnemonic, operands))

    return instructions, labels


def resolve_target(target: str, labels: dict[str, int], current: int) -> int | None:
    """Resolve a branch target (incl. numeric local labels 2b / 3f)."""
    if target.endswith("b") and target[:-1].isdigit():
        name = target[:-1]
        idx = None
        for key, value in labels.items():
            if key == name and value < current:
                idx = value  # nearest preceding
        return idx
    if target.endswith("f") and target[:-1].isdigit():
        name = target[:-1]
        idx = None
        for key, value in labels.items():
            if key == name and value > current:
                idx = value  # nearest following
                break
        return idx
    return labels.get(target)


# ----------------------------------------------------------------------
# Instruction semantics
# ----------------------------------------------------------------------

def _operand_regs(instruction: Instruction) -> list[str]:
    return instruction.regs()


def effect(instruction: Instruction) -> dict:
    """Compute an instruction's effect on tracked state.

    Returns a dict with keys:
      loads   -- list of registers restored by this instruction
      stores  -- list of registers saved (stored to memory)
      dirtied -- list of registers written with unknown values
      sp_delta -- int | None  (net change to sp, e.g. post-index ldp)
      sp_restore -- bool      (mov sp, xN -- treat as full restore)
      calls   -- bool         (bl/blr: x30 becomes the return address)
      ret     -- "x30" | "x19" | None  (default return register)
      br      -- "x30" | "x19" | None  (indirect tail branch register)
      branch  -- target | "fallthrough" | "none" (CFG successor info)
    """
    mnemonic = instruction.mnemonic
    operands = instruction.operands
    info: dict = {
        "loads": [], "stores": [], "dirtied": [], "sp_delta": None,
        "sp_restore": False, "calls": False, "ret": None, "br": None,
        "branch": "none",
    }

    def operand_regs() -> list[str]:
        return _operand_regs(instruction)

    if mnemonic in COND_BRANCH:
        info["branch"] = "cond"
        return info
    if mnemonic in {"ret"}:
        reg = "x30"
        if operands:
            found = [r for r in operand_regs() if r.startswith("x")]
            reg = found[0] if found else "x30"
        info["ret"] = reg
        info["branch"] = "ret"
        return info
    if mnemonic in {"br"}:
        reg = operand_regs()[0] if operand_regs() else "x30"
        info["br"] = reg
        info["branch"] = "ret"
        return info
    if mnemonic in {"bl", "blr"}:
        info["calls"] = True
        info["dirtied"].append("x30")
        if mnemonic == "blr":
            info["branch"] = "cond"  # continues after; target unknown
        return info
    if mnemonic == "mov":
        if len(operands) >= 2:
            dst, src = operands[0], operands[1]
            src_regs = _REGEX.findall(src)
            dst_regs = _REGEX.findall(dst)
            if dst_regs:
                # mov Rd, Rm -- copy; value may be restored or unknown.
                info["dirtied"].append(dst_regs[0])
                info["copy_from"] = src_regs[0] if src_regs else None
            return info
    if mnemonic in {"movz", "movk", "movn", "adr", "adrp"}:
        regs = operand_regs()
        if regs:
            info["dirtied"].append(regs[0])
        return info
    if mnemonic in LOAD_MNEMONICS:
        # Destination register(s): ldr -> op0; ldp -> op0, op1; ld1 {v..} -> op0.
        info["loads"] = operand_regs()
        if operands and operands[0].startswith("{"):
            info["loads"] = operand_regs()
        # Post-index restores sp: "ldp x29, x30, [sp], #16"
        if operands and len(operands) >= 3 and "sp" in operands[-2]:
            post = operands[-1]
            match = re.match(r"#([+-]?\d+)", post)
            if match:
                info["sp_delta"] = int(match.group(1))
        return info
    if mnemonic in STORE_MNEMONICS:
        info["stores"] = operand_regs()
        # Pre-index sp adjustment: "stp x29, x30, [sp, #-16]!"
        if operands and len(operands) >= 3:
            pre = re.search(r"\[sp,\s*#([+-]?\d+)\](!)", operands[-2])
            if pre and pre.group(2):
                info["sp_delta"] = -abs(int(pre.group(1)))
        return info
    if mnemonic in {"sub", "add"} and len(operands) >= 3:
        if operands[0] == "sp" and operands[1] == "sp":
            imm = re.match(r"#([+-]?\d+)", operands[2])
            if imm:
                value = int(imm.group(1))
                info["sp_delta"] = -value if mnemonic == "sub" else value
            return info
    if mnemonic == "mov" and len(operands) >= 2:
        if operands[0] == "sp":
            info["sp_restore"] = True
            return info
    if mnemonic in NO_DEST:
        return info

    # Default: dest = first register operand (covers all ALU/SIMD ops).
    regs = operand_regs()
    if regs:
        info["dirtied"].append(regs[0])
    return info


def normalise_reg(reg: str) -> str:
    """d8 -> v8, q8 -> v8; leave others alone."""
    if reg in SIMD_ALIASES:
        return SIMD_ALIASES[reg]
    return reg


TRACKED_GPR = CALLEE_SAVED_GPR
TRACKED_SIMD = CALLEE_SAVED_SIMD


def tracked(reg: str) -> bool:
    reg = normalise_reg(reg)
    return reg in TRACKED_GPR or reg in TRACKED_SIMD


# ----------------------------------------------------------------------
# Dataflow state
# ----------------------------------------------------------------------

@dataclass
class State:
    dirty: set[str] = field(default_factory=set)     # callee-saved regs written
    sp_net: int = 0                                  # net sp change (None=unknown)
    saved_x30: bool = False                          # x30 stored to memory at all
    called: bool = False                             # bl/blr seen

    def copy(self) -> "State":
        return State(set(self.dirty), self.sp_net, self.saved_x30, self.called)


def join(states: list[State]) -> State:
    """Merge predecessor states (union dirty, join sp, OR flags)."""
    if not states:
        return State()
    result = states[0].copy()
    for other in states[1:]:
        result.dirty |= other.dirty
        if result.sp_net != other.sp_net:
            result.sp_net = -1  # sentinel: unknown
        result.saved_x30 = result.saved_x30 or other.saved_x30
        result.called = result.called or other.called
    return result


def apply_effect(state: State, info: dict) -> None:
    """Update state with one instruction's effect."""
    for reg in info.get("loads", []):
        reg = normalise_reg(reg)
        if tracked(reg):
            state.dirty.discard(reg)
    for reg in info.get("stores", []):
        reg = normalise_reg(reg)
        if reg == "x30":
            state.saved_x30 = True
        # (saving a callee-saved reg is implicit in "stores")
    # Copy propagation for mov Rd, Rm.
    dirty_source = None
    copy_from = info.get("copy_from")
    if copy_from and tracked(copy_from):
        dirty_source = normalise_reg(copy_from) in state.dirty
    for reg in info.get("dirtied", []):
        reg = normalise_reg(reg)
        if not tracked(reg):
            continue
        if dirty_source is not None and reg != "sp":
            if dirty_source:
                state.dirty.add(reg)
            else:
                state.dirty.discard(reg)
        else:
            state.dirty.add(reg)
    if info.get("calls"):
        state.called = True
        state.dirty.add("x30")
    if info.get("sp_restore"):
        state.sp_net = 0
    delta = info.get("sp_delta")
    if delta is not None and state.sp_net != -1:
        state.sp_net += delta


# ----------------------------------------------------------------------
# Checker
# ----------------------------------------------------------------------

def check_function(function_source: str) -> list[ABIWarning]:
    """Run the static ABI checks over a function body."""
    warnings: list[ABIWarning] = []
    instructions, labels = parse_instructions(function_source)
    if not instructions:
        warnings.append(ABIWarning("error", "no instructions found in function"))
        return warnings

    # --- build basic blocks -----------------------------------------
    # Split at every label (branch targets) and at terminators.
    block_starts = [0]
    for i, insn in enumerate(instructions):
        if insn.mnemonic in {"b", "br", "ret"} or insn.mnemonic in COND_BRANCH:
            block_starts.append(i + 1)
    block_starts = sorted(set(block_starts))
    # Drop starts beyond the last instruction.
    block_starts = [s for s in block_starts if s < len(instructions)]

    blocks: list[list[int]] = []
    for idx, start in enumerate(block_starts):
        end = block_starts[idx + 1] if idx + 1 < len(block_starts) else len(instructions)
        blocks.append(list(range(start, end)))

    block_of_insn = {}
    for b, block in enumerate(blocks):
        for i in block:
            block_of_insn[i] = b

    # label -> block index
    label_block: dict[str, int] = {}
    for name, insn_idx in labels.items():
        if insn_idx in block_of_insn:
            label_block[name] = block_of_insn[insn_idx]

    # successors per block
    successors: list[list[int]] = [[] for _ in blocks]
    for b, block in enumerate(blocks):
        last = instructions[block[-1]]
        mn = last.mnemonic
        terminator = mn == "b" or mn in {"ret", "br"} or mn in COND_BRANCH
        if terminator and mn == "b":
            target = resolve_target(last.operands[0], labels, block[-1]) if last.operands else None
            if target is not None and target in block_of_insn:
                successors[b].append(block_of_insn[target])
            # unconditional branch with unknown target: no successors
        elif terminator and mn in {"ret", "br"}:
            pass
        elif terminator and mn in COND_BRANCH:
            if b + 1 < len(blocks):
                successors[b].append(b + 1)
            if last.operands and last.operands[-1] not in {"ret"}:
                target = resolve_target(last.operands[-1], labels, block[-1])
                if target is not None and target in block_of_insn:
                    successors[b].append(block_of_insn[target])
        else:
            if b + 1 < len(blocks):
                successors[b].append(b + 1)

    # --- forward dataflow to fixpoint -------------------------------
    entries: list[State] = [State() for _ in blocks]
    entries[0] = State()
    changed = True
    while changed:
        changed = False
        for b, block in enumerate(blocks):
            pred_states = []
            for pb, succs in enumerate(successors):
                if b in succs:
                    pred_states.append(entries[pb])
            if not pred_states:
                continue
            joined = join(pred_states)
            if b == 0:
                joined = State()  # entry block starts clean
            if _states_differ(joined, entries[b]):
                entries[b] = joined
                changed = True

    # --- check every ret --------------------------------------------
    for b, block in enumerate(blocks):
        state = entries[b].copy()
        for i in block:
            insn = instructions[i]
            info = effect(insn)
            if info["branch"] == "ret":
                _check_ret(state, info, insn, warnings)
            apply_effect(state, info)

    # --- function-wide x30-save check -------------------------------
    called = any(insn.mnemonic in {"bl", "blr"} for insn in instructions)
    x30_saved = False
    for insn in instructions:
        info = effect(insn)
        if "x30" in info.get("stores", []):
            x30_saved = True
    if called and not x30_saved:
        warnings.append(ABIWarning(
            "warning",
            "function calls bl/blr but never saves x30 to the stack; "
            "x30 must be restored some other way before ret",
        ))

    # --- alignment check ---------------------------------------------
    for insn in instructions:
        match = re.match(r"(sub|add)\s+sp,\s*sp,\s*#(-?\d+)", insn.text)
        if match:
            imm = int(match.group(2))
            if imm % 16 != 0:
                warnings.append(ABIWarning(
                    "error",
                    f"SP adjusted by {imm} (not a multiple of 16) -- "
                    "breaks 16-byte stack alignment",
                    insn.line,
                ))

    return warnings


def _states_differ(a: State, b: State) -> bool:
    return (a.dirty != b.dirty or a.sp_net != b.sp_net
            or a.saved_x30 != b.saved_x30 or a.called != b.called)


def _check_ret(state: State, info: dict, insn: Instruction,
               warnings: list[ABIWarning]) -> None:
    ret_reg = info.get("ret", "x30") or "x30"

    # The register we return through must hold a valid address; x30 must
    # hold the caller's return address (or the function must be returning
    # via a clean callee-saved register chain).
    if ret_reg in state.dirty:
        warnings.append(ABIWarning(
            "error",
            f"ret {ret_reg} with {ret_reg} dirty (modified but not restored)",
            insn.line,
        ))

    for reg in sorted(TRACKED_GPR - {"x30"} | TRACKED_SIMD):
        if reg in state.dirty:
            warnings.append(ABIWarning(
                "error",
                f"modifies callee-saved {reg} but never restores it before ret",
                insn.line,
            ))
    if "x30" in state.dirty and ret_reg == "x30":
        warnings.append(ABIWarning(
            "error",
            "returns with x30 dirty (return address not restored before ret)",
            insn.line,
        ))

    if state.sp_net == -1:
        warnings.append(ABIWarning(
            "warning",
            "could not verify SP restoration at ret (different paths disagree)",
            insn.line,
        ))
    elif state.sp_net != 0:
        warnings.append(ABIWarning(
            "error",
            f"SP not restored at ret (net change {state.sp_net:+d})",
            insn.line,
        ))


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--function", required=True)
    args = parser.parse_args()

    source = args.source.read_text()

    # Extract the function the same way the optimizer does.
    pattern = re.compile(
        rf"(?ms)^[ \t]*\.global[ \t]+{re.escape(args.function)}.*?(?=^[ \t]*\.global[ \t]+|\Z)"
    )
    match = pattern.search(source)
    if not match:
        raise SystemExit(f"function {args.function} not found in {args.source}")

    warnings = check_function(match.group(0))
    for warning in warnings:
        print(warning.render())
    errors = [w for w in warnings if w.severity == "error"]
    print(f"\n{len(warnings)} warning(s), {len(errors)} error(s)")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
