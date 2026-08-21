#!/usr/bin/env python3
"""Static AArch64 ABI checker (OPTIMISATION.MD, "AArch64 ABI checker").

Before a candidate is even compiled, this scans the function body and flags
definite calling-convention violations:

* callee-saved GPRs (x19-x28, x29, x30) and SIMD regs (v8-v15 / d8-d15)
  modified on some path but not restored on that path;
* a function that calls (``bl``/``blr``) without ever saving x30;
* stack pointer not restored to its entry value at ``ret``;
* SP adjustments that break 16-byte alignment;
* **the condition flags (NZCV)** -- 36 functions in this repo return their
  status in the carry flag ("carry clear = success / carry set = failure"),
  so NZCV is a live-out value and part of the ABI. A transformation that
  moves a flag-setting instruction between the status-setting site and the
  ``ret`` silently corrupts the return value while the returned *data* still
  looks correct, which no unit test checking only data will catch.

The analysis is a forward dataflow over the function's control-flow graph: per
instruction we simulate which callee-saved registers are "dirty" (written
since their last restore), the net SP change, and whether x30 was saved to the
stack. Merges union the dirty sets, so a register that is modified on one path
and restored on another is only accepted when *every* path to a ``ret`` has it
restored. NZCV is handled by a separate backward liveness pass plus a forward
reaching-definitions pass.

Parsing, macro expansion and branch resolution all live in ``asmparse``; this
module deliberately owns no parser of its own. It used to, and that parser
dropped every ``.L...`` local label, so the CFG this dataflow runs over had
almost no edges and the "every path" claim was vacuous.

This is deliberately conservative: it never lets a broken candidate through,
and a handful of exotic-but-legal idioms (e.g. restoring x30 via a register
chain it cannot prove) surface as warnings rather than errors.

Usage::

    python3 abi.py --source src/util/memcpy.S --function memcpy
    python3 abi.py --source src/crypto/gcm/data.S --function .Lgcm_ghash_run
    python3 abi.py --source src/crypto/p256/sqr_mul.S --function p256_reduce --flags
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from asmparse import (  # noqa: E402
    REG_RE as _REGEX,
    Instruction,
    Macro,
    expand_macros,
    index_source,
    load_macros,
    parse_instructions,
    resolve_target,
    split_operands,
    strip_comment,
)

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

# Mnemonics whose destination operand(s) are loaded (restore) registers.
LOAD_MNEMONICS = {
    "ldr", "ldp", "ldur", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw",
    "ldnp", "ldar", "ldxr", "ldaxr", "ldarh", "ldaxrh", "ldarb", "ldaxrb",
    "ldxp", "ldaxp", "ldursw", "ldurb", "ldurh", "ldursb", "ldursh",
    "ld1", "ld2", "ld3", "ld4", "ld1r", "ld2r", "ld3r", "ld4r",
    "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
}

# Load mnemonics writing two destination registers.
LOAD_PAIR = {"ldp", "ldnp", "ldxp", "ldaxp"}

# Mnemonics whose first operand register(s) are stored (saved).
STORE_MNEMONICS = {
    "str", "stp", "stur", "strb", "strh", "stnp", "stlr", "stxr", "stlxp",
    "sturb", "sturh", "stlxr", "stxp",
    "st1", "st2", "st3", "st4", "stadd", "stclr", "steor", "stset",
    "stsmax", "stsmin", "stumax", "stumin",
}

STORE_PAIR = {"stp", "stnp", "stxp", "stlxp"}

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

# ----------------------------------------------------------------------
# Condition flags (NZCV)
# ----------------------------------------------------------------------
#
# NZCV is a register like any other; it is simply spelled differently. These
# two tables say who writes it and who reads it. Getting the *write* set too
# small is the dangerous direction: a missed writer means the checker believes
# a status value survives to `ret` when it has actually been destroyed.

FLAG_DEFS = {
    "adds", "adcs", "subs", "sbcs", "ands", "bics", "negs", "ngcs",
    "cmp", "cmn", "tst", "ccmp", "ccmn",
    "fcmp", "fcmpe", "fccmp", "fccmpe",
    "rmif", "setf8", "setf16", "cfinv", "msr",
    # A call clobbers NZCV: AAPCS64 does not preserve the condition flags
    # across a procedure call, and neither does the kernel across `svc`.
    "bl", "blr", "svc",
}

FLAG_USES = {
    "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs",
    "ccmp", "ccmn", "cfinv",
    "csel", "csinc", "csinv", "csneg", "cset", "csetm",
    "cinc", "cinv", "cneg", "fcsel", "mrs",
}


def defines_flags(insn: Instruction) -> bool:
    return insn.mnemonic in FLAG_DEFS


def uses_flags(insn: Instruction) -> bool:
    mnemonic = insn.mnemonic
    if mnemonic in FLAG_USES:
        return True
    # b.<cond> and the BTI-era bc.<cond>; b.al/b.nv read nothing but are
    # harmless to include.
    return mnemonic.startswith("b.") or mnemonic.startswith("bc.")


def _norm_text(insn: Instruction) -> str:
    """A stable, whitespace-insensitive identity for one instruction."""
    return " ".join(
        [insn.mnemonic.lower()] + [o.lower() for o in insn.operands]
    )


@dataclass
class ABIWarning:
    severity: str  # "error" | "warning"
    message: str
    line: int | None = None

    def render(self) -> str:
        where = f" (line {self.line})" if self.line else ""
        return f"  [{self.severity.upper()}] {self.message}{where}"


# ----------------------------------------------------------------------
# Instruction semantics
# ----------------------------------------------------------------------

def _regs(text: str) -> list[str]:
    return [m.group(1) for m in _REGEX.finditer(text)]


def _sp_delta(operands: list[str]) -> int | None:
    """Net SP change encoded in an addressing mode, if any."""
    text = ", ".join(operands)
    pre = re.search(r"\[sp,\s*#(-?\d+)\]!", text)     # stp x29, x30, [sp, #-16]!
    if pre:
        return int(pre.group(1))
    post = re.search(r"\[sp\]\s*,\s*#(-?\d+)", text)  # ldp x29, x30, [sp], #16
    if post:
        return int(post.group(1))
    return None


def effect(instruction: Instruction) -> dict:
    """Compute an instruction's effect on tracked state.

    Returns a dict with keys:
      loads   -- list of registers restored by this instruction
      stores  -- list of registers saved (stored to memory)
      dirtied -- list of registers written with unknown values
      sp_delta -- int | None  (net change to sp, e.g. post-index ldp)
      sp_restore -- bool      (mov sp, xN -- treat as full restore)
      calls   -- bool         (bl/blr: x30 becomes the return address)
      ret     -- "x30" | ...  (register the ret returns through)
      br      -- register     (indirect tail branch register)
      branch  -- "cond" | "ret" | "none" (CFG successor info)
    """
    mnemonic = instruction.mnemonic
    operands = instruction.operands
    info: dict = {
        "loads": [], "stores": [], "dirtied": [], "sp_delta": None,
        "sp_restore": False, "calls": False, "ret": None, "br": None,
        "branch": "none",
    }

    if mnemonic in COND_BRANCH:
        info["branch"] = "cond"
        return info
    if mnemonic == "ret":
        reg = "x30"
        if operands:
            found = [r for r in _regs(operands[0]) if r.startswith("x")]
            reg = found[0] if found else "x30"
        info["ret"] = reg
        info["branch"] = "ret"
        return info
    if mnemonic == "br":
        found = _regs(operands[0]) if operands else []
        info["br"] = found[0] if found else "x30"
        info["branch"] = "ret"
        return info
    if mnemonic in {"bl", "blr"}:
        info["calls"] = True
        info["dirtied"].append("x30")
        if mnemonic == "blr":
            info["branch"] = "cond"  # continues after; target unknown
        return info
    if mnemonic == "mov" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        if dst.strip() == "sp":
            # `mov sp, x29` restores the frame pointer into SP.
            info["sp_restore"] = True
            return info
        src_regs = _regs(src)
        dst_regs = _regs(dst)
        if dst_regs:
            # mov Rd, Rm -- copy; value may be restored or unknown.
            info["dirtied"].append(dst_regs[0])
            info["copy_from"] = src_regs[0] if src_regs else None
        return info
    if mnemonic in {"movz", "movk", "movn", "adr", "adrp"}:
        regs = _regs(operands[0]) if operands else []
        if regs:
            info["dirtied"].append(regs[0])
        return info
    if mnemonic in LOAD_MNEMONICS:
        # Only the destination operands are restored. The base register in
        # "[x19, #8]" is an *input*: counting it as a load would wrongly mark
        # a dirty x19 as restored by any load that happens to address through
        # it, which is exactly the kind of false "safe" this checker must not
        # produce.
        n_dest = 2 if mnemonic in LOAD_PAIR else 1
        loaded: list[str] = []
        if operands and operands[0].startswith("{"):
            loaded = _regs(operands[0])
        else:
            for operand in operands[:n_dest]:
                loaded.extend(_regs(operand))
        # A load only *restores* a callee-saved register when it reads the
        # stack. The case that motivated this: `aes128_encrypt` did
        # `ld1 {v5.16b, ..., v8.16b}, [x1], #64`, loading round keys from the
        # caller's key schedule into the callee-saved v8-v11. Treating any
        # load as a restore made that clobber invisible and answered "safe"
        # to a question whose real answer was "this violates AAPCS64". The
        # function has since been fixed; the rule is what caught it.
        address = " ".join(operands[n_dest:]) if not (
            operands and operands[0].startswith("{")) else " ".join(operands[1:])
        if re.search(r"\b(sp|x29)\b", address):
            info["loads"] = loaded
        else:
            info["dirtied"] = loaded
        info["sp_delta"] = _sp_delta(operands)
        return info
    if mnemonic in STORE_MNEMONICS:
        n_src = 2 if mnemonic in STORE_PAIR else 1
        if operands and operands[0].startswith("{"):
            info["stores"] = _regs(operands[0])
        else:
            for operand in operands[:n_src]:
                info["stores"].extend(_regs(operand))
        info["sp_delta"] = _sp_delta(operands)
        return info
    if mnemonic in {"sub", "add"} and len(operands) >= 3:
        if operands[0] == "sp" and operands[1] == "sp":
            imm = re.match(r"#([+-]?\d+)", operands[2])
            if imm:
                value = int(imm.group(1))
                info["sp_delta"] = -value if mnemonic == "sub" else value
            else:
                info["sp_delta"] = None
            return info
    if mnemonic in NO_DEST:
        return info

    # Default: dest = first register operand (covers all ALU/SIMD ops).
    regs = _regs(operands[0]) if operands else []
    if regs:
        info["dirtied"].append(regs[0])
    return info


def normalise_reg(reg: str) -> str:
    """d8 -> v8, q8 -> v8; leave others alone."""
    return SIMD_ALIASES.get(reg, reg)


TRACKED_GPR = CALLEE_SAVED_GPR
TRACKED_SIMD = CALLEE_SAVED_SIMD


def tracked(reg: str) -> bool:
    reg = normalise_reg(reg)
    return reg in TRACKED_GPR or reg in TRACKED_SIMD


# ----------------------------------------------------------------------
# Control-flow graph
# ----------------------------------------------------------------------

def build_cfg(instructions: list[Instruction],
              labels: dict[str, int]) -> list[list[int]]:
    """Instruction-level successor lists.

    ``bl``/``blr`` fall through (the callee returns). ``b`` to an unresolved
    target -- an inter-file tail call -- has no successor inside this region.
    """
    n = len(instructions)
    succ: list[list[int]] = [[] for _ in range(n)]
    for i, insn in enumerate(instructions):
        mnemonic = insn.mnemonic
        if mnemonic in {"ret", "br", "eret"}:
            continue
        if mnemonic == "b":
            target = (resolve_target(insn.operands[0], labels, i)
                      if insn.operands else None)
            if target is not None and target < n:
                succ[i].append(target)
            continue
        if mnemonic in COND_BRANCH:
            if i + 1 < n:
                succ[i].append(i + 1)
            if insn.operands:
                target = resolve_target(insn.operands[-1], labels, i)
                if target is not None and target < n and target != i + 1:
                    succ[i].append(target)
            continue
        if i + 1 < n:
            succ[i].append(i + 1)
    return succ


def predecessors(succ: list[list[int]]) -> list[list[int]]:
    preds: list[list[int]] = [[] for _ in succ]
    for i, targets in enumerate(succ):
        for t in targets:
            preds[t].append(i)
    return preds


def back_edges(succ: list[list[int]]) -> list[tuple[int, int]]:
    """Edges that jump backwards -- the loops the old parser could not see."""
    return [(i, t) for i, targets in enumerate(succ) for t in targets if t <= i]


# ----------------------------------------------------------------------
# Dataflow state
# ----------------------------------------------------------------------

@dataclass
class State:
    dirty: set[str] = field(default_factory=set)     # callee-saved regs written
    sp_net: int = 0                                  # net sp change (-1=unknown)
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
        if normalise_reg(reg) == "x30":
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
        if dirty_source is not None:
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


def _states_differ(a: State, b: State) -> bool:
    return (a.dirty != b.dirty or a.sp_net != b.sp_net
            or a.saved_x30 != b.saved_x30 or a.called != b.called)


# ----------------------------------------------------------------------
# NZCV analysis
# ----------------------------------------------------------------------

@dataclass
class FlagAnalysis:
    """Where the condition flags are live, and which writes reach each read."""
    live_in: list[bool]
    live_out: list[bool]
    # flag-using instruction index -> set of flag-defining instruction indices
    reaching: dict[int, set[int]]
    # index of each ret, and whether flags are live there
    rets: list[int]
    carry_abi: bool

    def live_at_ret(self) -> bool:
        return self.carry_abi and bool(self.rets)

    def signature(self, instructions: list[Instruction]) -> dict[str, set[str]]:
        """use-text -> set of def-texts reaching it.

        Comparing this between the original and a candidate is what detects a
        flag-setting instruction moved into a live flag range.
        """
        out: dict[str, set[str]] = {}
        for use, defs in self.reaching.items():
            key = "ret" if use == -1 else _norm_text(instructions[use])
            texts = {_norm_text(instructions[d]) for d in defs}
            out.setdefault(key, set()).update(texts)
        return out


def analyse_flags(instructions: list[Instruction], succ: list[list[int]],
                  carry_abi: bool) -> FlagAnalysis:
    n = len(instructions)
    # Exits are `ret`, and also any branch that leaves the region: `write_all`
    # is nothing but `b transport_write`, and four carry-ABI functions are
    # pure tail-call trampolines like it. Treating only `ret` as an exit would
    # report their status flags as dead.
    rets = [i for i, insn in enumerate(instructions)
            if insn.mnemonic == "ret"
            or (insn.mnemonic in {"b", "br"} and not succ[i])]
    exit_set = set(rets)

    # --- backward liveness -------------------------------------------
    live_in = [False] * n
    live_out = [False] * n
    for _ in range(n + 2):
        changed = False
        for i in range(n - 1, -1, -1):
            out = any(live_in[s] for s in succ[i])
            if i in exit_set:
                # For a carry-ABI function the flags are a return value, so
                # they are live out of every ret.
                out = carry_abi
            new_in = uses_flags(instructions[i]) or (
                out and not defines_flags(instructions[i]))
            if out != live_out[i] or new_in != live_in[i]:
                live_out[i], live_in[i] = out, new_in
                changed = True
        if not changed:
            break

    # --- forward reaching definitions ---------------------------------
    preds = predecessors(succ)
    reach_in: list[set[int]] = [set() for _ in range(n)]
    reach_out: list[set[int]] = [set() for _ in range(n)]
    for _ in range(n + 2):
        changed = False
        for i in range(n):
            new_in: set[int] = set()
            for p in preds[i]:
                new_in |= reach_out[p]
            new_out = {i} if defines_flags(instructions[i]) else set(new_in)
            if new_in != reach_in[i] or new_out != reach_out[i]:
                reach_in[i], reach_out[i] = new_in, new_out
                changed = True
        if not changed:
            break

    reaching: dict[int, set[int]] = {}
    for i, insn in enumerate(instructions):
        if uses_flags(insn):
            reaching[i] = set(reach_in[i])
    if carry_abi:
        # A synthetic "use" standing for the caller reading the carry flag.
        at_ret: set[int] = set()
        for r in rets:
            at_ret |= reach_in[r]
        reaching[-1] = at_ret

    return FlagAnalysis(live_in=live_in, live_out=live_out, reaching=reaching,
                        rets=rets, carry_abi=carry_abi)


# ----------------------------------------------------------------------
# Checker
# ----------------------------------------------------------------------

_MACRO_CACHE: dict[bool | None, dict[str, Macro]] = {}


def _macros(linux: bool | None) -> dict[str, Macro]:
    if linux not in _MACRO_CACHE:
        _MACRO_CACHE[linux] = load_macros(linux=linux)
    return _MACRO_CACHE[linux]


def detect_carry_abi(source: str) -> bool:
    """Does this function document the carry-flag return convention?"""
    return bool(re.search(r"carry\s+(set|clear)", source, re.I))


def check_function(function_source: str, original: str | None = None, *,
                   linux: bool | None = None,
                   carry_abi: bool | None = None) -> list[ABIWarning]:
    """Run the static ABI checks over a function body.

    ``original`` is the function the candidate is meant to replace. Supplying
    it enables the differential NZCV check: the flags are a return value for
    the 36 carry-ABI functions here, and only a comparison against the
    original can tell that a candidate moved a flag-setting instruction into
    a live flag range. Without it the flag checks are informational only.
    """
    warnings: list[ABIWarning] = []
    macros = _macros(linux)
    expanded = expand_macros(function_source, macros)
    instructions, labels = parse_instructions(expanded)
    if not instructions:
        warnings.append(ABIWarning("error", "no instructions found in function"))
        return warnings

    succ = build_cfg(instructions, labels)
    preds = predecessors(succ)

    # --- forward dataflow to fixpoint -------------------------------
    # ``None`` means "not yet known to be reachable". Seeding every
    # instruction with a clean State() instead would join a real predecessor
    # state against a fictitious sp_net=0 at every loop header, and the
    # sp-disagreement sentinel is sticky, so every loop in the repo would
    # report "could not verify SP restoration". That only became visible once
    # the parser started resolving .L labels and loops appeared at all.
    entry: list[State | None] = [None] * len(instructions)
    entry[0] = State()
    for _ in range(len(instructions) + 2):
        changed = False
        for i in range(len(instructions)):
            if i == 0:
                continue  # the entry instruction always starts clean
            live_preds = [p for p in preds[i] if entry[p] is not None]
            if not live_preds:
                continue
            joined = join([_after(entry[p], instructions[p]) for p in live_preds])
            if entry[i] is None or _states_differ(joined, entry[i]):
                entry[i] = joined
                changed = True
        if not changed:
            break

    # --- check every ret --------------------------------------------
    for i, insn in enumerate(instructions):
        state = entry[i]
        if state is None:
            continue  # unreachable within this region
        info = effect(insn)
        if info["branch"] == "ret":
            _check_ret(state, info, insn, warnings)

    # --- function-wide x30-save check -------------------------------
    called = any(insn.mnemonic in {"bl", "blr"} for insn in instructions)
    x30_saved = any("x30" in effect(insn).get("stores", [])
                    for insn in instructions)
    if called and not x30_saved:
        warnings.append(ABIWarning(
            "warning",
            "function calls bl/blr but never saves x30 to the stack; "
            "x30 must be restored some other way before ret",
        ))

    # --- alignment check ---------------------------------------------
    for insn in instructions:
        if insn.mnemonic not in {"sub", "add"}:
            continue
        if len(insn.operands) < 3 or insn.operands[0] != "sp":
            continue
        imm = re.match(r"#([+-]?\d+)$", insn.operands[2].strip())
        if imm and int(imm.group(1)) % 16 != 0:
            warnings.append(ABIWarning(
                "error",
                f"SP adjusted by {imm.group(1)} (not a multiple of 16) -- "
                "breaks 16-byte stack alignment",
                insn.line,
            ))
    for insn in instructions:
        delta = _sp_delta(insn.operands)
        if delta is not None and delta % 16 != 0:
            warnings.append(ABIWarning(
                "error",
                f"SP adjusted by {delta} (not a multiple of 16) -- "
                "breaks 16-byte stack alignment",
                insn.line,
            ))

    # --- NZCV --------------------------------------------------------
    if carry_abi is None:
        carry_abi = detect_carry_abi(function_source) or (
            original is not None and detect_carry_abi(original))
    flags = analyse_flags(instructions, succ, carry_abi)
    warnings.extend(_check_flags(instructions, flags, original,
                                 linux=linux, carry_abi=carry_abi))
    return warnings


def _after(state: State, insn: Instruction) -> State:
    out = state.copy()
    apply_effect(out, effect(insn))
    return out


def _check_flags(instructions: list[Instruction], flags: FlagAnalysis,
                 original: str | None, *, linux: bool | None,
                 carry_abi: bool) -> list[ABIWarning]:
    warnings: list[ABIWarning] = []

    if carry_abi:
        # Every path to a `ret` must set the flags somewhere, or the status
        # returned is whatever the caller happened to leave in NZCV. A tail
        # call is exempt: `write_all` is `b transport_write`, and the flags it
        # returns are the ones its target sets.
        real_rets = [i for i in flags.rets
                     if instructions[i].mnemonic == "ret"]
        if -1 in flags.reaching and not flags.reaching[-1] and real_rets:
            warnings.append(ABIWarning(
                "warning",
                "documents a carry-flag return but no instruction on the path "
                "to ret writes NZCV; the returned status is the caller's flags",
                instructions[real_rets[0]].line,
            ))

    if original is None:
        return warnings

    original_expanded = expand_macros(original, _macros(linux))
    original_insns, original_labels = parse_instructions(original_expanded)
    if not original_insns:
        return warnings
    original_succ = build_cfg(original_insns, original_labels)
    original_flags = analyse_flags(original_insns, original_succ, carry_abi)

    before = original_flags.signature(original_insns)
    after = flags.signature(instructions)

    for use, defs in before.items():
        if use not in after:
            continue  # the reader itself is gone; other checks cover that
        if after[use] == defs:
            continue
        added = sorted(after[use] - defs)
        removed = sorted(defs - after[use])
        detail = []
        if added:
            detail.append("now also reached by " + "; ".join(added))
        if removed:
            detail.append("no longer reached by " + "; ".join(removed))
        where = "the ret (carry-flag return value)" if use == "ret" else f"'{use}'"
        warnings.append(ABIWarning(
            "error",
            f"NZCV dependency changed: the condition flags read by {where} "
            f"come from a different instruction than in the original "
            f"({', '.join(detail)}) -- a flag-clobbering instruction was "
            "moved or inserted into a live flag range",
        ))
    return warnings


def _check_ret(state_in: State, info: dict, insn: Instruction,
               warnings: list[ABIWarning]) -> None:
    state = state_in
    ret_reg = info.get("ret") or info.get("br") or "x30"

    # The register we return through must hold a valid address; x30 must
    # hold the caller's return address (or the function must be returning
    # via a clean callee-saved register chain).
    if ret_reg in state.dirty and ret_reg != "x30":
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
# Whole-region checking, in caller context
# ----------------------------------------------------------------------

_UNRESTORED_RE = re.compile(
    r"modifies callee-saved (\w+) but never restores it before ret")


def _saves_and_restores(body: str, reg: str, macros: dict[str, Macro]) -> bool:
    """Does this body both store ``reg`` to the stack and load it back?"""
    instructions, _ = parse_instructions(expand_macros(body, macros))
    saved = restored = False
    for insn in instructions:
        info = effect(insn)
        if reg in [normalise_reg(r) for r in info.get("stores", [])]:
            saved = True
        if reg in [normalise_reg(r) for r in info.get("loads", [])]:
            restored = True
    return saved and restored


def check_region(index, region, *, linux: bool | None = None) -> list[ABIWarning]:
    """Check one region, judged against the contract it actually has.

    A ``.global`` symbol is bound by AAPCS64 and is checked as such. A private
    region -- a ``.L...`` label reached only by ``bl`` from inside this tree --
    has whatever contract its callers agree to, so an unrestored callee-saved
    register is only a violation if some caller fails to preserve it. That is
    the difference between ``hex_to_val``, which deliberately returns a flag in
    x20 that ``decode_url`` saves around it, and ``h2_verify_preface``, which
    is exported and clobbers x21 with nobody preserving it.
    """
    warnings = check_function(index.analysis_body(region), linux=linux,
                              carry_abi=region.carry_abi())
    if region.is_global:
        return warnings

    callers = index.callers.get(region.name, [])
    out: list[ABIWarning] = []
    for warning in warnings:
        match = _UNRESTORED_RE.search(warning.message)
        if warning.severity != "error" or not match or not callers:
            out.append(warning)
            continue
        reg = normalise_reg(match.group(1))
        unprotected = [
            name for name, _file in callers
            if not _saves_and_restores(
                index.analysis_body(index.by_name[name]), reg, index.macros)
        ]
        if unprotected:
            warning.message += (
                f"; caller(s) {', '.join(sorted(unprotected))} do not preserve "
                f"{reg} either")
            out.append(warning)
        else:
            out.append(ABIWarning(
                "warning",
                f"private region writes callee-saved {reg} without restoring "
                f"it; all {len(callers)} caller(s) "
                f"({', '.join(sorted(n for n, _ in callers))}) do preserve it, "
                "so this is a non-AAPCS internal contract, not a violation",
                warning.line,
            ))
    return out


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def _find_region(source_path: Path, name: str, linux: bool | None):
    """Locate a region by name -- ``.global`` symbol or local ``bl`` target."""
    index = index_source(linux=linux)
    for region in index.all_by_name.get(name, []):
        if region.path == source_path.resolve():
            return index, region
    for region in index.all_by_name.get(name, []):
        return index, region
    return index, None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--function", required=True,
                        help="a .global symbol or a local bl target (.Lfoo)")
    parser.add_argument("--flags", action="store_true",
                        help="also print the NZCV liveness result")
    parser.add_argument("--linux", action="store_true",
                        help="expand the Linux macros (default: host platform)")
    args = parser.parse_args()

    linux = True if args.linux else None
    index, region = _find_region(args.source, args.function, linux)
    if region is None:
        raise SystemExit(f"function {args.function} not found in {args.source}")

    body = index.analysis_body(region)
    warnings = check_region(index, region, linux=linux)
    for warning in warnings:
        print(warning.render())

    if args.flags:
        instructions, labels = parse_instructions(
            expand_macros(body, index.macros))
        succ = build_cfg(instructions, labels)
        flags = analyse_flags(instructions, succ, region.carry_abi())
        print()
        print(f"NZCV: carry-flag return ABI  : "
              f"{'yes' if region.carry_abi() else 'no'}")
        print(f"NZCV: live at ret            : "
              f"{'yes' if flags.live_at_ret() else 'no'}")
        print(f"NZCV: writers / readers      : "
              f"{sum(1 for i in instructions if defines_flags(i))} / "
              f"{sum(1 for i in instructions if uses_flags(i))}")
        print(f"back edges (loops)           : {len(back_edges(succ))}")
        if flags.carry_abi:
            reaching = sorted(_norm_text(instructions[d])
                              for d in flags.reaching.get(-1, set()))
            print("NZCV at ret set by           : "
                  + (", ".join(reaching) or "nothing"))

    errors = [w for w in warnings if w.severity == "error"]
    print(f"\n{len(warnings)} warning(s), {len(errors)} error(s)")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
