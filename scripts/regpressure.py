#!/usr/bin/env python3
"""Register-pressure analyzer and report for sarm's AArch64 assembly.

This is the *measurement* half of the register work: it reads the assembly
and reports where register pressure, callee-saved traffic and register
moves actually cost something. It never modifies a source file.

The metric that matters here is not "how many registers does this function
use". Every function in this repo fits comfortably in the 31 GPRs, so
nothing spills. What costs real instructions is the fixed prologue/epilogue
needed to preserve callee-saved registers, so the central question is:

    is each callee-saved register this function preserves actually
    *justified* by a value that must stay live across a call?

A value live across ``bl``/``blr``/``svc`` must sit in a callee-saved
register -- the callee (or the kernel) may destroy x0-x18. A callee-saved
register holding a value that is never live across such a point is pure
save/restore overhead and is the transformation opportunity.

Two things must be modelled correctly or every number below is wrong:

* **Macros.** ``src/defs.S`` defines ``adr_l``/``ldr_l``/``str_l``/``cb``
  and the syscall helpers; 82 files use them ~500 times. ``ldr_l`` writes a
  hidden scratch register (x9 by default) and ``SCWISVC`` expands to
  ``svc``. Without expansion, liveness misses those writes and syscall
  sites look like straight-line code.
* **Call clobbers.** ``bl``/``blr``/``svc`` destroy the caller-saved GPRs.
  Without that, values look safe in x0-x18 across a call and the analyzer
  would report callee-saved registers as removable when they are load
  bearing.

Usage::

    python3 scripts/regpressure.py                    # ranked report
    python3 scripts/regpressure.py --function ghash   # one function
    python3 scripts/regpressure.py --json             # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from abi import (  # noqa: E402
    COND_BRANCH,
    LOAD_MNEMONICS,
    NO_DEST,
    STORE_MNEMONICS,
    Instruction,
    strip_comment,
)

ROOT = HERE.parent

# AAPCS64: x0-x17 are caller-saved (x18 is the platform register, reserved
# on Darwin). A value live across a call must be in x19-x28.
CALLER_SAVED = {f"x{i}" for i in range(0, 18)}
CALLEE_SAVED = {f"x{i}" for i in range(19, 29)}

# Files that are data tables or shared headers, not functions.
SKIP_FILES = {
    "config.S", "defs.S", "embedded.S", "cert_data.S", "h2_huffman_table.S",
}

GLOBAL_RE = re.compile(r"(?m)^[ \t]*\.globa?l[ \t]+([A-Za-z0-9_.]+)")
REG_RE = re.compile(r"\b(x\d+|w\d+|v\d+|d\d+|q\d+|s\d+|b\d+|h\d+|sp|xzr|wzr)\b")


# ----------------------------------------------------------------------
# Macro expansion
# ----------------------------------------------------------------------

@dataclass
class Macro:
    name: str
    params: list[tuple[str, str | None]]  # (name, default)
    body: list[str]


def parse_macros(defs_text: str, *, linux: bool = False) -> dict[str, Macro]:
    """Parse ``.macro`` definitions from defs.S for one platform.

    defs.S defines each syscall/relocation helper twice inside an
    ``#ifdef __linux__`` / ``#else``; we keep only the active branch, since
    the two differ in ways that matter (Linux puts the syscall number in
    x8, Darwin in x16).
    """
    macros: dict[str, Macro] = {}
    active = True
    branch: list[bool] = []
    current: Macro | None = None

    for raw in defs_text.splitlines():
        line = raw.strip()

        if line.startswith("#ifdef __linux__"):
            branch.append(linux)
            active = all(branch)
            continue
        if line.startswith("#else") and branch:
            branch[-1] = not branch[-1]
            active = all(branch)
            continue
        if line.startswith("#endif") and branch:
            branch.pop()
            active = all(branch)
            continue

        if current is not None:
            if line.startswith(".endm"):
                if active:
                    macros[current.name] = current
                current = None
            else:
                current.body.append(raw)
            continue

        if line.startswith(".macro"):
            decl = line[len(".macro"):].strip()
            # ".macro adr_l, reg, sym" and ".macro ldr_l reg, sym, scratch=x9"
            head, _, rest = decl.partition(" ")
            name = head.rstrip(",")
            params: list[tuple[str, str | None]] = []
            for part in rest.split(","):
                part = part.strip()
                if not part:
                    continue
                pname, eq, default = part.partition("=")
                params.append((pname.strip(), default.strip() if eq else None))
            current = Macro(name=name, params=params, body=[])

    return macros


def expand_macros(text: str, macros: dict[str, Macro], depth: int = 4) -> str:
    """Recursively expand macro invocations in a function body."""
    for _ in range(depth):
        out: list[str] = []
        changed = False
        for raw in text.splitlines():
            stripped = strip_comment(raw)
            if not stripped:
                out.append(raw)
                continue
            head, _, argtext = stripped.partition(" ")
            macro = macros.get(head.rstrip(","))
            if macro is None:
                out.append(raw)
                continue

            args = [a.strip() for a in argtext.split(",") if a.strip()]
            bindings: dict[str, str] = {}
            for i, (pname, default) in enumerate(macro.params):
                if i < len(args):
                    bindings[pname] = args[i]
                elif default is not None:
                    bindings[pname] = default
                else:
                    bindings[pname] = ""

            for body_line in macro.body:
                expanded = body_line
                # Longest parameter names first so \src does not eat \scratch.
                for pname in sorted(bindings, key=len, reverse=True):
                    expanded = expanded.replace("\\" + pname, bindings[pname])
                out.append(expanded)
            changed = True

        text = "\n".join(out)
        if not changed:
            break
    return text


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
#
# This does not reuse ``abi.parse_instructions``: that function drops every
# line beginning with "." before it looks for a label, so the 393 ``.L...``
# local labels in src/ are never recorded. Branch targets to them resolve
# to nothing, back edges disappear and no loop is ever detected -- which
# makes liveness (and abi.py's own "restored on every path" reasoning)
# unsound for most functions here. Labels are matched before directives.

LABEL_RE = re.compile(r"^(\.?[A-Za-z0-9_.$]+):\s*(.*)$")


def parse_instructions(source: str) -> tuple[list[Instruction], dict[str, int]]:
    """Parse a function body into instructions and a label -> index map."""
    instructions: list[Instruction] = []
    labels: dict[str, int] = {}

    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = strip_comment(raw)
        if not line:
            continue
        # Labels first -- ".Lfoo:" is a label, ".align 2" is a directive.
        match = LABEL_RE.match(line)
        if match and not re.match(r"^\.(align|text|data|globa?l|equ|byte|word|"
                                  r"quad|section|macro|endm|asciz|ascii|space|"
                                  r"fill|zero|rept|endr|set|type|size)\b", line):
            labels[match.group(1)] = len(instructions)
            line = match.group(2).strip()
            if not line:
                continue
        if line.startswith("#") or line.startswith("."):
            continue
        parts = line.split(None, 1)
        mnemonic = parts[0]
        operands = []
        if len(parts) > 1:
            operands = [op.strip() for op in parts[1].split(",")]
        instructions.append(Instruction(lineno, raw, mnemonic, operands))

    return instructions, labels


def resolve_target(target: str, labels: dict[str, int], current: int) -> int | None:
    """Resolve a branch target, including numeric local labels (2b / 3f)."""
    target = target.strip()
    if target[:-1].isdigit() and target[-1:] in ("b", "f"):
        name, direction = target[:-1], target[-1]
        best = None
        for key, value in labels.items():
            if key != name:
                continue
            if direction == "b" and value <= current:
                best = value if best is None else max(best, value)
            elif direction == "f" and value > current:
                best = value if best is None else min(best, value)
        return best
    return labels.get(target)


# ----------------------------------------------------------------------
# Instruction semantics: def / use
# ----------------------------------------------------------------------

def norm(reg: str) -> str:
    """Normalise wN -> xN and dN/qN/sN -> vN."""
    if reg in ("xzr", "wzr", "sp"):
        return reg
    match = re.match(r"^[xw](\d+)$", reg)
    if match:
        return "x" + match.group(1)
    match = re.match(r"^[vdqsbh](\d+)$", reg)
    if match:
        return "v" + match.group(1)
    return reg


def regs_in(text: str) -> set[str]:
    return {norm(m.group(1)) for m in REG_RE.finditer(text)}


def def_use(insn) -> tuple[set[str], set[str], bool]:
    """Return (defs, uses, is_call_site) for one instruction.

    ``abi.py`` deliberately lumps all operand registers together -- that is
    fine for "was this callee-saved register written", but liveness needs
    the two separated, so this is computed here rather than reused.
    """
    mnemonic = insn.mnemonic
    operands = insn.operands
    defs: set[str] = set()
    uses: set[str] = set()
    call = False

    if mnemonic in ("bl", "blr", "svc"):
        # A call or syscall destroys the caller-saved GPRs. Modelling the
        # clobber as a *definition* is what makes a value live across the
        # call show up as requiring a callee-saved register.
        call = True
        defs |= CALLER_SAVED | {"x30"}
        if mnemonic == "blr" and operands:
            uses |= regs_in(operands[0])
        return defs, uses, call

    if mnemonic == "ret":
        uses |= {"x30", "x0"} if not operands else regs_in(operands[0]) | {"x0"}
        return defs, uses, call

    if mnemonic == "br":
        if operands:
            uses |= regs_in(operands[0])
        return defs, uses, call

    if mnemonic in COND_BRANCH:
        if mnemonic in ("cbz", "cbnz", "tbz", "tbnz") and operands:
            uses |= regs_in(operands[0])
        return defs, uses, call

    if mnemonic in LOAD_MNEMONICS:
        n_dest = 2 if mnemonic in ("ldp", "ldnp", "ldxp", "ldaxp") else 1
        if operands and operands[0].startswith("{"):
            defs |= regs_in(operands[0])
            for operand in operands[1:]:
                uses |= regs_in(operand)
            return defs, uses, call
        for operand in operands[:n_dest]:
            defs |= regs_in(operand)
        for operand in operands[n_dest:]:
            uses |= regs_in(operand)
        return defs, uses, call

    if mnemonic in STORE_MNEMONICS:
        n_src = 2 if mnemonic in ("stp", "stnp") else 1
        for operand in operands[:n_src]:
            uses |= regs_in(operand)
        for operand in operands[n_src:]:
            uses |= regs_in(operand)
        return defs, uses, call

    if mnemonic in NO_DEST:
        for operand in operands:
            uses |= regs_in(operand)
        return defs, uses, call

    if mnemonic in ("movz", "movn", "adr", "adrp"):
        if operands:
            defs |= regs_in(operands[0])
        return defs, uses, call

    if mnemonic == "movk":
        if operands:
            defs |= regs_in(operands[0])
            uses |= regs_in(operands[0])
        return defs, uses, call

    # Default ALU/SIMD shape: first operand is the destination.
    if operands:
        defs |= regs_in(operands[0])
        for operand in operands[1:]:
            uses |= regs_in(operand)

    for discard in ("xzr", "wzr", "sp"):
        defs.discard(discard)
        uses.discard(discard)
    return defs, uses, call


# ----------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------

@dataclass
class FunctionInfo:
    name: str
    file: str
    insns: int = 0
    peak: int = 0
    peak_loop: int = 0
    callee_used: list[str] = field(default_factory=list)
    callee_justified: list[str] = field(default_factory=list)
    save_restore: int = 0
    frame: int = 0
    loads: int = 0
    stores: int = 0
    movs: int = 0
    calls: int = 0
    uses_flags_abi: bool = False

    @property
    def unjustified(self) -> list[str]:
        """Callee-saved registers never holding a value live across a call."""
        return sorted(set(self.callee_used) - set(self.callee_justified))

    def opportunity(self) -> tuple[str, str]:
        """(rank, reason) -- why this function is or is not interesting."""
        if self.unjustified and self.save_restore:
            return ("HIGH",
                    f"{len(self.unjustified)} callee-saved reg(s) "
                    f"({', '.join(self.unjustified)}) never hold a value "
                    "across a call")
        if self.peak > 20:
            return ("HIGH", f"peak pressure {self.peak} approaches the 31-GPR "
                            "limit; scheduling may be constrained")
        if self.calls == 0 and self.callee_used:
            return ("MEDIUM", "leaf function preserving callee-saved registers")
        if self.peak_loop >= 12:
            return ("MEDIUM", f"loop carries {self.peak_loop} live registers")
        if self.save_restore >= 10:
            return ("LOW", f"{self.save_restore} save/restore instructions, "
                           "all justified by live-across-call values")
        return ("NONE", "register usage already tight")


def analyse(name: str, path: Path, body: str,
            macros: dict[str, Macro]) -> FunctionInfo | None:
    expanded = expand_macros(body, macros)
    insns, labels = parse_instructions(expanded)
    if not insns:
        return None

    n = len(insns)
    du = [def_use(i) for i in insns]

    # --- instruction-level CFG ---------------------------------------
    succ: list[list[int]] = [[] for _ in range(n)]
    for i, insn in enumerate(insns):
        mnemonic = insn.mnemonic
        if mnemonic in ("ret", "br"):
            continue
        if mnemonic == "b":
            target = (resolve_target(insn.operands[0], labels, i)
                      if insn.operands else None)
            if target is not None:
                succ[i].append(target)
            continue
        if mnemonic in COND_BRANCH:
            if i + 1 < n:
                succ[i].append(i + 1)
            if insn.operands:
                target = resolve_target(insn.operands[-1], labels, i)
                if target is not None:
                    succ[i].append(target)
            continue
        if i + 1 < n:
            succ[i].append(i + 1)

    # --- backward liveness to fixpoint --------------------------------
    live_in: list[set[str]] = [set() for _ in range(n)]
    live_out: list[set[str]] = [set() for _ in range(n)]
    for _ in range(500):
        changed = False
        for i in range(n - 1, -1, -1):
            out: set[str] = set()
            for s in succ[i]:
                out |= live_in[s]
            defs, uses, _ = du[i]
            new_in = (out - defs) | uses
            if out != live_out[i] or new_in != live_in[i]:
                live_out[i], live_in[i] = out, new_in
                changed = True
        if not changed:
            break

    # --- loops (back edges) -------------------------------------------
    loop_insns: set[int] = set()
    for i in range(n):
        for s in succ[i]:
            if s <= i:
                loop_insns |= set(range(s, i + 1))

    def gprs(regs: set[str]) -> set[str]:
        return {r for r in regs if re.fullmatch(r"x\d+", r or "")}

    info = FunctionInfo(name=name, file=str(path.relative_to(ROOT)), insns=n)
    info.peak = max((len(gprs(live_out[i])) for i in range(n)), default=0)
    info.peak_loop = max((len(gprs(live_out[i])) for i in loop_insns), default=0)

    used: set[str] = set()
    for defs, uses, _ in du:
        used |= defs | uses
    # A call's modelled clobber must not count as "this function uses x5".
    explicit: set[str] = set()
    for i, insn in enumerate(insns):
        if du[i][2]:
            continue
        explicit |= du[i][0] | du[i][1]
    info.callee_used = sorted(gprs(explicit) & CALLEE_SAVED,
                              key=lambda r: int(r[1:]))

    # Callee-saved registers actually justified: live across a call site.
    justified: set[str] = set()
    for i in range(n):
        if du[i][2]:
            justified |= gprs(live_out[i]) & CALLEE_SAVED
    info.callee_justified = sorted(justified, key=lambda r: int(r[1:]))
    info.calls = sum(1 for d in du if d[2])

    # --- stack frame and preservation traffic -------------------------
    for insn in insns:
        text = strip_comment(insn.text)
        match = re.search(r"sub\s+sp,\s*sp,\s*#(\d+)", text)
        if match:
            info.frame = max(info.frame, int(match.group(1)))
        match = re.search(r"\[sp,\s*#-(\d+)\]!", text)
        if match:
            info.frame = max(info.frame, int(match.group(1)))
        if (insn.mnemonic in ("stp", "ldp", "str", "ldr")
                and "sp" in text
                and re.search(r"\b(x(19|2[0-8])|x29|x30|d([89]|1[0-5]))\b", text)):
            info.save_restore += 1

    info.loads = sum(1 for i in insns if i.mnemonic in LOAD_MNEMONICS)
    info.stores = sum(1 for i in insns if i.mnemonic in STORE_MNEMONICS)
    info.movs = sum(
        1 for i in insns
        if i.mnemonic == "mov" and len(i.operands) == 2
        and re.fullmatch(r"[xw]\d+", i.operands[1].strip() or "-")
    )
    info.uses_flags_abi = bool(
        re.search(r"carry (set|clear)", body, re.I)
    )
    return info


def split_functions(text: str) -> list[tuple[str, str]]:
    """Split a source file into (name, text) from each .global to the next."""
    marks = [(m.start(), m.group(1)) for m in GLOBAL_RE.finditer(text)]
    out = []
    for idx, (pos, name) in enumerate(marks):
        end = marks[idx + 1][0] if idx + 1 < len(marks) else len(text)
        out.append((name, text[pos:end]))
    return out


def collect(root: Path, linux: bool = False) -> list[FunctionInfo]:
    macros = parse_macros((root / "src" / "defs.S").read_text(), linux=linux)
    rows: list[FunctionInfo] = []
    for path in sorted((root / "src").rglob("*.S")):
        if path.name in SKIP_FILES:
            continue
        text = path.read_text(errors="replace")
        for name, body in split_functions(text):
            info = analyse(name, path, body, macros)
            if info is not None:
                rows.append(info)
    return rows


# ----------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------

RANK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NONE": 3}


def report(rows: list[FunctionInfo]) -> None:
    rows = sorted(
        rows,
        key=lambda r: (RANK_ORDER[r.opportunity()[0]], -r.save_restore, -r.peak),
    )
    header = (f"{'Rank':<7}{'Function':<34}{'Peak':>5}{'Loop':>5}{'Save':>5}"
              f"{'Just':>5}{'S/R':>5}{'Stack':>7}  Opportunity")
    print(header)
    print("-" * 120)
    for r in rows:
        rank, reason = r.opportunity()
        if rank == "NONE":
            continue
        print(f"{rank:<7}{r.name:<34}{r.peak:>5}{r.peak_loop:>5}"
              f"{len(r.callee_used):>5}{len(r.callee_justified):>5}"
              f"{r.save_restore:>5}{r.frame:>6}B  {reason}")

    print()
    print("=" * 120)
    print("AGGREGATE")
    print("=" * 120)
    total_sr = sum(r.save_restore for r in rows)
    unjust = [r for r in rows if r.unjustified]
    print(f"functions analysed                        : {len(rows)}")
    print(f"peak GPR pressure (max / median)          : "
          f"{max(r.peak for r in rows)} / "
          f"{sorted(r.peak for r in rows)[len(rows) // 2]}")
    print(f"functions with peak >= 24 (spill risk)    : "
          f"{sum(1 for r in rows if r.peak >= 24)}")
    print(f"total save/restore instructions           : {total_sr}")
    print(f"functions preserving callee-saved GPRs    : "
          f"{sum(1 for r in rows if r.callee_used)}")
    print(f"  ...with a register never live across a call: {len(unjust)}")
    print(f"functions using the carry-flag return ABI : "
          f"{sum(1 for r in rows if r.uses_flags_abi)}")
    print(f"register-to-register movs                 : "
          f"{sum(r.movs for r in rows)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--function", help="report a single function in detail")
    parser.add_argument("--json", action="store_true", help="machine-readable")
    parser.add_argument("--linux", action="store_true",
                        help="expand the Linux syscall macros (default: Darwin)")
    args = parser.parse_args()

    rows = collect(args.root, linux=args.linux)

    if args.function:
        rows = [r for r in rows if r.name == args.function]
        if not rows:
            raise SystemExit(f"function {args.function!r} not found")

    if args.json:
        print(json.dumps([{
            "function": r.name, "file": r.file, "instructions": r.insns,
            "peak_pressure": r.peak, "peak_pressure_loop": r.peak_loop,
            "callee_saved_used": r.callee_used,
            "callee_saved_justified": r.callee_justified,
            "callee_saved_unjustified": r.unjustified,
            "save_restore_insns": r.save_restore, "stack_bytes": r.frame,
            "loads": r.loads, "stores": r.stores, "movs": r.movs,
            "calls": r.calls, "carry_flag_abi": r.uses_flags_abi,
            "opportunity": r.opportunity()[0],
            "reason": r.opportunity()[1],
        } for r in rows], indent=2))
        return

    if args.function:
        r = rows[0]
        rank, reason = r.opportunity()
        print(f"{r.name}  ({r.file})")
        print(f"  instructions            : {r.insns}")
        print(f"  peak live GPRs          : {r.peak}  (in loops: {r.peak_loop})")
        print(f"  callee-saved used       : {', '.join(r.callee_used) or 'none'}")
        print(f"  ...justified across call: {', '.join(r.callee_justified) or 'none'}")
        print(f"  ...unjustified          : {', '.join(r.unjustified) or 'none'}")
        print(f"  save/restore insns      : {r.save_restore}")
        print(f"  stack frame             : {r.frame} bytes")
        print(f"  loads / stores          : {r.loads} / {r.stores}")
        print(f"  reg-to-reg movs         : {r.movs}")
        print(f"  call sites              : {r.calls}")
        print(f"  carry-flag return ABI   : {'yes' if r.uses_flags_abi else 'no'}")
        print(f"  opportunity             : {rank} -- {reason}")
        return

    report(rows)


if __name__ == "__main__":
    main()
