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

Three things must be modelled correctly or every number below is wrong:

* **Local labels.** All 393 ``.L...`` labels in ``src/`` are branch targets.
  Miss them and back edges vanish, no loop is ever detected, and liveness
  is computed over straight-line code that does not exist. This is handled
  in ``asmparse``, which ``abi.py`` shares.
* **Macros.** ``src/defs.S`` defines 13 macros used ~500 times across 82
  files, and subsystems define more. ``ldr_l`` writes a hidden scratch
  register (x9 by default) and ``SCWISVC`` expands to ``svc``. Without
  expansion, liveness misses those writes and syscall sites look like
  straight-line code.
* **Call clobbers.** ``bl``/``blr``/``svc`` destroy the caller-saved GPRs.
  Without that, values look safe in x0-x18 across a call and the analyzer
  would report callee-saved registers as removable when they are load
  bearing.

**The unit of analysis is a region, not a ``.global`` symbol.** Any label
reached by ``bl`` is analysable in its own right. This matters: AES-GCM
never calls the exported ``ghash`` symbol -- ``encrypt.S`` and ``decrypt.S``
both ``bl .Lgcm_ghash_run``, a file-local label in ``gcm/data.S``. Ranking
by call sites keeps a dead ``.global`` from being mistaken for the hot path.

Usage::

    python3 scripts/regpressure.py                          # ranked report
    python3 scripts/regpressure.py --function .Lgcm_ghash_run
    python3 scripts/regpressure.py --callers .Lgcm_ghash_run
    python3 scripts/regpressure.py --json                   # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from abi import (  # noqa: E402
    COND_BRANCH,
    LOAD_MNEMONICS,
    LOAD_PAIR,
    NO_DEST,
    STORE_MNEMONICS,
    STORE_PAIR,
    analyse_flags,
    back_edges,
    build_cfg,
    defines_flags,
    uses_flags,
)
from asmparse import (  # noqa: E402
    ROOT,
    Instruction,
    Region,
    SourceIndex,
    index_source,
    parse_instructions,
    expand_macros,
    strip_comment,
)

# AAPCS64: x0-x17 are caller-saved (x18 is the platform register, reserved
# on Darwin). A value live across a call must be in x19-x28.
CALLER_SAVED = {f"x{i}" for i in range(0, 18)}
CALLEE_SAVED = {f"x{i}" for i in range(19, 29)}
# SIMD: v0-v7 and v16-v31 are caller-saved; v8-v15 are callee-saved, and only
# their low 64 bits at that.
CALLER_SAVED_SIMD = ({f"v{i}" for i in range(0, 8)}
                     | {f"v{i}" for i in range(16, 32)})

REG_RE = re.compile(r"\b(x\d+|w\d+|v\d+|d\d+|q\d+|s\d+|b\d+|h\d+|sp|xzr|wzr)\b")


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


_WRITEBACK_RE = re.compile(r"\[\s*(\w+)\s*(?:,[^\]]*)?\]\s*!")
_BARE_BRACKET_RE = re.compile(r"^\[\s*(\w+)\s*\]$")


def _writeback_regs(operands: list[str]) -> set[str]:
    """Base registers updated by pre-/post-indexed addressing.

    ``ld1 {v0.16b}, [x27], #16`` writes x27 as well as v0; missing that makes
    the pointer look loop-invariant. Operands arrive already comma-split
    (``split_operands`` splits outside ``[]``/``{}``), so the post-index
    form shows up as a bare ``[x27]`` operand followed by a separate ``#16``
    operand -- there is no trailing comma left on the string for a
    single-operand regex to match. A bracket-only operand that is not the
    last one is exactly that form; a plain ``[x27]`` with nothing after it
    is just non-writeback addressing.
    """
    out: set[str] = set()
    for operand in operands:
        for match in _WRITEBACK_RE.finditer(operand):
            out |= regs_in(match.group(1))
    for operand in operands[:-1]:
        match = _BARE_BRACKET_RE.match(operand.strip())
        if match:
            out |= regs_in(match.group(1))
    return out


def def_use(insn: Instruction) -> tuple[set[str], set[str], bool]:
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

    def done() -> tuple[set[str], set[str], bool]:
        for discard in ("xzr", "wzr", "sp"):
            defs.discard(discard)
            uses.discard(discard)
        return defs, uses, call

    if mnemonic in ("bl", "blr", "svc"):
        # A call or syscall destroys the caller-saved GPRs (and the
        # caller-saved SIMD registers). Modelling the clobber as a
        # *definition* is what makes a value live across the call show up as
        # requiring a callee-saved register.
        call = True
        defs |= CALLER_SAVED | CALLER_SAVED_SIMD | {"x30"}
        if mnemonic == "blr" and operands:
            uses |= regs_in(operands[0])
        return done()

    if mnemonic == "ret":
        uses |= {"x30", "x0"} if not operands else regs_in(operands[0]) | {"x0"}
        return done()

    if mnemonic == "br":
        if operands:
            uses |= regs_in(operands[0])
        return done()

    if mnemonic in COND_BRANCH:
        if mnemonic in ("cbz", "cbnz", "tbz", "tbnz") and operands:
            uses |= regs_in(operands[0])
        return done()

    if mnemonic in LOAD_MNEMONICS:
        n_dest = 2 if mnemonic in LOAD_PAIR else 1
        if operands and operands[0].startswith("{"):
            defs |= regs_in(operands[0])
            for operand in operands[1:]:
                uses |= regs_in(operand)
        else:
            for operand in operands[:n_dest]:
                defs |= regs_in(operand)
            for operand in operands[n_dest:]:
                uses |= regs_in(operand)
        defs |= _writeback_regs(operands)
        return done()

    if mnemonic in STORE_MNEMONICS:
        for operand in operands:
            uses |= regs_in(operand)
        defs |= _writeback_regs(operands)
        return done()

    if mnemonic in NO_DEST:
        for operand in operands:
            uses |= regs_in(operand)
        return done()

    if mnemonic in ("movz", "movn", "adr", "adrp"):
        if operands:
            defs |= regs_in(operands[0])
        return done()

    if mnemonic == "movk":
        if operands:
            defs |= regs_in(operands[0])
            uses |= regs_in(operands[0])
        return done()

    # Default ALU/SIMD shape: first operand is the destination.
    if operands:
        defs |= regs_in(operands[0])
        for operand in operands[1:]:
            uses |= regs_in(operand)
    return done()


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
    loops: int = 0
    callee_used: list[str] = field(default_factory=list)
    callee_justified: list[str] = field(default_factory=list)
    save_restore: int = 0
    frame: int = 0
    loads: int = 0
    stores: int = 0
    movs: int = 0
    calls: int = 0
    uses_flags_abi: bool = False
    flags_live_at_ret: bool = False
    flag_writers: int = 0
    flag_readers: int = 0
    # Region identity -- a .global symbol nothing calls is not the hot path.
    is_global: bool = True
    is_local_label: bool = False
    enclosing: str | None = None
    call_sites: int = 0
    caller_names: list[str] = field(default_factory=list)
    address_taken: bool = False
    # Registers this region leaves clobbered for its caller.
    clobbers_direct: set[str] = field(default_factory=set)
    clobbers: set[str] = field(default_factory=set)
    preserved: set[str] = field(default_factory=set)
    callees: list[str] = field(default_factory=list)

    @property
    def unjustified(self) -> list[str]:
        """Callee-saved registers this region pays to preserve but need not.

        Restricted to registers the region actually spills and reloads. A
        private region like ``.Lgcm_ghash_run`` *reads* x27 and x28 -- they
        are its input contract, set up by its callers -- without saving them;
        there is no prologue to recover there, and reporting one would point
        a transformation at code that does not exist.
        """
        candidates = set(self.callee_used) & self.preserved
        return sorted(candidates - set(self.callee_justified),
                      key=lambda r: int(r[1:]))

    def opportunity(self) -> tuple[str, str]:
        """(rank, reason) -- why this function is or is not interesting."""
        if self.is_global and self.call_sites == 0 and self.is_reachable_dead():
            return ("NONE", "no call site anywhere in src/ -- not on any hot "
                            "path this server executes")
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

    def is_reachable_dead(self) -> bool:
        """Exported, but nothing in this tree calls it.

        Not proof it is dead -- ``_main`` and the exported entry points are
        called by the loader or by tests -- but it is the signal that stops a
        ``.global`` from shadowing the local label that does the real work.
        """
        return self.name not in ENTRY_POINTS and not self.address_taken


# Symbols reached from outside src/: the process entry point and the C test
# harness. Everything else with zero in-tree call sites is not on a hot path.
ENTRY_POINTS = {"_start", "_main", "main"}


def analyse(region: Region, index: SourceIndex) -> FunctionInfo | None:
    body = index.analysis_body(region)
    expanded = expand_macros(body, index.macros)
    insns, labels = parse_instructions(expanded)
    if not insns:
        return None

    n = len(insns)
    du = [def_use(i) for i in insns]
    succ = build_cfg(insns, labels)

    # --- backward liveness to fixpoint --------------------------------
    live_in: list[set[str]] = [set() for _ in range(n)]
    live_out: list[set[str]] = [set() for _ in range(n)]
    for _ in range(n + 2):
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
    edges = back_edges(succ)
    loop_insns: set[int] = set()
    for source, target in edges:
        loop_insns |= set(range(target, source + 1))

    def gprs(regs: set[str]) -> set[str]:
        return {r for r in regs if re.fullmatch(r"x\d+", r or "")}

    info = FunctionInfo(name=region.name, file=region.rel, insns=n)
    info.is_global = region.is_global
    info.is_local_label = region.is_local_label
    info.enclosing = region.enclosing
    info.call_sites = index.call_sites(region.name)
    info.caller_names = sorted(name for name, _f in
                               index.callers.get(region.name, []))
    info.address_taken = index.referenced(region.name)
    info.callees = sorted(index.calls.get(region.name, set()))
    info.loops = len(edges)
    info.peak = max((len(gprs(live_out[i])) for i in range(n)), default=0)
    info.peak_loop = max((len(gprs(live_out[i])) for i in loop_insns), default=0)

    # A call's modelled clobber must not count as "this function uses x5".
    explicit: set[str] = set()
    written: set[str] = set()
    for i in range(n):
        if du[i][2]:
            continue
        explicit |= du[i][0] | du[i][1]
        written |= du[i][0]
    info.callee_used = sorted(gprs(explicit) & CALLEE_SAVED,
                              key=lambda r: int(r[1:]))
    # svc is modelled as a call for CALLER_SAVED-clobber purposes (the
    # kernel is permitted to destroy those), but unlike bl/blr it does not
    # write the link register -- a bare syscall never touches x30.
    if any(insn.mnemonic in ("bl", "blr") for insn in insns):
        written |= {"x30"}
    info.clobbers_direct = written

    # Callee-saved registers actually justified: live across a call site.
    justified: set[str] = set()
    for i in range(n):
        if du[i][2]:
            justified |= gprs(live_out[i]) & CALLEE_SAVED
    info.callee_justified = sorted(justified, key=lambda r: int(r[1:]))
    info.calls = sum(1 for d in du if d[2])

    # --- NZCV ---------------------------------------------------------
    info.uses_flags_abi = region.carry_abi()
    flags = analyse_flags(insns, succ, info.uses_flags_abi)
    info.flags_live_at_ret = flags.live_at_ret()
    info.flag_writers = sum(1 for i in insns if defines_flags(i))
    info.flag_readers = sum(1 for i in insns if uses_flags(i))

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

    info.preserved = _preserved_registers(insns)
    info.loads = sum(1 for i in insns if i.mnemonic in LOAD_MNEMONICS)
    info.stores = sum(1 for i in insns if i.mnemonic in STORE_MNEMONICS)
    info.movs = sum(
        1 for i in insns
        if i.mnemonic == "mov" and len(i.operands) == 2
        and re.fullmatch(r"[xw]\d+", i.operands[1].strip() or "-")
    )
    return info


def _preserved_registers(insns: list[Instruction]) -> set[str]:
    """Registers this region both spills to the stack and reloads.

    Used to subtract the prologue/epilogue from the clobber set: a register
    that is saved and restored is not clobbered as far as the caller can tell.
    """
    saved: set[str] = set()
    restored: set[str] = set()
    for insn in insns:
        text = strip_comment(insn.text)
        if "sp" not in text:
            continue
        if insn.mnemonic in STORE_MNEMONICS:
            n_src = 2 if insn.mnemonic in STORE_PAIR else 1
            for operand in insn.operands[:n_src]:
                saved |= regs_in(operand)
        elif insn.mnemonic in LOAD_MNEMONICS:
            n_dest = 2 if insn.mnemonic in LOAD_PAIR else 1
            for operand in insn.operands[:n_dest]:
                restored |= regs_in(operand)
    return saved & restored


def resolve_clobbers(rows: dict[str, FunctionInfo], index: SourceIndex) -> None:
    """Propagate clobber sets along call edges to a fixpoint.

    A ``// Clobbered Registers:`` header is a caller-facing contract, so what
    it must describe is everything the call destroys -- including what the
    callees destroy. ``p256_fe_mul`` writes barely a dozen registers itself,
    but calling ``p256_bn_mul`` and ``p256_reduce`` costs the caller x0-x17.
    An unresolvable callee (an extern, or an indirect ``blr``) is treated as
    clobbering the whole caller-saved set, which is the safe direction.
    """
    for info in rows.values():
        info.clobbers = set(info.clobbers_direct)
    for _ in range(len(rows) + 2):
        changed = False
        for name, info in rows.items():
            new = set(info.clobbers_direct)
            edges = (index.calls.get(name, set())
                     | index.tail_calls.get(name, set()))
            for callee in edges:
                target = rows.get(callee)
                if target is None:
                    new |= CALLER_SAVED | CALLER_SAVED_SIMD | {"x30"}
                else:
                    new |= target.clobbers - target.preserved
            new -= info.preserved
            if new != info.clobbers:
                info.clobbers = new
                changed = True
        if not changed:
            break


def collect(root: Path | None = None,
            linux: bool | None = None) -> tuple[list[FunctionInfo], SourceIndex]:
    index = index_source(root, linux=linux)
    rows: dict[str, FunctionInfo] = {}
    ordered: list[FunctionInfo] = []
    for region in index.regions:
        info = analyse(region, index)
        if info is None:
            continue
        ordered.append(info)
        rows.setdefault(region.name, info)
    resolve_clobbers(rows, index)
    return ordered, index


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
              f"{'Just':>5}{'S/R':>5}{'Call':>5}{'Stack':>7}  Opportunity")
    print(header)
    print("-" * 128)
    for r in rows:
        rank, reason = r.opportunity()
        if rank == "NONE":
            continue
        print(f"{rank:<7}{r.name:<34}{r.peak:>5}{r.peak_loop:>5}"
              f"{len(r.callee_used):>5}{len(r.callee_justified):>5}"
              f"{r.save_restore:>5}{r.call_sites:>5}{r.frame:>6}B  {reason}")

    print()
    print("=" * 128)
    print("AGGREGATE")
    print("=" * 128)
    total_sr = sum(r.save_restore for r in rows)
    unjust = [r for r in rows if r.unjustified]
    local = [r for r in rows if not r.is_global]
    print(f"regions analysed                          : {len(rows)}")
    print(f"  ...reached only via a local .L label    : {len(local)}")
    print(f"peak GPR pressure (max / median)          : "
          f"{max(r.peak for r in rows)} / "
          f"{sorted(r.peak for r in rows)[len(rows) // 2]}")
    print(f"functions with peak >= 24 (spill risk)    : "
          f"{sum(1 for r in rows if r.peak >= 24)}")
    print(f"regions containing a loop                 : "
          f"{sum(1 for r in rows if r.loops)}")
    print(f"total save/restore instructions           : {total_sr}")
    print(f"functions preserving callee-saved GPRs    : "
          f"{sum(1 for r in rows if r.callee_used)}")
    print(f"  ...with a register never live across a call: {len(unjust)}")
    print(f"regions using the carry-flag return ABI   : "
          f"{sum(1 for r in rows if r.uses_flags_abi)}")
    print(f"  ...with NZCV live at ret                : "
          f"{sum(1 for r in rows if r.flags_live_at_ret)}")
    print(f"exported symbols with no in-tree caller   : "
          f"{sum(1 for r in rows if r.is_global and r.call_sites == 0)}")
    print(f"  ...and whose address is never taken     : "
          f"{sum(1 for r in rows if r.is_global and r.call_sites == 0 and r.is_reachable_dead())}")
    print(f"register-to-register movs                 : "
          f"{sum(r.movs for r in rows)}")


def detail(r: FunctionInfo, index: SourceIndex) -> None:
    rank, reason = r.opportunity()
    kind = ("exported symbol" if r.is_global
            else f"private region (local label{', nested in ' + r.enclosing if r.enclosing else ''})")
    print(f"{r.name}  ({r.file})")
    print(f"  kind                    : {kind}")
    print(f"  call sites in src/      : {r.call_sites}"
          + (f"  ({', '.join(r.caller_names)})" if r.caller_names else ""))
    print(f"  instructions            : {r.insns}")
    print(f"  loops (back edges)      : {r.loops}")
    print(f"  peak live GPRs          : {r.peak}  (in loops: {r.peak_loop})")
    print(f"  callee-saved used       : {', '.join(r.callee_used) or 'none'}")
    print(f"  ...justified across call: {', '.join(r.callee_justified) or 'none'}")
    print(f"  ...unjustified          : {', '.join(r.unjustified) or 'none'}")
    print(f"  save/restore insns      : {r.save_restore}")
    print(f"  stack frame             : {r.frame} bytes")
    print(f"  loads / stores          : {r.loads} / {r.stores}")
    print(f"  reg-to-reg movs         : {r.movs}")
    print(f"  call sites out          : {r.calls}"
          + (f"  ({', '.join(r.callees)})" if r.callees else ""))
    print(f"  carry-flag return ABI   : {'yes' if r.uses_flags_abi else 'no'}")
    print(f"  NZCV live at ret        : {'yes' if r.flags_live_at_ret else 'no'}")
    print(f"  NZCV writers / readers  : {r.flag_writers} / {r.flag_readers}")
    print(f"  clobbers (transitive)   : {fmt_regs(r.clobbers)}")
    print(f"  preserved (saved+restored): {fmt_regs(r.preserved) or 'none'}")
    print(f"  opportunity             : {rank} -- {reason}")


def fmt_regs(regs: set[str]) -> str:
    """Collapse a register set into ranges: {x0..x5, x9} -> 'x0-x5, x9'."""
    out: list[str] = []
    for prefix in ("x", "v"):
        nums = sorted(int(r[1:]) for r in regs
                      if re.fullmatch(prefix + r"\d+", r))
        start = prev = None
        for num in nums + [None]:
            if start is None:
                start = prev = num
                continue
            if num is not None and num == prev + 1:
                prev = num
                continue
            out.append(f"{prefix}{start}" if start == prev
                       else f"{prefix}{start}-{prefix}{prev}")
            start = prev = num
    return ", ".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--function", help="report a single region in detail")
    parser.add_argument("--callers",
                        help="report a region together with its real callers")
    parser.add_argument("--json", action="store_true", help="machine-readable")
    parser.add_argument("--linux", action="store_true",
                        help="expand the Linux syscall macros (default: host)")
    args = parser.parse_args()

    rows, index = collect(args.root, linux=True if args.linux else None)

    if args.callers:
        target = next((r for r in rows if r.name == args.callers), None)
        if target is None:
            raise SystemExit(f"region {args.callers!r} not found")
        detail(target, index)
        print()
        print(f"--- real caller context ({len(target.caller_names)} caller(s)) ---")
        for name in target.caller_names:
            caller = next((r for r in rows if r.name == name), None)
            if caller is None:
                continue
            print()
            detail(caller, index)
        return

    if args.function:
        rows = [r for r in rows if r.name == args.function]
        if not rows:
            raise SystemExit(f"function {args.function!r} not found")

    if args.json:
        print(json.dumps([{
            "function": r.name, "file": r.file, "instructions": r.insns,
            "global": r.is_global, "local_label": r.is_local_label,
            "enclosing": r.enclosing,
            "call_sites": r.call_sites, "callers": r.caller_names,
            "loops": r.loops,
            "peak_pressure": r.peak, "peak_pressure_loop": r.peak_loop,
            "callee_saved_used": r.callee_used,
            "callee_saved_justified": r.callee_justified,
            "callee_saved_unjustified": r.unjustified,
            "save_restore_insns": r.save_restore, "stack_bytes": r.frame,
            "loads": r.loads, "stores": r.stores, "movs": r.movs,
            "calls": r.calls, "carry_flag_abi": r.uses_flags_abi,
            "flags_live_at_ret": r.flags_live_at_ret,
            "clobbers": fmt_regs(r.clobbers),
            "preserved": fmt_regs(r.preserved),
            "opportunity": r.opportunity()[0],
            "reason": r.opportunity()[1],
        } for r in rows], indent=2))
        return

    if args.function:
        detail(rows[0], index)
        return

    report(rows)


if __name__ == "__main__":
    main()
