#!/usr/bin/env python3
"""Check the analyzer against 207 hand-written ``// Clobbered Registers:`` headers.

Every function in ``src/`` carries a doc header naming the registers it
destroys. That is 207 independent, human-written statements about register
behaviour -- by far the strongest correctness signal available for
``regpressure.py``, and it costs nothing to run. Where the analyzer and a
header disagree, exactly one of them is wrong; this script finds the
disagreements so each one can be triaged.

What is compared
----------------

*Documented*: the register set named in the header, minus anything the header
itself marks as ``(saved/restored)`` or ``preserved`` -- those are restored
before return, so the caller never sees them clobbered.

*Computed*: every register the region writes, plus everything its callees
write (a clobber header is a caller-facing contract: ``p256_fe_mul`` writes
barely a dozen registers itself, but calling ``p256_bn_mul`` costs its caller
x0-x17), minus the registers the region spills and reloads.

One asymmetry is deliberate. ``regpressure`` models ``svc`` as destroying the
whole caller-saved set, because that is what the kernel is *permitted* to do
and liveness must assume it. The headers describe what the syscall path
actually writes. Folding the permitted-clobber model into this comparison
would make every syscall function disagree for a reason that is about
conservatism, not about either side being wrong, so the comparison uses
architectural writes only. The conservative model still governs the
``justified`` analysis, which is where it matters.

Verdicts
--------

``AGREE``       identical sets.
``UNDERSTATES`` the header omits a register the analyzer says is clobbered.
                This is the direction that can hurt: a caller trusting the
                header would leave a live value there.
``OVERSTATES``  the header names a register the analyzer says is untouched.
                Harmless to a caller, but usually a stale comment.
``BOTH``        each side has registers the other lacks.
``UNPARSED``    the header is prose ("everything hmac_sha256 clobbers") that
                could not be resolved to a register set.

Usage::

    python3 scripts/validate_clobbers.py                # summary + all diffs
    python3 scripts/validate_clobbers.py --verdict UNDERSTATES
    python3 scripts/validate_clobbers.py --json
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

from asmparse import ROOT, doc_field  # noqa: E402
from regpressure import collect, fmt_regs, norm  # noqa: E402

# "x0-x17", "x19", "w11", "v16-v21", "d8"
RANGE_RE = re.compile(r"\b([xwvdqsbh])(\d+)\s*(?:[-–]|\.\.)\s*[xwvdqsbh]?(\d+)\b")
SINGLE_RE = re.compile(r"\b([xwvdqsbh])(\d+)\b")
PAREN_RE = re.compile(r"\(([^)]*)\)")
REFERENCE_RE = re.compile(r"everything\s+[`']?([A-Za-z_][A-Za-z0-9_]*)[`']?\s+clobbers")

PRESERVE_WORDS = ("saved", "restored", "preserved", "preserve")


def parse_regs(text: str) -> set[str]:
    """Register tokens and ranges in a chunk of header prose."""
    out: set[str] = set()
    consumed = []
    for match in RANGE_RE.finditer(text):
        prefix, lo, hi = match.group(1), int(match.group(2)), int(match.group(3))
        if hi >= lo:
            out |= {norm(f"{prefix}{i}") for i in range(lo, hi + 1)}
        consumed.append((match.start(), match.end()))
    for match in SINGLE_RE.finditer(text):
        if any(start <= match.start() < end for start, end in consumed):
            continue
        out.add(norm(match.group(0)))
    return {r for r in out if re.fullmatch(r"[xv]\d+", r)}


@dataclass
class Documented:
    clobbers: set[str] = field(default_factory=set)
    preserved: set[str] = field(default_factory=set)
    flags: bool = False
    references: set[str] = field(default_factory=set)
    outputs: set[str] = field(default_factory=set)
    parsed: bool = True
    raw: str = ""


def parse_header(raw: str) -> Documented:
    """Turn one ``// Clobbered Registers:`` field into register sets.

    Three annotation styles appear in the tree and all three are handled:

        x0-x17 (plus x19, x20 saved/restored on the stack)
        x0-x12, x19-x24 (saved/restored), x30 (saved/restored), v0-v7
        x9-x12, x30, v0-v7 (x19-x28 and v16-v21 are preserved)
    """
    doc = Documented(raw=raw)
    text = raw.strip()
    if not text or text.lower() in {"(none)", "none"}:
        doc.clobbers = set()
        return doc

    doc.flags = "nzcv" in text.lower()
    for match in REFERENCE_RE.finditer(text):
        doc.references.add(match.group(1))

    # Parentheticals that talk about preservation.
    remainder = text
    for match in PAREN_RE.finditer(text):
        inner = match.group(1)
        if not any(word in inner.lower() for word in PRESERVE_WORDS):
            continue
        inner_regs = parse_regs(inner)
        if inner_regs:
            # "(x19-x28 and v16-v21 are preserved)" / "(plus x19, x20 saved...)"
            doc.preserved |= inner_regs
        else:
            # "(saved/restored)" annotating whatever precedes it.
            before = text[:match.start()]
            item = re.split(r",(?![^(]*\))", before)[-1]
            doc.preserved |= parse_regs(item)
        remainder = remainder.replace(match.group(0), " ")

    doc.clobbers = parse_regs(text) - doc.preserved
    if not doc.clobbers and not doc.preserved and doc.references:
        doc.parsed = False
    if not doc.clobbers and not doc.preserved and not doc.references:
        # Prose with no register token at all, e.g. "(handlers clobber their own)".
        doc.parsed = bool(re.search(r"\bnone\b", text, re.I))
    return doc


def resolve_references(docs: dict[str, Documented]) -> None:
    """Expand "plus everything `sha256` clobbers" using that symbol's header.

    Resolved against the *documented* set of the named symbol, never the
    computed one -- borrowing the analyzer's own answer would make the
    comparison agree with itself.
    """
    for _ in range(len(docs) + 2):
        changed = False
        for doc in docs.values():
            for name in list(doc.references):
                other = docs.get(name)
                if other is None or not other.parsed:
                    continue
                new = doc.clobbers | (other.clobbers - doc.preserved)
                if new != doc.clobbers:
                    doc.clobbers = new
                    changed = True
                if not doc.parsed:
                    doc.parsed = True
                    changed = True
        if not changed:
            break
    for doc in docs.values():
        if doc.references and not doc.clobbers:
            doc.parsed = False


@dataclass
class Result:
    name: str
    file: str
    verdict: str
    documented: set[str]
    computed: set[str]
    missing: set[str]   # computed but not documented
    spurious: set[str]  # documented but not computed
    basis: str          # "direct" | "transitive" -- which the header follows
    flags_documented: bool
    flags_computed: bool
    raw: str


def validate(linux: bool | None = None) -> list[Result]:
    rows, index = collect(linux=linux)
    by_name = {r.name: r for r in rows}

    docs: dict[str, Documented] = {}
    for region in index.regions:
        raw = region.documented_clobbers()
        if raw is None:
            continue
        doc = parse_header(raw)
        # The headers do not list a function's return registers as clobbered
        # -- x0 is named under "Output/Returns:" instead. Treating a
        # documented output as an undocumented clobber would be scoring the
        # tree's convention rather than its accuracy.
        returns = doc_field(region.doc, "Output/Returns") or ""
        doc.outputs = parse_regs(returns)
        docs.setdefault(region.name, doc)
    resolve_references(docs)

    results: list[Result] = []
    for region in index.regions:
        doc = docs.get(region.name)
        info = by_name.get(region.name)
        if doc is None or info is None:
            continue
        def clean(regs: set[str]) -> set[str]:
            return {r for r in regs if re.fullmatch(r"[xv]\d+", r)}

        # The headers do not follow one convention. Some list only what the
        # function itself writes; others list the full cost to a caller. Score
        # against both and report the closer one, so that a header is not
        # marked wrong merely for choosing the other convention.
        options = {
            "direct": clean(info.clobbers_direct - info.preserved),
            "transitive": clean(info.clobbers),
        }
        if not doc.parsed:
            verdict, basis = "UNPARSED", "direct"
            computed = options["transitive"]
            missing = spurious = set()
        else:
            def score(computed: set[str]) -> tuple[int, int]:
                return (len(computed - doc.clobbers - doc.outputs),
                        len(doc.clobbers - computed))
            basis = min(options, key=lambda k: sum(score(options[k])))
            computed = options[basis]
            missing = computed - doc.clobbers - doc.outputs
            spurious = doc.clobbers - computed
            if not missing and not spurious:
                verdict = "AGREE"
            elif missing and spurious:
                verdict = "BOTH"
            elif missing:
                verdict = "UNDERSTATES"
            else:
                verdict = "OVERSTATES"
        results.append(Result(
            name=region.name, file=region.rel, verdict=verdict,
            documented=doc.clobbers, computed=computed,
            missing=missing, spurious=spurious, basis=basis,
            flags_documented=doc.flags, flags_computed=info.flag_writers > 0,
            raw=doc.raw,
        ))
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verdict", help="show only one verdict class")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--linux", action="store_true")
    args = parser.parse_args()

    results = validate(linux=True if args.linux else None)

    if args.json:
        print(json.dumps([{
            "function": r.name, "file": r.file, "verdict": r.verdict,
            "documented": fmt_regs(r.documented),
            "computed": fmt_regs(r.computed), "basis": r.basis,
            "missing_from_header": fmt_regs(r.missing),
            "not_actually_clobbered": fmt_regs(r.spurious),
            "flags_documented": r.flags_documented,
            "flags_computed": r.flags_computed,
            "header": r.raw,
        } for r in results], indent=2))
        return

    order = ["UNDERSTATES", "BOTH", "OVERSTATES", "UNPARSED", "AGREE"]
    shown = [r for r in results
             if args.verdict is None or r.verdict == args.verdict.upper()]
    for verdict in order:
        group = [r for r in shown if r.verdict == verdict]
        if not group or verdict == "AGREE":
            continue
        print(f"===== {verdict} ({len(group)}) " + "=" * 60)
        for r in sorted(group, key=lambda r: r.file):
            print(f"{r.name}  ({r.file})")
            print(f"    header  : {r.raw}")
            print(f"    computed: {fmt_regs(r.computed) or '(none)'}  [{r.basis}]")
            if r.missing:
                print(f"    MISSING from header : {fmt_regs(r.missing)}")
            if r.spurious:
                print(f"    not actually written: {fmt_regs(r.spurious)}")
        print()

    print("=" * 78)
    print(f"{'headers checked':<34}: {len(results)}")
    for verdict in order:
        count = sum(1 for r in results if r.verdict == verdict)
        print(f"{'  ' + verdict:<34}: {count}")
    print(f"{'  header basis: direct':<34}: "
          f"{sum(1 for r in results if r.basis == 'direct')}")
    print(f"{'  header basis: transitive':<34}: "
          f"{sum(1 for r in results if r.basis == 'transitive')}")
    # Only one NZCV direction is a defect. Roughly 30 headers use the "NZCV"
    # annotation at all, so a header that omits it while the function writes
    # flags is following the majority convention, not making a false claim.
    # A header that *claims* NZCV for a function with no flag writer is wrong.
    claimed = [r for r in results if r.flags_documented and not r.flags_computed]
    silent = [r for r in results if r.flags_computed and not r.flags_documented]
    print(f"{'NZCV claimed but never written':<34}: {len(claimed)}"
          + (f"  ({', '.join(r.name for r in claimed)})" if claimed else ""))
    print(f"{'NZCV written but not annotated':<34}: {len(silent)}"
          " (convention gap, not a defect)")


if __name__ == "__main__":
    main()
