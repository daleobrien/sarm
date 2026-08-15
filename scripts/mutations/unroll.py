"""Unroll the classic 16-byte ``ldp``/``stp`` copy loop by 2.

Detects the idiom used by ``src/util/memcpy.S``::

    cbz  <len>, <end>          # entry
    cmp  <len>, #16
    b.lo <tail>
<loop>:
    ldp  <ra>, <rb>, [<src>], #16
    stp  <ra>, <rb>, [<dst>], #16
    sub  <len>, <len>, #16
    cmp  <len>, #16
    b.hs <loop>
<tail>: ...byte loop...

and produces an equivalent function that processes 32 bytes per iteration
(keeping the original 16-byte loop as the remainder path so lengths 16-31
are not regressed to the byte loop)::

    cbz  <len>, <end>
    cmp  <len>, #16
    b.lo <tail>
    cmp  <len>, #32
    b.lo <oldloop>
<nloop>:
    ldp  <ra>, <rb>, [<src>], #16
    ldp  <rc>, <rd>, [<src>], #16
    stp  <ra>, <rb>, [<dst>], #16
    stp  <rc>, <rd>, [<dst>], #16
    sub  <len>, <len>, #32
    cmp  <len>, #32
    b.hs <nloop>
<oldloop>: (original 16-byte loop, verbatim)
<tail>:    (verbatim)

The two extra registers are chosen from caller-saved registers that the
function never touches, so the ABI is preserved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import fresh_numeric_labels, split_function, strip_insn

_LDP = re.compile(r"^ldp\s+(\w+),\s*(\w+),\s*\[(\w+)\],\s*#16$")
_STP = re.compile(r"^stp\s+(\w+),\s*(\w+),\s*\[(\w+)\],\s*#16$")
_SUB16 = re.compile(r"^sub\s+(\w+),\s*(\w+),\s*#16$")
_CMP16 = re.compile(r"^cmp\s+(\w+),\s*#16$")
_BHS = re.compile(r"^b\.hs\s+(\w+)$")
_CBZ = re.compile(r"^cbz\s+(\w+),\s*([\w.]+)$")
_BLO = re.compile(r"^b\.lo\s+([\w.]+)$")

_REG = re.compile(r"\b(x\d+|w\d+)\b")


@dataclass
class _Loop:
    entry_body_idx: int      # body index of the cbz entry line
    loop_body_idx: int       # body index of the first ldp line
    tail_body_idx: int       # body index of the first line after the loop
    ra: str
    rb: str
    src: str
    dst: str
    rlen: str
    back: str                  # original back-branch target, e.g. "2b"
    loop_lines: list[str]    # original 5 loop lines, verbatim


def detect_loop(function_text: str) -> tuple[list[str], str, list[str], _Loop] | None:
    """Detect the idiom; return (preamble, label, body, loop) or None."""
    parts = split_function(function_text)
    if parts is None:
        return None
    preamble, label, body = parts

    items: list[tuple[int, str, str]] = []
    for idx, line in enumerate(body):
        stripped = strip_insn(line)
        if (
            not stripped
            or stripped.startswith(".")
            or stripped.startswith("#")
            or re.match(r"^[A-Za-z0-9_.$]+:", stripped)
        ):
            continue
        items.append((idx, line, stripped))

    for i in range(len(items) - 4):
        seq = [items[i + k][2] for k in range(5)]
        m_ldp, m_stp = _LDP.match(seq[0]), _STP.match(seq[1])
        m_sub, m_cmp, m_bhs = (
            _SUB16.match(seq[2]),
            _CMP16.match(seq[3]),
            _BHS.match(seq[4]),
        )
        if not (m_ldp and m_stp and m_sub and m_cmp and m_bhs):
            continue
        if m_ldp.group(1) != m_stp.group(1) or m_ldp.group(2) != m_stp.group(2):
            continue
        if m_sub.group(1) != m_sub.group(2) or m_sub.group(1) != m_cmp.group(1):
            continue
        if m_ldp.group(3) == m_sub.group(1) or m_stp.group(3) == m_sub.group(1):
            continue  # length register must not alias a base pointer
        if i < 3:
            continue
        entry = [items[i - 3][2], items[i - 2][2], items[i - 1][2]]
        m_cbz = _CBZ.match(entry[0])
        m_cmp16 = _CMP16.match(entry[1])
        m_blo = _BLO.match(entry[2])
        if not (m_cbz and m_cmp16 and m_blo):
            continue
        if m_cbz.group(1) != m_sub.group(1) or m_cmp16.group(1) != m_sub.group(1):
            continue

        loop = _Loop(
            entry_body_idx=items[i - 3][0],
            loop_body_idx=items[i][0],
            tail_body_idx=items[i + 4][0] + 1,
            ra=m_ldp.group(1),
            rb=m_ldp.group(2),
            src=m_ldp.group(3),
            dst=m_stp.group(3),
            rlen=m_sub.group(1),
            back=m_bhs.group(1),
            loop_lines=[items[i + k][1] for k in range(5)],
        )
        return preamble, label, body, loop
    return None


def _fresh_regs(body_lines: list[str]) -> list[str] | None:
    """Two caller-saved x-registers unused anywhere in the body."""
    used: set[str] = set()
    for line in body_lines:
        for match in _REG.finditer(strip_insn(line)):
            used.add(match.group(1))
    for ra, rb in (
        ("x5", "x6"), ("x7", "x8"), ("x9", "x10"), ("x11", "x12"),
        ("x13", "x14"), ("x15", "x16"), ("x17", "x18"),
    ):
        if ra not in used and rb not in used:
            return [ra, rb]
    return None


def _expand(function_text: str, main_loop: str) -> str | None:
    """Shared generator: build the unrolled function around ``main_loop``."""
    detected = detect_loop(function_text)
    if detected is None:
        return None
    preamble, label, body, loop = detected

    labels = fresh_numeric_labels(body, 2)
    nloop, oldloop = labels

    indent = "    "
    new_body: list[str] = []
    new_body.extend(body[: loop.entry_body_idx])                 # before entry
    new_body.extend(body[loop.entry_body_idx : loop.loop_body_idx])  # entry checks
    new_body.append(f"{indent}cmp {loop.rlen}, #32")
    new_body.append(f"{indent}b.lo {oldloop}f")
    new_body.append(f"{nloop}:")
    new_body.append(main_loop)
    new_body.append(f"{indent}sub {loop.rlen}, {loop.rlen}, #32")
    new_body.append(f"{indent}cmp {loop.rlen}, #32")
    new_body.append(f"{indent}b.hs {nloop}b")
    new_body.append(f"{oldloop}:")
    # Retarget the old loop's back-branch: it used to point at its own
    # label, which is now the entry check, so it must jump to `oldloop`.
    back_re = re.compile(rf"^(\s*)b\.hs\s+{re.escape(loop.back)}\s*$")
    for line in loop.loop_lines:
        if back_re.match(line):
            new_body.append(f"    b.hs {oldloop}b")
        else:
            new_body.append(line)
    new_body.extend(body[loop.tail_body_idx :])                  # tail + end

    return "\n".join(preamble + [label] + new_body) + "\n"


def unroll_2x(function_text: str) -> str | None:
    detected = detect_loop(function_text)
    if detected is None:
        return None
    body = detected[2]

    fresh = _fresh_regs(body)
    if fresh is None:
        return None
    rc, rd = fresh
    loop = detected[3]

    main_loop = "\n".join(
        [
            f"    ldp {loop.ra}, {loop.rb}, [{loop.src}], #16",
            f"    ldp {rc}, {rd}, [{loop.src}], #16",
            f"    stp {loop.ra}, {loop.rb}, [{loop.dst}], #16",
            f"    stp {rc}, {rd}, [{loop.dst}], #16",
        ]
    )
    return _expand(function_text, main_loop)
