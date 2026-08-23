#!/usr/bin/env python3
"""Guard the width argument that docs/SECURITY.md §3.5 rests on.

§3.5 gives ~120 length sites one of three verdicts. Most are **width**:
the sum cannot wrap because every operand is an 8/16/24-bit wire field
held in a wider register, and the result is compared against an end
pointer before use. Sound — but, as the section says, the soundness
lives outside the instruction, and nothing in the build re-derives it
when a field changes size. That was item 3 of §3.5's carried-forward
list, and §14 A3 asked for a guard rather than a proof.

So this is a guard. It verifies no sum. It asserts the *premises* the
human verdicts were reached under, so that changing one fails something:

  1. **Nowhere in the wire-parsing tree is a multi-octet field composed
     in a 64-bit register.** The `orr xD, xS, xA, lsl #N` idiom does not
     occur today. Every field is assembled in a `w` register, which is
     what makes "16-bit field, 32-bit arithmetic" an argument at all.
     This half is a sweep, not a list — a new file cannot escape it.

  2. Per declared file: the widest composition shift, and the exact
     number of composition instructions. A 2-octet field grown to 3
     changes both. A field added or removed changes the count. Neither
     is necessarily a defect — it is a site with no verdict.

A failure here does not mean "you introduced a bug". It means "a premise
§3.5 depends on changed, so the section needs re-reading before this
lands", which is the most a guard of this kind can honestly claim.

What it does not catch: a field that keeps its width and its idiom but
acquires a new consumer that composes it with something unbounded. That
is the empirical half, and it belongs to the fuzzers.

Usage:
    python3 scripts/width_guard.py            # check, exit 1 on drift
    python3 scripts/width_guard.py --report   # print what it sees
"""

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# Directories that parse attacker-controlled bytes (docs/SECURITY.md
# §3.1-§3.4). Swept whole for premise 1.
WIRE_DIRS = [
    "src/tls/record", "src/tls/handshake", "src/tls/server",
    "src/h2", "src/hpack", "src/parse", "src/http1", "src/file",
]

# ── The declared premises (2) ────────────────────────────────────────
# `shift` is the widest big-endian composition the file performs, in
# bits: 8 for a 2-octet field, 16 for 3 octets, 24 for 4. `ops` is the
# exact number of composition instructions — one per octet past the
# first, so a 2-octet field is 1 and a 4-octet field is 3. Both were
# read off the tree at the commit that closed §14 A3; neither is a
# target, both are a record of what the verdicts were written against.
DECLARED = {
    "src/tls/record/parse.S": (8, 2,
        "legacy_record_version and the fragment length, both 2-octet (§3.1)"),
    "src/tls/handshake/client_hello.S": (8, 14,
        "every ClientHello list length is 2-octet — §3.5 calls this the "
        "width argument in its purest and most fragile form"),
    "src/h2/h2_parse_frame_header.S": (24, 5,
        "the 3-octet frame length and the 4-octet stream id (§3.3)"),
    "src/h2/h2_handle_settings.S": (24, 4,
        "the 2-octet setting id and its 4-octet value (§3.3)"),
    "src/h2/h2_handle_window_update.S": (24, 3,
        "the 4-octet window increment (§3.3)"),
    "src/h2/h2_handle_goaway.S": (24, 3,
        "the 4-octet last-stream-id (§3.3)"),
}

# `orr wD, wS, wA, lsl #N` — the composition step
ORR_SHIFT = re.compile(
    r"^\s*orr\s+([wx])(\d+)\s*,\s*[wx]\d+\s*,\s*[wx]\d+\s*,\s*lsl\s*#(\d+)", re.I)
# `lsl wD, wS, #N` — the leading shift of a 3- or 4-octet composition
LSL_IMM = re.compile(r"^\s*lsl\s+([wx])(\d+)\s*,\s*[wx]\d+\s*,\s*#(\d+)", re.I)


def scan(path):
    """(max_shift, composition_ops, [(line, text)] composed in x)."""
    max_shift = ops = 0
    wide = []
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        code = line.split("//", 1)[0]
        for pattern, is_orr in ((ORR_SHIFT, True), (LSL_IMM, False)):
            m = pattern.match(code)
            if not m:
                continue
            reg, shift = m.group(1).lower(), int(m.group(3))
            ops += 1
            max_shift = max(max_shift, shift)
            # A bare `lsl x` is overwhelmingly array indexing, not field
            # assembly; only the `orr` form is unambiguous enough to
            # sweep the whole tree for.
            if reg == "x" and is_orr:
                wide.append((lineno, code.strip()))
    return max_shift, ops, wide


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true",
                    help="print what each file looks like and exit 0")
    args = ap.parse_args()

    failures = []

    # ── premise 1: swept, not listed ──
    swept = 0
    for d in WIRE_DIRS:
        root = REPO / d
        if not root.is_dir():
            failures.append(f"{d}: declared a wire-parsing directory but "
                            f"missing — the sweep has nothing to sweep")
            continue
        for path in sorted(root.rglob("*.S")):
            swept += 1
            _, _, wide = scan(path)
            for lineno, text in wide:
                rel = path.relative_to(REPO)
                failures.append(
                    f"{rel}:{lineno}: a field is composed in a 64-bit "
                    f"register — `{text}`. §3.5's width verdicts assume this "
                    f"arithmetic is 32-bit")

    # ── premise 2: the declared per-file shape ──
    rows = []
    for rel, (want_shift, want_ops, note) in sorted(DECLARED.items()):
        path = REPO / rel
        if not path.exists():
            failures.append(f"{rel}: declared here but missing — §3.5's "
                            f"verdict for it has nothing to guard")
            continue
        shift, ops, _ = scan(path)
        rows.append((rel, shift, ops, want_shift, want_ops))
        if shift > want_shift:
            failures.append(
                f"{rel}: widest composition is {shift} bits, declared "
                f"{want_shift} — a field grew. ({note})")
        if ops != want_ops:
            failures.append(
                f"{rel}: {ops} composition instruction(s), declared "
                f"{want_ops} — a field was added, removed or changed width, "
                f"so there is a site with no verdict. ({note})")

    if args.report or failures:
        print(f"{'file':<46} {'shift':>6} {'ops':>5}   declared")
        for rel, shift, ops, w_shift, w_ops in rows:
            drift = "" if (shift <= w_shift and ops == w_ops) else "  <-- drift"
            print(f"{rel:<46} {shift:>6} {ops:>5}   {w_shift}/{w_ops}{drift}")
        print()

    if failures:
        for f in failures:
            print(f"width_guard: {f}", file=sys.stderr)
        print(f"\n{len(failures)} premise(s) of docs/SECURITY.md §3.5 no "
              f"longer hold. That is a prompt to re-read §3.5, not "
              f"necessarily a defect.", file=sys.stderr)
        return 1

    print(f"width_guard: {swept} wire-parsing file(s) swept, "
          f"{len(rows)} declared — every §3.5 width premise holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
