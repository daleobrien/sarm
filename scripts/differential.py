#!/usr/bin/env python3
"""Differential testing driver (OPTIMISATION.MD, "Differential testing").

Runs a reference implementation and the assembly candidate over the same
randomly generated inputs and asserts identical outputs::

             same input
                 |
       ┌─────────┴─────────┐
       ▼                   ▼
   reference             optimized
   implementation        ARMv8 asm
       │                   │
       └─────────┬─────────┘
                 ▼
              compare

The concrete programs speak the protocol in
``scripts/differential/driver.h`` (one case per line on stdin, one result
per line on stdout). The bundled drivers cover ``memcpy``:

    python3 scripts/differential.py --cases 2000

Case mix: boundary lengths (0..65, 127..257, 1024, 4096...), random
lengths, every src/dst alignment offset 0-15, random payloads, and
guard-page cases that place the source/destination flush against a
PROT_NONE page so any read/write overrun segfaults.

For a different function, write drivers for it and pass --ref/--cand.
"""

from __future__ import annotations

import argparse
import random
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKDIR = HERE.parent  # project root

BOUNDARY_LENS = [
    0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33,
    63, 64, 65, 127, 128, 129, 255, 256, 257,
    1023, 1024, 1025, 4095, 4096,
]
MAX_GUARD_LEN = 4080  # must fit before the guard page on 4K pages

DEFAULT_REF = (
    "make -s -C scripts/differential _build/memcpy_ref "
    "&& ./scripts/differential/_build/memcpy_ref"
)
DEFAULT_CAND = (
    "make -s -C scripts/differential _build/memcpy_asm "
    "&& ./scripts/differential/_build/memcpy_asm"
)


# ----------------------------------------------------------------------
# Case generation
# ----------------------------------------------------------------------

def generate_cases(n: int, seed: int, max_len: int,
                   guard_frac: float) -> list[tuple[str, int, int, int, bytes]]:
    rng = random.Random(seed)
    cases: list[tuple[str, int, int, int, bytes]] = []
    for _ in range(n):
        if rng.random() < 0.3:
            length = rng.choice(BOUNDARY_LENS)
        else:
            length = rng.randint(0, max_len)
        soff = rng.randint(0, 15)
        doff = rng.randint(0, 15)
        payload = bytes(rng.randrange(256) for _ in range(length))
        kind = "N"
        if rng.random() < guard_frac and length <= MAX_GUARD_LEN:
            kind = rng.choice(("GS", "GD"))
        cases.append((kind, length, soff, doff, payload))
    return cases


def serialize(cases) -> str:
    lines = []
    for kind, length, soff, doff, payload in cases:
        prefix = f"{kind} " if kind != "N" else ""
        lines.append(
            f"{prefix}{length} {soff} {doff} {payload.hex()}"
        )
    return "\n".join(lines) + "\n"


def run_program(command: str, cases, timeout: int = 120):
    """Run one program over all cases; return (rc, output lines, stderr).

    A hang (infinite loop in a broken candidate) is reported as rc=-1 with
    an explanatory stderr instead of raising.
    """
    try:
        proc = subprocess.run(
            command,
            input=serialize(cases),
            capture_output=True,
            text=True,
            cwd=str(WORKDIR),
            timeout=timeout,
            shell=True,
        )
        return proc.returncode, proc.stdout.splitlines(), proc.stderr
    except subprocess.TimeoutExpired as exc:
        return -1, [], f"timed out after {timeout}s (broken infinite loop?)"


# ----------------------------------------------------------------------
# Comparison
# ----------------------------------------------------------------------

def check_batch(ref_cmd: str, cand_cmd: str, cases) -> tuple[int, str] | None:
    """Run both programs over a batch; None on success, else (index, detail)."""
    ref_rc, ref_out, ref_err = run_program(ref_cmd, cases)
    cand_rc, cand_out, cand_err = run_program(cand_cmd, cases)

    if ref_rc == -1:
        return 0, f"reference program timed out:\n{ref_err[:800]}"
    if ref_rc != 0:
        return 0, f"reference program failed (rc={ref_rc}):\n{ref_err[:800]}"
    if cand_rc != 0:
        return 0, f"candidate program failed (rc={cand_rc}):\n{cand_err[-800:]}"

    for i, (case, expected) in enumerate(zip(cases, ref_out)):
        actual = cand_out[i] if i < len(cand_out) else "<crash: no output>"
        if actual != expected:
            kind, length, soff, doff, payload = case
            return i, (
                f"case {i}: kind={kind} len={length} src_off={soff} "
                f"dst_off={doff}\n"
                f"  payload[0:32] = {payload[:32].hex()}\n"
                f"  reference: {expected[:160]}\n"
                f"  candidate: {actual[:160]}"
            )
    if len(cand_out) != len(ref_out):
        return len(ref_out), (
            f"candidate produced {len(cand_out)} lines, "
            f"reference {len(ref_out)} (candidate crashed early?)"
        )
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default=DEFAULT_REF,
                        help="reference program command")
    parser.add_argument("--cand", default=DEFAULT_CAND,
                        help="candidate program command")
    parser.add_argument("--cases", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--max-len", type=int, default=4096)
    parser.add_argument("--guard-frac", type=float, default=0.25)
    parser.add_argument("--batch", type=int, default=200,
                        help="cases per subprocess invocation")
    args = parser.parse_args()

    if args.cases <= 0:
        raise SystemExit("--cases must be positive")

    cases = generate_cases(args.cases, args.seed, args.max_len, args.guard_frac)
    guard_count = sum(1 for c in cases if c[0] != "N")

    print(f"Differential testing: {len(cases)} cases "
          f"({guard_count} guard-page), seed={args.seed}")

    checked = 0
    failures = 0
    for start in range(0, len(cases), args.batch):
        batch = cases[start : start + args.batch]
        result = check_batch(args.ref, args.cand, batch)
        checked += len(batch)
        if result is None:
            print(f"  ✓ batch {start // args.batch + 1}: {len(batch)} cases match")
            continue

        index, detail = result
        failures += 1
        print(f"  ✗ batch {start // args.batch + 1}: mismatch at local case {index}")
        print(detail)

        # Isolate the exact failing case by rerunning it alone.
        failing = batch[index]
        alone = [failing]
        r_ref = run_program(args.ref, alone)
        r_cand = run_program(args.cand, alone)
        print(f"  isolated case: {detail.splitlines()[0]}")
        print(f"    reference rc={r_ref[0]} out={r_ref[1][:1]}")
        print(f"    candidate rc={r_cand[0]} out={r_cand[1][:1]}")
        if r_cand[2]:
            print(f"    candidate stderr: {r_cand[2][-400:]}")
        break  # one failing case is enough to reject the candidate

    print()
    if failures:
        print(f"FAILED: {len(cases)} cases, mismatch found")
        raise SystemExit(1)
    print(f"OK: {len(cases)}/{len(cases)} cases match")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
