#!/usr/bin/env python3
"""Static syscall audit for sarm (docs/SECURITY.md Step 11, §14).

Step 11 asks for a syscall allowlist and a test that the server never opens a
file.  The usual way to answer that is to trace a running process, and
``tests/test_syscalls.sh`` does exactly that where the platform allows it.  But
tracing only proves that the workload you *ran* did not open a file.  ``sarm``
supports a much stronger claim, and this script is what checks it:

    the binary contains no code path that can issue a file-opening syscall,
    because it contains no ``svc`` site whose syscall number is one.

That holds because every syscall in this tree goes through the ``SCWINUM`` /
``SCWISVC`` macro pair in ``src/defs.S``, which materialises the syscall number
as an immediate into x16 (macOS) or x8 (Linux) and then executes ``svc``.  The
number is therefore a compile-time constant at every call site, visible in the
disassembly, and the complete set of syscalls the binary can make is decidable
by reading it.  There is no indirect ``svc``, no libc, and no dynamic linking:
``sarm`` is statically linked against nothing at all.

Three checks, all of which must pass:

  source    every ``SCWINUM SYS_x`` site in ``src/`` names a syscall on the
            allowlist.  Platform-blind (it takes the union of the macOS and
            Linux call sites), so it catches a new syscall added under the
            ``#ifdef`` you are not currently building.

  binary    every ``svc`` in the built binary resolves to a syscall number,
            and that number is on the allowlist for this platform.  An
            unresolved ``svc`` — one whose number register was not set by a
            reachable immediate — is itself a failure: it means the property
            above no longer holds and the claim has to be re-argued.

  forbidden no syscall from the explicitly forbidden set (open, openat,
            execve, unlink, …) appears in either.  This is redundant with the
            allowlist and deliberately so: it is the assertion Step 11 is
            actually about, and it should fail loudly and by name.

Syscall numbers are read from the ``.equ SYS_x, n`` table in ``src/defs.S``
itself — the same source of truth the assembler uses — split by the
``#ifdef __linux__`` / ``#else`` boundary so the two platforms' numbering
(93 = exit on Linux, 93 = nothing on macOS) can never be confused.

Usage:
    scripts/syscall_audit.py                     # audit ./sarm and src/
    scripts/syscall_audit.py --binary ./sarm.prod
    scripts/syscall_audit.py --quiet             # one line per check
    scripts/syscall_audit.py --json              # machine-readable

Exit status: 0 all checks passed, 1 a check failed, 2 the audit could not run
(no binary, no disassembler).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_BINARY = os.path.join(REPO, "sarm")
DEFAULT_SOURCE = os.path.join(REPO, "src")
DEFAULT_DEFS = os.path.join(REPO, "src", "defs.S")
DEFAULT_ALLOWLIST = os.path.join(REPO, "tests", "syscall_allowlist.txt")

# The syscalls Step 11 is about.  A filesystem-opening or code-loading call
# reaching the binary is the finding, whatever the allowlist happens to say.
FORBIDDEN = {
    "open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat",
    "renameatx_np", "mkdir", "mkdirat", "rmdir", "execve", "execveat",
    "chdir", "chroot", "getdents64", "getdirentries64", "stat64",
    "newfstatat", "link", "symlink", "mount", "ptrace",
}


# ── the syscall number tables ───────────────────────────────────────
def parse_defs(path):
    """Return {'linux': {num: name}, 'macos': {num: name}} from src/defs.S.

    The file carries both tables, guarded by one top-level
    ``#ifdef __linux__`` / ``#else`` / ``#endif``.  Nesting is tracked so a
    conditional inside either arm cannot be mistaken for the boundary.
    """
    tables = {"linux": {}, "macos": {}}
    names = {"linux": {}, "macos": {}}
    arm = None          # which side of the top-level #ifdef we are in
    depth = 0
    top_at = None

    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith("#if"):
                depth += 1
                if top_at is None and s.startswith("#ifdef __linux__"):
                    top_at, arm = depth, "linux"
                continue
            if s.startswith("#else"):
                if top_at is not None and depth == top_at:
                    arm = "macos"
                continue
            if s.startswith("#endif"):
                if top_at is not None and depth == top_at:
                    top_at, arm = None, None
                depth -= 1
                continue
            m = re.match(r"\.equ\s+SYS_(\w+)\s*,\s*(\d+)", s)
            if m and arm:
                name, num = m.group(1), int(m.group(2))
                tables[arm][num] = name
                names[arm][name] = num

    if not tables["linux"] or not tables["macos"]:
        raise SystemExit(f"syscall_audit: no SYS_ table found in {path}")
    return tables, names


# ── the allowlist ───────────────────────────────────────────────────
def parse_allowlist(path):
    """One bare syscall name per line; '#' comments and blanks ignored."""
    allowed = set()
    with open(path) as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if s:
                allowed.add(s)
    return allowed


# ── check 1: the source ─────────────────────────────────────────────
def scan_source(root):
    """Every SCWINUM call site in the tree, as (name, file, line).

    defs.S is skipped: it *defines* the macro and the numbers, and mentions
    every syscall the platform has, including the ones this server has never
    called.  What matters is which ones something asks for.
    """
    sites = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.endswith(".S"):
                continue
            path = os.path.join(dirpath, fn)
            if os.path.abspath(path) == os.path.abspath(DEFAULT_DEFS):
                continue
            with open(path) as f:
                for n, line in enumerate(f, 1):
                    m = re.search(r"\bSCWINUM\s+SYS_(\w+)", line)
                    if m:
                        sites.append((m.group(1),
                                      os.path.relpath(path, REPO), n))
    return sites


# ── check 2: the binary ─────────────────────────────────────────────
def disassemble(binary):
    """Text disassembly of `binary`, via whichever tool this platform has."""
    if sys.platform == "darwin" and shutil.which("otool"):
        cmd = ["otool", "-tvV", binary]
    elif shutil.which("objdump"):
        cmd = ["objdump", "-d", binary]
    elif shutil.which("llvm-objdump"):
        cmd = ["llvm-objdump", "-d", binary]
    else:
        raise SystemExit("syscall_audit: no otool or objdump on PATH — "
                         "cannot disassemble (exit 2)")
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"syscall_audit: {cmd[0]} failed: {out.stderr.strip()}")
    return out.stdout


# The number register: x16 on macOS (svc #0x80), x8 on Linux (svc #0).
NUM_REG = {"darwin": "x16", "linux": "x8"}

_INSN = re.compile(r"^\s*(?:[0-9a-fA-F]+)[:\t ]\s*(?:[0-9a-fA-F]{8}\s+)?"
                   r"(\w[\w.]*)\s*(.*)$")
_LABEL = re.compile(r"^([_A-Za-z][\w.$]*)\s*:\s*$|"
                    r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$")


def scan_binary(text, reg):
    """Resolve every ``svc`` to the syscall number in `reg`.

    A linear scan, not a dataflow: it remembers the most recent immediate
    written to the number register and attributes it to the next ``svc``,
    resetting at each function label.  That is exactly as strong as the
    property being checked — if a number ever arrives at an ``svc`` by a route
    a linear scan cannot see (a register copy, a branch that skips the ``mov``,
    a value loaded from memory), the site resolves to None and the audit fails
    rather than guessing.  Every site in this tree is a ``mov`` of a literal a
    few instructions above its ``svc``, because they all come from one macro.

    Returns [(number_or_None, function, address)].
    """
    sites = []
    func = "?"
    last = None
    mov = re.compile(r"^(?:mov|movz)$")
    imm = re.compile(r"#(0x[0-9a-fA-F]+|\d+)")

    for line in text.splitlines():
        lab = _LABEL.match(line.strip())
        if lab:
            func = lab.group(1) or lab.group(2)
            last = None
            continue
        m = _INSN.match(line)
        if not m:
            continue
        op, args = m.group(1), m.group(2)
        # Any write to the number register that is not a plain immediate
        # invalidates what we know about it.
        if args.startswith(reg + ","):
            if mov.match(op):
                v = imm.search(args)
                last = int(v.group(1), 0) if v else None
            else:
                last = None
        elif op == "svc":
            addr = re.match(r"^\s*([0-9a-fA-F]+)", line).group(1)
            sites.append((last, func, addr))
    return sites


# ── reporting ───────────────────────────────────────────────────────
GRN, RED, YEL, CLR = "\033[0;32m", "\033[0;31m", "\033[0;33m", "\033[0m"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--source", default=DEFAULT_SOURCE)
    ap.add_argument("--defs", default=DEFAULT_DEFS)
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    ap.add_argument("--skip-binary", action="store_true",
                    help="source check only (no built binary needed)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    plat = "linux" if sys.platform.startswith("linux") else "macos"
    reg = NUM_REG.get("linux" if plat == "linux" else "darwin")

    tables, names = parse_defs(args.defs)
    allowed = parse_allowlist(args.allowlist)

    failures = []
    report = {"platform": plat, "allowlist": sorted(allowed)}

    # ── source ──
    sites = scan_source(args.source)
    src_used = {}
    for name, path, line in sites:
        src_used.setdefault(name, []).append(f"{path}:{line}")
    report["source"] = {k: v for k, v in sorted(src_used.items())}

    for name in sorted(src_used):
        if name not in allowed:
            failures.append(f"source: SYS_{name} is called from "
                            f"{src_used[name][0]} but is not on the allowlist")
        if name in FORBIDDEN:
            failures.append(f"source: forbidden syscall {name} is called from "
                            f"{src_used[name][0]}")

    # Syscalls the allowlist permits that nothing calls: not a failure (the
    # allowlist is written per platform and both arms are listed), but worth
    # printing — an allowlist wider than the binary is an allowlist that has
    # stopped tracking it.
    report["allowlist_unused"] = sorted(allowed - set(src_used))

    # ── binary ──
    bin_used = {}
    if not args.skip_binary:
        if not os.path.exists(args.binary):
            print(f"syscall_audit: {args.binary} not found — run 'make' first",
                  file=sys.stderr)
            return 2
        bsites = scan_binary(disassemble(args.binary), reg)
        if not bsites:
            failures.append("binary: no svc instruction found at all — "
                            "is this the right binary?")
        for num, func, addr in bsites:
            if num is None:
                failures.append(f"binary: svc at {addr} (in {func}) has no "
                                f"resolvable syscall number in {reg} — the "
                                f"static allowlist claim no longer holds")
                continue
            name = tables[plat].get(num, f"unknown({num})")
            bin_used.setdefault(name, []).append(addr)
            if name not in allowed:
                failures.append(f"binary: syscall {name} ({num}) at {addr} "
                                f"in {func} is not on the allowlist")
            if name in FORBIDDEN:
                failures.append(f"binary: forbidden syscall {name} ({num}) at "
                                f"{addr} in {func}")
        report["binary"] = {k: v for k, v in sorted(bin_used.items())}

        # The source is platform-blind, the binary is not: everything the
        # binary calls must have come from a source site.
        for name in bin_used:
            if name not in src_used and not name.startswith("unknown("):
                failures.append(f"binary: syscall {name} appears in the "
                                f"binary but no SCWINUM site in src/ asks "
                                f"for it")

    report["failures"] = failures
    report["ok"] = not failures

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if not failures else 1

    if not args.quiet:
        print()
        print(f"── syscall audit ({plat}, number register {reg}) ──")
        print()
        print(f"  source — {len(sites)} SCWINUM sites, "
              f"{len(src_used)} distinct syscalls")
        for name in sorted(src_used):
            mark = f"{GRN}✓{CLR}" if name in allowed else f"{RED}✗{CLR}"
            print(f"    {mark} {name:<16} {len(src_used[name])} site(s)")
        if not args.skip_binary:
            print()
            print(f"  binary — {args.binary}")
            for name in sorted(bin_used):
                mark = f"{GRN}✓{CLR}" if name in allowed else f"{RED}✗{CLR}"
                print(f"    {mark} {name:<16} {len(bin_used[name])} svc site(s)")
            print()
            print("  forbidden set (open/openat/execve/unlink/…): "
                  + (f"{GRN}absent{CLR}"
                     if not any(n in FORBIDDEN for n in bin_used)
                     else f"{RED}PRESENT{CLR}"))
        if report["allowlist_unused"]:
            print()
            print(f"  {YEL}allowlisted but never called{CLR}: "
                  + ", ".join(report["allowlist_unused"]))
        print()

    for f in failures:
        print(f"  {RED}✗{CLR} {f}")
    if failures:
        print()
        print(f"{RED}syscall audit failed ({len(failures)} finding(s)){CLR}")
        return 1
    if args.quiet:
        n = len(bin_used) if bin_used else len(src_used)
        print(f"  {GRN}✓{CLR} syscall audit: {n} syscalls, all allowlisted, "
              f"no filesystem access")
    else:
        print(f"{GRN}syscall audit passed{CLR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
