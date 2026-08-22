#!/usr/bin/env python3
"""Inspect a linked sarm binary for its production hardening
(docs/SECURITY.md §13 and Step 13, called by tests/test_hardening.sh).

Usage: hardening_checks.py <binary> [--quiet] [--allow-missing-symbols]

Reads a Mach-O with the platform's own tools (otool/nm/dyld_info) and an
ELF by parsing it directly, so that a macOS host can inspect the Linux
binary the container ships without a cross-binutils installed.  Prints
one line per check:

    ok    <name>   <detail>
    fail  <name>   <detail>
    skip  <name>   <why>

Exit status is 0 when nothing failed, 1 when something did.  The caller
decides what to do with a `skip`; nothing here treats an unrunnable
check as a passing one.

A symbol this script looks for and does not find is a failure, not a
pass: it means the binary was stripped, or the tree renamed something,
and either way the check stopped covering what it claims to.  The one
exception is `--allow-missing-symbols`, for the `make production`
binary the container ships: local symbols are gone from that one by
design, so the check is made over the globals that remain and says how
many it saw.

The checks, and why each one is a security property rather than a build
detail:

  pie              The image can be loaded at a random base.  Without
                   it every gadget, every table and the private scalar
                   are at addresses an attacker can write down once.

  wx               No mapping is both writable and executable, at
                   current *or* maximum protection.  A W^X violation
                   turns any write primitive into code execution
                   without needing a gadget chain.

  rodata-const     The constants really are in a read-only region:
                   the certificate, the private scalar, the embedded
                   assets, the crypto tables, and the two tables an
                   indirect branch goes through.  A write primitive
                   that reaches a handler table is a jump primitive.

  rodata-mutable   The genuinely mutable globals are *not* in it.
                   This is the non-vacuity check for the one above: a
                   binary with no read-only region at all, or a symbol
                   lookup that silently returns nothing, would pass
                   `rodata-const` by finding nothing to complain about.

  fixups           The loader is asked to relocate nothing.  Every
                   table in the tree stores link-time-resolved offsets
                   rather than addresses, which is what lets the Linux
                   build be a PIE with no dynamic linker behind it, and
                   what keeps the read-only regions genuinely read-only
                   rather than write-then-protect.

  noexecstack      (ELF only) PT_GNU_STACK is present and not
                   executable.  aarch64 Linux reads a *missing*
                   PT_GNU_STACK as READ_IMPLIES_EXEC, which makes every
                   readable mapping in the process executable — the W^X
                   check above passes on the file and means nothing in
                   the process.

  rodata-segment   (ELF only) .rodata is in its own r-- LOAD segment
                   rather than sharing the r-x one with .text, so
                   constants are not mapped executable.
"""

import re
import subprocess
import sys

# Symbols that must be read-only, and what each one is.  Some are local
# symbols (no .global), which is why the binary under test is the
# unstripped default build rather than `make production`.
CONST_SYMBOLS = {
    "tls_priv_key": "the ECDSA P-256 private scalar",
    "tls_cert_der": "the server certificate",
    "embedded_files": "the embedded asset table",
    "status_table": "the HTTP status-line table",
    "h2_hpack_static_table": "the HPACK static table",
    "h2_frame_handlers": "the HTTP/2 frame dispatch table",
    "h2_huffman_table": "the HPACK Huffman table",
    "K256": "the SHA-256 round constants",
    "p256_comb_table": "the P-256 comb table",
    "p256_p": "the P-256 field modulus",
    "file_types_a": "the MIME type table",
}

# Globals that must stay writable — the non-vacuity control.
MUTABLE_SYMBOLS = {
    "tls_state": "the per-connection TLS state",
    "tls_hs_record_buf": "the handshake record buffer",
    "buf": "the HTTP/1 request buffer",
    "worker_count": "the worker count parsed from argv",
}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


class Checks:
    def __init__(self):
        self.results = []

    def ok(self, name, detail):
        self.results.append(("ok", name, detail))

    def fail(self, name, detail):
        self.results.append(("fail", name, detail))

    def skip(self, name, detail):
        self.results.append(("skip", name, detail))


def symbol_addresses(binary):
    """name -> address, for every symbol nm reports with one."""
    out = run(["nm", "-n", binary])
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        addr, kind, name = parts
        if kind in ("a", "A", "U"):  # absolute .equ values, undefined
            continue
        try:
            syms.setdefault(name.lstrip("_"), int(addr, 16))
        except ValueError:
            continue
    return syms


# ── Mach-O ───────────────────────────────────────────────────────────

def macho_segments(binary):
    """[(name, vmaddr, vmsize, initprot, maxprot, flags)] from otool -lv."""
    out = run(["otool", "-lv", binary])
    segs = []
    cur = None
    for line in out.splitlines():
        s = line.strip()
        if s == "cmd LC_SEGMENT_64":
            cur = {}
            continue
        if cur is None:
            continue
        m = re.match(r"^(segname|vmaddr|vmsize|initprot|maxprot|flags) +(.*)$", s)
        if not m:
            continue
        key, val = m.groups()
        if key in cur:  # the section list repeats segname — segment done
            segs.append(cur)
            cur = None
            continue
        cur[key] = val.strip()
        if key == "flags":
            segs.append(cur)
            cur = None
    return segs


def check_macho(binary, c, allow_missing=False):
    header = run(["otool", "-hv", binary])
    if "PIE" in header:
        c.ok("pie", "Mach-O header carries MH_PIE")
    else:
        c.fail("pie", "Mach-O header has no MH_PIE flag")

    segs = macho_segments(binary)
    if not segs:
        c.fail("wx", "could not read any LC_SEGMENT_64 from otool")
        return

    bad = [s["segname"] for s in segs
           if ("w" in s.get("maxprot", "") and "x" in s.get("maxprot", ""))
           or ("w" in s.get("initprot", "") and "x" in s.get("initprot", ""))]
    if bad:
        c.fail("wx", "writable and executable: " + ", ".join(bad))
    else:
        c.ok("wx", "no segment is writable and executable (%d segments)" % len(segs))

    ro = [s for s in segs
          if s["segname"] == "__DATA_CONST" and "SG_READ_ONLY" in s.get("flags", "")]
    if not ro:
        c.fail("rodata-const",
               "no __DATA_CONST segment with SG_READ_ONLY — nothing is read-only")
        c.fail("rodata-mutable", "no read-only segment to be outside of")
        ro_ranges = []
    else:
        ro_ranges = [(int(s["vmaddr"], 16),
                      int(s["vmaddr"], 16) + int(s["vmsize"], 16)) for s in ro]

    if ro_ranges:
        check_symbol_placement(symbol_addresses(binary), c, ro_ranges,
                               "__DATA_CONST", allow_missing)

    fixups = run(["dyld_info", "-fixups", binary])
    entries = [l for l in fixups.splitlines()
               if re.match(r"^\s+__[A-Z_]+\s", l)]
    if entries:
        c.fail("fixups", "%d chained fixup(s) — the loader rewrites static data"
               % len(entries))
    else:
        c.ok("fixups", "no chained fixups: the loader rewrites nothing")


# ── ELF ────────────────────────────────────────────────────────────
#
# Parsed here rather than shelled out to readelf, so that a macOS host
# can inspect the Linux binary the container ships (tests/
# test_hardening.sh --docker) without a cross-binutils installed.

import struct

PT_LOAD, PT_DYNAMIC, PT_GNU_STACK = 1, 2, 0x6474e551
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB, SHT_DYNSYM, SHT_RELA = 2, 11, 4
ET_DYN = 3


class Elf:
    """Just enough ELF64 little-endian aarch64 to answer Step 13."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        (self.etype,) = struct.unpack_from("<H", d, 16)
        (self.phoff, self.shoff) = struct.unpack_from("<QQ", d, 32)
        (self.phentsize, self.phnum, self.shentsize, self.shnum,
         self.shstrndx) = struct.unpack_from("<HHHHH", d, 54)

        self.phdrs = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            ptype, flags, poff, vaddr, _paddr, filesz, memsz, _align = \
                struct.unpack_from("<IIQQQQQQ", d, off)
            self.phdrs.append({"type": ptype, "flags": flags, "vaddr": vaddr,
                               "memsz": memsz, "offset": poff,
                               "filesz": filesz})

        self.sections = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            name, stype, sflags, addr, soff, size, link, info, align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", d, off)
            self.sections.append({"name_off": name, "type": stype,
                                  "flags": sflags, "addr": addr,
                                  "offset": soff, "size": size, "link": link,
                                  "entsize": entsize})
        shstr = self.sections[self.shstrndx] if self.shnum else None
        for sec in self.sections:
            sec["name"] = self._str(shstr, sec["name_off"]) if shstr else ""

    def _str(self, strtab, off):
        base = strtab["offset"] + off
        end = self.data.index(b"\x00", base)
        return self.data[base:end].decode("utf-8", "replace")

    def section(self, name):
        for sec in self.sections:
            if sec["name"] == name:
                return sec
        return None

    def symbols(self):
        """name -> value, from .symtab if present, else .dynsym."""
        syms = {}
        for stype in (SHT_SYMTAB, SHT_DYNSYM):
            tabs = [s for s in self.sections if s["type"] == stype]
            for tab in tabs:
                strtab = self.sections[tab["link"]]
                n = tab["size"] // 24
                for i in range(n):
                    off = tab["offset"] + i * 24
                    name, _info, _other, _shndx, value, _size = \
                        struct.unpack_from("<IBBHQQ", self.data, off)
                    if not name or not value:
                        continue
                    syms.setdefault(self._str(strtab, name), value)
            if syms:
                break
        return syms

    def dynamic_relocations(self):
        n = 0
        for sec in self.sections:
            if sec["type"] == SHT_RELA and sec["name"].startswith(".rela.dyn"):
                n += sec["size"] // 24
        return n


def flagstr(flags):
    return ("R" if flags & PF_R else "") + ("W" if flags & PF_W else "") \
        + ("E" if flags & PF_X else "")


def check_elf(binary, c, allow_missing=False):
    elf = Elf(binary)

    if elf.etype == ET_DYN:
        c.ok("pie", "ET_DYN with no interpreter — a static PIE")
    else:
        c.fail("pie", "ELF type is not DYN: the image loads at a fixed address")

    loads = [p for p in elf.phdrs if p["type"] == PT_LOAD]
    if not loads:
        c.fail("wx", "no LOAD segments found")
        return

    bad = [hex(p["vaddr"]) for p in loads
           if p["flags"] & PF_W and p["flags"] & PF_X]
    if bad:
        c.fail("wx", "writable and executable LOAD at " + ", ".join(bad))
    else:
        c.ok("wx", "no LOAD segment is writable and executable (%d segments)"
             % len(loads))

    stack = [p for p in elf.phdrs if p["type"] == PT_GNU_STACK]
    if not stack:
        c.fail("noexecstack",
               "no PT_GNU_STACK — aarch64 Linux then applies READ_IMPLIES_EXEC")
    elif stack[0]["flags"] & PF_X:
        c.fail("noexecstack", "PT_GNU_STACK is executable")
    else:
        c.ok("noexecstack", "PT_GNU_STACK present and non-executable")

    rodata = elf.section(".rodata")
    if rodata is None:
        c.fail("rodata-segment", "no .rodata section")
        ro_ranges = []
    else:
        start = rodata["addr"]
        ro_ranges = [(start, start + rodata["size"])]
        holder = [p for p in loads if p["vaddr"] <= start < p["vaddr"] + p["memsz"]]
        if not holder:
            c.fail("rodata-segment", ".rodata is in no LOAD segment")
        elif flagstr(holder[0]["flags"]) == "R":
            c.ok("rodata-segment", ".rodata has its own r-- LOAD segment")
        else:
            c.fail("rodata-segment",
                   ".rodata shares a %s segment" % flagstr(holder[0]["flags"]))

    if ro_ranges:
        check_symbol_placement(elf.symbols(), c, ro_ranges, ".rodata",
                               allow_missing)
    else:
        c.fail("rodata-const", "no .rodata to place constants in")
        c.fail("rodata-mutable", "no .rodata to be outside of")

    n = elf.dynamic_relocations()
    if n:
        c.fail("fixups", "%d dynamic relocation(s) — and nothing applies them "
                         "in a binary with no dynamic linker" % n)
    else:
        c.ok("fixups", "no dynamic relocations: nothing to apply at load time")


# ── shared ───────────────────────────────────────────────────────────

def check_symbol_placement(syms, c, ro_ranges, region, allow_missing=False):
    def inside(addr):
        return any(lo <= addr < hi for lo, hi in ro_ranges)

    def one(check, wanted, want_inside, verdict):
        missing, wrong = [], []
        for name, what in wanted.items():
            if name not in syms:
                missing.append(name)
            elif inside(syms[name]) != want_inside:
                wrong.append("%s (%s)" % (name, what))
        seen = len(wanted) - len(missing)
        if wrong:
            c.fail(check, verdict + ": " + ", ".join(wrong))
        elif missing and not allow_missing:
            # A symbol that vanished is not a passing check: either the
            # binary was stripped or the tree renamed something, and
            # either way this check stopped covering what it claims to.
            c.fail(check, "symbol(s) not in the binary: " + ", ".join(missing))
        elif missing and seen == 0:
            c.fail(check, "no symbols left to check — the binary has none")
        elif missing:
            c.ok(check, "%d of %d symbols survive stripping, and all of them "
                        "are %s %s" % (seen, len(wanted),
                                       "in" if want_inside else "outside",
                                       region))
        else:
            c.ok(check, "all %d are %s %s" % (len(wanted),
                                              "in" if want_inside else "outside",
                                              region)
                 + (", private scalar included" if want_inside else ""))

    one("rodata-const", CONST_SYMBOLS, True, "writable")
    one("rodata-mutable", MUTABLE_SYMBOLS, False,
        "read-only, but written at runtime")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    quiet = "--quiet" in sys.argv[1:]
    allow_missing = "--allow-missing-symbols" in sys.argv[1:]
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    binary = args[0]

    c = Checks()
    with open(binary, "rb") as f:
        magic = f.read(4)
    if magic == b"\x7fELF":
        check_elf(binary, c, allow_missing)
    elif magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        check_macho(binary, c, allow_missing)
    else:
        print("fail\tformat\tnot a Mach-O or ELF binary: %s" % binary)
        return 1

    failed = 0
    for status, name, detail in c.results:
        if status == "fail":
            failed += 1
        if not quiet or status == "fail":
            print("%s\t%s\t%s" % (status, name, detail))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
