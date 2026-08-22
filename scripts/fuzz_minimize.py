#!/usr/bin/env python3
"""Shrink a fuzzer finding to a minimal reproducer (docs/SECURITY.md Step 14).

Step 14's pipeline is four arrows long::

    corpus input -> minimal reproducer -> unit/regression test -> fix

The first arrow is the harness's job: a campaign that crashes, hangs or
violates an invariant writes the bytes it died on into ``findings/`` before it
reports (``tests/security/fuzz_common.h``).  This script is the second one.  It
takes such a file and removes everything from it that the failure does not
need, so that what gets preserved is an input a human can read and a comment
can explain — the 238 random-looking bytes of a generated flight become the
five bytes that actually crash.

The oracle is the harness's replay mode, and the whole interface is an exit
code::

    SARM_FUZZ_TARGET=<campaign> SARM_FUZZ_REPLAY=<file> <suite binary>

zero if those bytes were handled cleanly, non-zero if they still fail.  Nothing
here knows what the failure *is* — a guard-page SIGSEGV, a broken invariant and
a hang all reduce to "non-zero", which is exactly what makes the search valid
for all three.

The search is delta debugging over bytes: remove ever-smaller runs while the
failure survives, then try to simplify the bytes that are left to a readable
value.  Both passes repeat until a whole pass changes nothing.  Every candidate
is checked, so the result is guaranteed to still reproduce; it is 1-minimal
under the operations tried, not globally minimal, which is the usual and
sufficient bargain.

Usage:
    scripts/fuzz_minimize.py tests/security/_obj/test_fuzz_tls_handshake \\
                             flight findings/....bin

    scripts/fuzz_minimize.py <binary> <campaign> <input> --keep hs-underflow
        also install the result as a corpus entry, which is the third arrow:
        tests/security/corpus/<suite>/<campaign>/<name>.bin is replayed by
        every later run of that suite (and so by `make test`).
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# A replay is one case. Anything past this is the hang the input was
# preserved for, and a hang reproduces the finding just as a crash does.
REPLAY_TIMEOUT_SECS = 30


def suite_of(binary):
    """The suite name a binary reports to fuzz_suite(), from its filename."""
    base = os.path.basename(binary)
    for prefix in ("test_fuzz_", "test_"):
        if base.startswith(prefix):
            return base[len(prefix):]
    return base


class Unusable(Exception):
    """The suite cannot answer the question at all (exit 2)."""


class Oracle:
    """Does this byte string still reproduce the finding?"""

    def __init__(self, binary, campaign, verbose=False):
        self.binary = os.path.abspath(binary)
        self.campaign = campaign
        self.verbose = verbose
        self.runs = 0
        # The suite reads its corpus relative to the working directory, and a
        # minimisation run should not be perturbed by the corpus: run from the
        # binary's directory with the corpus pointed somewhere empty.
        self.cwd = os.path.dirname(self.binary)

    def fails(self, data):
        self.runs += 1
        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            env = dict(os.environ)
            env["SARM_FUZZ_TARGET"] = self.campaign
            env["SARM_FUZZ_REPLAY"] = path
            env["SARM_FUZZ_CORPUS"] = os.path.join(path + ".nocorpus")
            try:
                p = subprocess.run([self.binary], cwd=self.cwd, env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   timeout=REPLAY_TIMEOUT_SECS)
            except subprocess.TimeoutExpired:
                return True         # a hang is a failure, and a reproduction
            # 2 is the harness's "you asked for something this campaign
            # cannot do" — a misuse, not a reproduction. Shrinking against
            # it would produce a beautifully minimal file that means
            # nothing, so it stops the run instead.
            if p.returncode == 2:
                raise Unusable(p.stdout.decode("utf-8", "replace").strip())
            if self.verbose and p.returncode != 0:
                sys.stderr.write(p.stdout.decode("utf-8", "replace"))
            return p.returncode != 0
        finally:
            os.unlink(path)


def remove_pass(data, oracle):
    """Delta debugging: drop runs of bytes, finest granularity last."""
    n = 2
    while len(data) >= 2 and n <= len(data):
        chunk = max(1, len(data) // n)
        i = 0
        dropped = False
        while i < len(data):
            candidate = data[:i] + data[i + chunk:]
            if candidate != data and oracle.fails(candidate):
                data = candidate
                dropped = True
            else:
                i += chunk
        if dropped:
            n = max(2, n - 1)        # the input shrank; retry coarsely
        else:
            n *= 2
    return data


# Bytes to try in place of whatever is there, in order of how much easier they
# make the result to read. A minimal reproducer that is all 'A' says "the value
# of this byte does not matter" far more clearly than a comment can.
SIMPLIFY_TO = (0x00, 0x41)


def simplify_pass(data, oracle):
    out = bytearray(data)
    for i in range(len(out)):
        for value in SIMPLIFY_TO:
            if out[i] == value:
                break
            was, out[i] = out[i], value
            if oracle.fails(bytes(out)):
                break
            out[i] = was
    return bytes(out)


def hexdump(data, limit=256):
    lines = []
    for off in range(0, min(len(data), limit), 16):
        row = data[off:off + 16]
        hexpart = " ".join("%02x" % b for b in row)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append("  %04x  %-47s  %s" % (off, hexpart, text))
    if len(data) > limit:
        lines.append("  ... %d more bytes" % (len(data) - limit))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="the fuzz suite binary, e.g. "
                                   "tests/security/_obj/test_fuzz_http")
    ap.add_argument("campaign", help="the campaign name, e.g. path")
    ap.add_argument("input", help="the preserved input to shrink")
    ap.add_argument("-o", "--out", help="where to write the minimised input "
                                        "(default: <input>.min)")
    ap.add_argument("--keep", metavar="NAME",
                    help="also install the result as a corpus entry named "
                         "NAME.bin, which makes it a regression test")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show the replay output of each failing candidate")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    oracle = Oracle(args.binary, args.campaign, args.verbose)

    try:
        reproduces = oracle.fails(data)
    except Unusable as why:
        print(str(why) or "the suite refused the request")
        print("Nothing to minimise. Reproduce it with the seed and case the "
              "campaign reported.")
        return 2

    if not reproduces:
        print("%s does not reproduce anything under %s/%s."
              % (args.input, suite_of(args.binary), args.campaign))
        print("Nothing to minimise — the finding is either already fixed, or "
              "belongs to a campaign whose input is more than these bytes.")
        return 1

    start = len(data)
    try:
        while True:
            before = data
            data = remove_pass(data, oracle)
            data = simplify_pass(data, oracle)
            if data == before:
                break
    except Unusable as why:
        print(str(why))
        return 2

    out = args.out or args.input + ".min"
    with open(out, "wb") as f:
        f.write(data)

    print("%s: %d bytes -> %d (%d replays)"
          % (args.campaign, start, len(data), oracle.runs))
    print(hexdump(data))
    print("wrote %s" % out)

    if args.keep:
        root = os.path.join(os.path.dirname(os.path.abspath(args.binary)),
                            os.pardir, "corpus")
        dest_dir = os.path.normpath(os.path.join(root, suite_of(args.binary),
                                                 args.campaign))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, args.keep + ".bin")
        shutil.copyfile(out, dest)
        print("kept as %s" % dest)
        print("It is replayed by every run of %s from now on. Say in "
              "corpus/MANIFEST.md what it is." % os.path.basename(args.binary))
    else:
        print("Keep it: re-run with --keep <name>, or copy it under "
              "tests/security/corpus/%s/%s/."
              % (suite_of(args.binary), args.campaign))
    return 0


if __name__ == "__main__":
    sys.exit(main())
