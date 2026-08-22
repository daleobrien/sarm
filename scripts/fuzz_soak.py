#!/usr/bin/env python3
"""Run the fuzz suites continuously on fresh seeds (docs/SECURITY.md Step 14).

`make test` runs every fuzz campaign in this tree, but always on the same seed:
that is deliberate, because a suite whose corpus changes from run to run cannot
tell a regression from a coincidence.  The cost of that choice is that `make
test` only ever asks the same few million questions.  Step 14 is where the
other questions get asked — the same campaigns, on seeds nobody has run before,
for as long as there is machine time to spend.

Each round picks a random seed and runs the selected suites at a case-count
multiplier.  A round that fails has already preserved its input: the harness
writes the failing case's bytes into ``findings/`` before it reports (see
``tests/security/fuzz_common.h``), which is Step 14's one rule — *never just
fix a fuzzer crash without preserving the input* — enforced by the thing that
finds the crash rather than by whoever reads the log.  With ``--minimize`` the
next arrow is taken too, and the finding is shrunk to a minimal reproducer on
the spot.

What to do with what it finds:

    findings/<suite>-<campaign>-seed<seed>-case<n>-<why>.bin      the input
      -> scripts/fuzz_minimize.py <binary> <campaign> <file> --keep <name>
      -> tests/security/corpus/<suite>/<campaign>/<name>.bin      the test
      -> fix the routine; the corpus entry is what keeps it fixed

Usage:
    scripts/fuzz_soak.py                       # 4 rounds at x4, all suites
    scripts/fuzz_soak.py --minutes 60          # soak for an hour
    scripts/fuzz_soak.py --forever --minimize  # until it finds something
    scripts/fuzz_soak.py --suite http --mult 20 --keep-going
"""

import argparse
import os
import random
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY = os.path.join(ROOT, "tests", "security")
OBJ = os.path.join(SECURITY, "_obj")

# The suites that take a seed. Named rather than globbed so that adding a
# campaign to one of them needs no change here, and adding a *suite* is a
# deliberate line in this list.
SUITES = [
    "test_fuzz_tls_record",
    "test_fuzz_tls_handshake",
    "test_fuzz_http",
    "test_frag_socket",
    "test_frag_http",
]


def suite_matches(name, wanted):
    """--suite http matches test_fuzz_http; a full name matches exactly."""
    return not wanted or any(w == name or w in name for w in wanted)


def build():
    subprocess.run(["make", "-s", "-C", SECURITY, "build"], check=True)


def run_round(binary, seed, mult, secs, findings):
    env = dict(os.environ)
    env["SARM_FUZZ_SEED"] = str(seed)
    env["SARM_FUZZ_MULT"] = str(mult)
    env["SARM_FUZZ_SECS"] = str(secs)
    env["SARM_FUZZ_FINDINGS"] = findings
    before = set(os.listdir(findings)) if os.path.isdir(findings) else set()
    started = time.time()
    p = subprocess.run([os.path.join(OBJ, binary)], cwd=SECURITY, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    took = time.time() - started
    after = set(os.listdir(findings)) if os.path.isdir(findings) else set()
    new = sorted(after - before)
    return p.returncode, p.stdout.decode("utf-8", "replace"), took, new


def campaign_of(finding):
    """<suite>-<campaign>-seed…: the campaign is the second-to-last field
    before the seed, and campaign names contain no '-'."""
    parts = os.path.basename(finding).split("-")
    for i, part in enumerate(parts):
        if part.startswith("seed") and i >= 2:
            return "-".join(parts[1:i])
    return None


def minimize(binary, finding):
    campaign = campaign_of(finding)
    if not campaign:
        print("    (cannot tell which campaign %s came from; minimise it by "
              "hand)" % finding)
        return
    cmd = [os.path.join(ROOT, "scripts", "fuzz_minimize.py"),
           os.path.join(OBJ, binary), campaign, finding]
    print("    minimising: %s" % " ".join(cmd))
    subprocess.run(cmd)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, default=4,
                    help="rounds of every selected suite (default 4)")
    ap.add_argument("--minutes", type=float,
                    help="stop starting new rounds after this long")
    ap.add_argument("--forever", action="store_true",
                    help="keep going until interrupted or until a finding")
    ap.add_argument("--mult", type=int, default=4,
                    help="SARM_FUZZ_MULT for each round (default 4)")
    ap.add_argument("--secs", type=int, default=300,
                    help="per-campaign no-progress deadline (default 300)")
    ap.add_argument("--suite", action="append", default=[], metavar="NAME",
                    help="only this suite; repeatable, substring match")
    ap.add_argument("--seed", type=int, action="append", default=[],
                    metavar="N", help="run this seed instead of a random one; "
                                      "repeatable")
    ap.add_argument("--findings", default=os.path.join(SECURITY, "findings"),
                    help="where preserved inputs are written")
    ap.add_argument("--minimize", action="store_true",
                    help="shrink every finding to a minimal reproducer")
    ap.add_argument("--keep-going", action="store_true",
                    help="carry on after a finding instead of stopping")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if not args.no_build:
        build()

    suites = [s for s in SUITES if suite_matches(s, args.suite)]
    if not suites:
        print("no suite matches %s" % args.suite, file=sys.stderr)
        return 2
    os.makedirs(args.findings, exist_ok=True)

    log_path = os.path.join(args.findings, "soak.log")
    log = open(log_path, "a")
    log.write("# soak started %s  suites=%s mult=%d\n"
              % (time.strftime("%Y-%m-%d %H:%M:%S"), ",".join(suites),
                 args.mult))

    deadline = time.time() + args.minutes * 60 if args.minutes else None
    rounds = float("inf") if (args.forever or args.minutes) else args.rounds
    seeds = list(args.seed)

    found = 0
    done = 0
    started = time.time()
    try:
        while done < rounds:
            if deadline and time.time() >= deadline:
                break
            seed = seeds.pop(0) if seeds else random.getrandbits(63)
            print("── round %d — seed %d ──" % (done + 1, seed))
            # Before the round, not after: a machine that dies holding the
            # round still leaves behind the seed that was running on it.
            log.write("%s round=%d seed=%d start\n"
                      % (time.strftime("%H:%M:%S"), done + 1, seed))
            log.flush()
            for binary in suites:
                rc, out, took, new = run_round(binary, seed, args.mult,
                                               args.secs, args.findings)
                status = "ok" if rc == 0 else "FAILED"
                print("   %-26s %6.1fs  %s" % (binary, took, status))
                log.write("%s seed=%d suite=%s mult=%d %.1fs %s\n"
                          % (time.strftime("%H:%M:%S"), seed, binary,
                             args.mult, took, status))
                log.flush()
                if rc == 0:
                    continue
                found += 1
                # The suite's own report says which campaign, which case and
                # where the input went; reprinting it whole beats paraphrasing.
                for line in out.splitlines():
                    if line.strip().startswith(("✗", "input preserved",
                                                "minimise", "replay", "(")):
                        print("   %s" % line.strip())
                for finding in new:
                    if finding.endswith(".bin") and args.minimize:
                        minimize(binary, os.path.join(args.findings, finding))
                if not args.keep_going:
                    done += 1
                    raise KeyboardInterrupt
            done += 1
    except KeyboardInterrupt:
        print("\n(stopping)")

    elapsed = time.time() - started
    print("\n%d round%s over %.1f min, %d finding%s. Log: %s"
          % (done, "" if done == 1 else "s", elapsed / 60.0,
             found, "" if found == 1 else "s", log_path))
    if found:
        print("Every finding's input is in %s. Minimise it, keep it under "
              "tests/security/corpus/, then fix the routine — in that order "
              "(docs/SECURITY.md Step 14)." % args.findings)
    log.close()
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
