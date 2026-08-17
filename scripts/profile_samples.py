#!/usr/bin/env python3
"""Sampled time profile of sarm, attributed to functions.

`xctrace` needs a full Xcode install; this machine has Command Line Tools
only, so `xctrace` refuses to run. `/usr/bin/sample` is the same kind of
instrument — a periodic PC sampler over a live task — and it is present,
so it is what this uses.

sarm is hand-written assembly with no frame-pointer chain, so `sample`'s
unwinder collapses every sarm frame to the leaf PC. That yields a flat
self-time profile and no call tree, which is exactly what "which function
is hot" needs; it cannot tell you who called whom. `sample` also cannot
symbolicate the binary (it prints `load address + 0xNNN`), so the offsets
are mapped to symbols here against `nm -n`, taking the nearest preceding
`T` symbol.

Because sarm's syscalls are raw `svc` instructions rather than libSystem
calls, kernel time lands on the `svc` site inside the calling function —
so `raw_read`/`raw_write` self time *is* the syscall cost.

Load is driven by several concurrent client processes so the server is
kept busy; `sample` samples a blocked thread as readily as a running one,
and an idle server would otherwise pile every sample onto whichever
`svc` it was parked in. `--idle-report` prints how much still landed on
the accept-loop block, which is the residual idle to discount.

Usage
  python3 scripts/profile_samples.py handshake --seconds 20
  python3 scripts/profile_samples.py request --clients 6 --json out.json
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import profile_workload as pw  # noqa: E402

TEXT_VMADDR = 0x100000000      # __TEXT vmaddr; sample reports PC - load_addr

# Where each symbol belongs in the cost breakdown the profile asks for.
# Matched in order, first hit wins.
GROUPS = [
    (r"^(p256_|x25519|crypto_random_bytes)", "handshake asymmetric crypto"),
    (r"^(sha256|hkdf_|hmac_sha256|tls_transcript)",
     "transcript / key schedule"),
    (r"^(aes|ghash|gf_mult_128)", "AES-GCM record crypto"),
    (r"^(tls_record|tls_read_record|tls_app_data)", "TLS record framing"),
    (r"^(h2_hpack|h2_huffman)", "HPACK"),
    (r"^(h2_|http1_|parse_|get_header|create_response|reply_status|"
     r"find_http_code|check_path|decode_url|get_filetype|get$|get_setup|"
     r"head$|options$|handle_fs_error|verify_http_version)",
     "H2 / HTTP framing"),
    (r"^(raw_read|raw_write|transport_|write_all|_main|skip_argv|exit$|"
     r"child)", "transport / syscalls / accept loop"),
    (r"^tls_", "handshake plumbing (non-crypto)"),
    (r"^(memcpy|strlen|streqn|itoa|atoi|fnv1a_64)", "util"),
    (r".*", "everything else"),
]


# sample(1) samples a blocked thread as readily as a running one, so the
# accept() block between connections shows up as work. `loop:` in main.S
# is not in the linked symbol table, so those samples resolve to the
# nearest preceding `T` symbol, which is `skip_argv`.
IDLE_SYMBOLS = {"skip_argv"}

# Local (`t`) symbols that are genuine subroutines rather than branch
# labels. `p256_reduce` is the P-256 Solinas reduction that every
# `p256_fe_mul` runs; it lives between `p256_fe_inv` and `p256_fe_sqr` in
# address order, so leaving it out charged half the handshake to
# `p256_fe_inv`, which the source shows is called twice per handshake.
#
# `.Lgcm_gf_mul` is the head of the GHASH block that src/crypto/gcm/data.S
# emits into .text, and every gcm file `#include`s it — so there are four
# copies, each placed *before* its file's exported function. Without it,
# aes_gcm_encrypt's GHASH (which sits just below the `aes_gcm_encrypt`
# symbol) was charged to `aes_gcm_decrypt`, and the transfer profile
# claimed the server spent 29% of its time decrypting a few hundred
# 26-byte WINDOW_UPDATE records. All four copies share the name and so
# merge into one row, which is the right granularity: the call tree still
# shows which GCM entry point each one was reached through.
LOCAL_FUNCTIONS = {"p256_reduce", "p256_scalar_reduce_wide", ".Lgcm_gf_mul"}

NAME_ALIASES = {".Lgcm_gf_mul": "ghash (inlined gcm block)"}


def group_of(symbol: str) -> str:
    for pattern, name in GROUPS:
        if re.match(pattern, symbol):
            return name
    return "everything else"


# ── symbol map ───────────────────────────────────────────────────────

def text_symbols(binary: Path):
    """[(addr, name)] of __TEXT symbols, sorted, for nearest-preceding
    lookup. Local labels are not in the table, so a sample inside a
    function attributes to the function — which is what we want."""
    # `nm` exits non-zero on the debug stabs `cc -g` leaves behind while
    # still printing every symbol, so the status is deliberately ignored —
    # but a genuinely empty stdout means nm itself failed, and its stderr
    # is the only thing that says why (running under an x86_64 `timeout`,
    # for one, breaks the xcrun shim).
    proc = subprocess.run(["nm", "-n", str(binary)], capture_output=True,
                          text=True)
    out = proc.stdout
    if not out.strip():
        raise SystemExit(f"nm produced no output for {binary}: "
                         f"{proc.stderr.strip() or 'no stderr'}")
    syms = []
    for line in out.splitlines():
        parts = line.split()
        # Mostly `T` only: the `t` entries are branch labels inside a
        # function, and attributing to them would split one function's
        # samples across a dozen rows. LOCAL_FUNCTIONS is the exception —
        # real subroutines that happen never to have been given `.global`,
        # and that sit between two `T` symbols, so without them their time
        # would be charged to whichever function precedes them.
        keep = parts[1] == "T" or (parts[1] == "t"
                                   and parts[2] in LOCAL_FUNCTIONS)
        if len(parts) == 3 and keep and parts[0].strip("0"):
            addr = int(parts[0], 16)
            if addr >= TEXT_VMADDR:
                syms.append((addr, parts[2]))
    syms.sort()
    # de-duplicate aliases at the same address, keeping the first name
    deduped = []
    for addr, name in syms:
        if deduped and deduped[-1][0] == addr:
            continue
        deduped.append((addr, name))
    return deduped


def lookup(syms, addr):
    lo, hi = 0, len(syms)
    while lo < hi:
        mid = (lo + hi) // 2
        if syms[mid][0] <= addr:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return "<before first symbol>", 0
    base, name = syms[lo - 1]
    return name, addr - base


# ── load generation ──────────────────────────────────────────────────

def _worker(scenario, stop_at):
    workload, _sizes = pw.SCENARIOS[scenario]
    # Requests per connection. Large for the single-connection scenarios,
    # or the handshake they each pay once leaks back into the profile and
    # stops them isolating per-byte / per-request cost.
    unit = {"handshake": 20, "pageload": 10,
            "transfer": 400, "request": 4000}[scenario]
    while time.time() < stop_at:
        try:
            workload(unit)
        except SystemExit:
            return
        except OSError:
            return


def drive(scenario, clients, seconds):
    stop_at = time.time() + seconds
    procs = [mp.Process(target=_worker, args=(scenario, stop_at))
             for _ in range(clients)]
    for p in procs:
        p.start()
    return procs


# ── sample parsing ───────────────────────────────────────────────────
#
# sample(1)'s call graph is an indented tree, two characters per level,
# drawn with `+ ! : |` guides rather than plain spaces:
#
#     2556 Thread_6321068   DispatchQueue_1: com.apple.main-thread
#       1250 tls_certificate_verify_sign_with_k  (in sarm) + 72  [0x…]
#       + 1176 p256_ecdsa_sign_with_k  (in sarm) + 124  [0x…]
#       + ! 820 .Lpmul_loop  (in sarm) + 28  [0x…]
#
# A node's count is inclusive of its children, so self = count minus the
# sum of the counts one level in.
#
# The symbol sample(1) prints is the nearest preceding entry in the whole
# table, `.L…` assembler labels included, which splits one function across
# a dozen rows. The bracketed absolute PC is used instead and resolved
# against the `T` symbols only, so `.Lpmul_loop` lands on `p256_point_mul`.

TREE_LINE = re.compile(r"^([ +!:|]*?)(\d+) (.*)$")
PC_RE = re.compile(r"\[(0x[0-9a-f]+)")
LOAD_ADDR_RE = re.compile(r"^Load Address:\s+(0x[0-9a-f]+)", re.M)


def parse_sample(text, resolve):
    """-> (total, self_by_name, inclusive_by_name).

    `resolve` maps one call-graph line's description to a function name.
    Resolution happens here, before the tree walk, and not afterwards:
    the GHASH block is `#include`d into gcm/encrypt.S and gcm/decrypt.S,
    so `aes_gcm_decrypt` calls a `.Lgcm_ghash_run` that resolves back to
    `aes_gcm_decrypt`. Deduplicating inclusive time by PC rather than by
    name would count that subtree twice — it inflated aes_gcm_decrypt to
    5x its real share before this was fixed."""
    match = LOAD_ADDR_RE.search(text)
    load_addr = int(match.group(1), 16) if match else None

    nodes = []          # (depth, count, key)
    in_graph = False
    for line in text.splitlines():
        if line.startswith("Call graph:"):
            in_graph = True
            continue
        if in_graph and line.startswith(("Total number in stack",
                                         "Sort by top of stack",
                                         "Binary Images:")):
            break
        if not in_graph or not line.strip():
            continue
        m = TREE_LINE.match(line)
        if not m:
            continue
        nodes.append((len(m.group(1)) // 2, int(m.group(2)),
                      resolve(_key(m.group(3), load_addr))))

    total = sum(count for depth, count, _ in nodes if depth == 2)
    self_counts, incl_counts = {}, {}
    for i, (depth, count, key) in enumerate(nodes):
        children = 0
        for j in range(i + 1, len(nodes)):
            if nodes[j][0] <= depth:
                break
            if nodes[j][0] == depth + 1:
                children += nodes[j][1]
        own = count - children
        if own > 0:
            self_counts[key] = self_counts.get(key, 0) + own
        # inclusive: only if no ancestor carries the same key
        ancestor_depth, seen = depth, False
        for j in range(i - 1, -1, -1):
            if nodes[j][0] >= ancestor_depth:
                continue
            ancestor_depth = nodes[j][0]
            if nodes[j][2] == key:
                seen = True
                break
            if ancestor_depth == 0:
                break
        if not seen:
            incl_counts[key] = incl_counts.get(key, 0) + count
    return total, self_counts, incl_counts


def _key(desc, load_addr):
    if "(in sarm)" in desc and load_addr is not None:
        m = PC_RE.search(desc)
        if m:
            return ("sarm", TEXT_VMADDR + (int(m.group(1), 16) - load_addr))
    m = re.match(r"^(.*?)\s+\(in ([^)]+)\)", desc)
    if m:
        return ("other", f"{m.group(1).strip()} [{m.group(2)}]")
    return ("other", desc.strip())


# ── main ─────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", choices=["handshake", "transfer",
                                         "request", "pageload"])
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--interval", type=int, default=1, help="ms")
    ap.add_argument("--clients", type=int, default=4)
    ap.add_argument("--binary", type=Path, default=REPO / "sarm")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--keep-raw", type=Path, default=None,
                    help="save sample(1)'s own output here")
    args = ap.parse_args()

    syms = text_symbols(args.binary)
    if not syms:
        raise SystemExit("no __TEXT symbols — build with `make`, not "
                         "`make production` (which strips them)")

    raw = REPO / ".profile_sample.txt"
    with pw.Server(args.binary):
        procs = drive(args.scenario, args.clients, args.seconds + 4)
        time.sleep(1.5)                       # let the load reach steady state
        pid = _server_pid()
        subprocess.run(["sample", str(pid), str(args.seconds),
                        str(args.interval), "-mayDie", "-file", str(raw)],
                       capture_output=True, text=True)
        for p in procs:
            p.join(timeout=20)
            if p.is_alive():
                p.terminate()

    text = raw.read_text()
    if args.keep_raw:
        args.keep_raw.write_text(text)
    def resolve(key):
        if key[0] != "sarm":
            return key[1]
        name = lookup(syms, key[1])[0]
        return NAME_ALIASES.get(name, name)

    total, self_by_symbol, incl_by_symbol = parse_sample(text, resolve)
    raw.unlink(missing_ok=True)

    # The accept-loop block is idle, not work: with the server serving one
    # connection at a time, any moment no client has a connection queued
    # lands here. Percentages are of busy samples, and the idle share is
    # reported separately so a reader can see how saturated the run was.
    idle = sum(c for n, c in self_by_symbol.items()
               if n in IDLE_SYMBOLS)
    busy = total - idle

    print(f"\n── sampled profile: {args.scenario} "
          f"({total} samples @ {args.interval} ms, {args.clients} clients; "
          f"{idle} idle, {busy} busy) ──")

    print(f"\n  self time (% of busy)")
    print(f"  {'samples':>8}  {'share':>7}  function")
    ranked = sorted(((n, c) for n, c in self_by_symbol.items()
                     if n not in IDLE_SYMBOLS), key=lambda kv: -kv[1])
    for name, count in ranked[:args.top]:
        print(f"  {count:>8}  {count / busy * 100:6.2f}%  {name}")

    print(f"\n  inclusive time (% of busy) — top of each subtree")
    incl_ranked = sorted(((n, c) for n, c in incl_by_symbol.items()
                          if n not in IDLE_SYMBOLS), key=lambda kv: -kv[1])
    for name, count in incl_ranked[:args.top]:
        print(f"  {count:>8}  {count / busy * 100:6.2f}%  {name}")

    groups = {}
    for name, count in self_by_symbol.items():
        if name in IDLE_SYMBOLS:
            continue
        groups[group_of(name)] = groups.get(group_of(name), 0) + count
    print(f"\n  cost centres (self time, % of busy)")
    for name, count in sorted(groups.items(), key=lambda kv: -kv[1]):
        print(f"  {count:>8}  {count / busy * 100:6.2f}%  {name}")

    if args.json:
        args.json.write_text(json.dumps(
            {"scenario": args.scenario, "samples": total, "idle": idle,
             "busy": busy, "interval_ms": args.interval,
             "clients": args.clients, "self": self_by_symbol,
             "inclusive": incl_by_symbol, "groups": groups}, indent=2))
        print(f"\nwrote {args.json}")
    return 0


def _server_pid() -> int:
    out = subprocess.run(["pgrep", "-n", "-f", "sarm d"],
                         capture_output=True, text=True).stdout.strip()
    if not out:
        raise SystemExit("could not find the sarm process")
    return int(out.splitlines()[0])


if __name__ == "__main__":
    mp.set_start_method("fork")
    sys.exit(main())
