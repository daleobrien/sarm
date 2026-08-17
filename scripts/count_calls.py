#!/usr/bin/env python3
"""Count how often each function runs, per connection and per request.

Frequency, not size, is what makes a function hot
(prompts/00-workload-profile.md, step 3) — and nothing in the repo
records it, because the shipped binary deliberately logs nothing.

Rather than add counters to the assembly, this drives sarm under `lldb`
with auto-continuing breakpoints and reads the hit counts back out. No
`.S` file is touched and no instrumented binary exists at any point.

Each breakpoint hit is a process stop, so this is thousands of times
slower than the real thing — fine for counting, useless for timing, and
the reason the innermost primitives are excluded by default. Their
counts are exact functions of the ones measured here anyway:
`p256_fe_mul` is 3 `p256_bn_mul`, `p256_point_mul` is 256 rounds of
`p256_point_dbl` + `p256_point_add`, and `aes128_encrypt` runs once per
16-byte block of every record.

Usage
  python3 scripts/count_calls.py                 # one page-load connection
  python3 scripts/count_calls.py --workload request --requests 20
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import profile_workload as pw  # noqa: E402

# Functions worth a per-connection / per-request count. Deliberately
# excludes the innermost primitives (p256_bn_mul, p256_fe_mul,
# p256_point_add/dbl, aes128_encrypt, memcpy): each runs 10^4-10^6 times
# per connection, so breakpointing them would take hours, and each is a
# fixed multiple of something already on this list.
FUNCTIONS = [
    # handshake asymmetric
    "p256_ecdsa_sign_with_k", "p256_point_mul", "p256_point_to_affine",
    "p256_fe_inv", "p256_scalar_inv", "p256_scalar_mul", "x25519",
    "crypto_random_bytes",
    # transcript / key schedule
    "sha256", "hmac_sha256", "hkdf_extract", "hkdf_expand",
    "hkdf_expand_label", "tls_transcript_add", "tls_transcript_hash",
    # record layer
    "tls_record_encrypt", "tls_record_decrypt", "tls_read_record",
    "tls_record_write", "aes_gcm_encrypt", "aes_gcm_decrypt",
    "aes128_key_expand", "ghash", "gf_mult_128",
    # transport
    "raw_read_exact", "raw_write_all", "transport_read", "transport_write",
    "write_all",
    # h2 / hpack
    "h2_connection_loop", "h2_dispatch_frame", "h2_process_request",
    "h2_handle_headers", "h2_handle_window_update", "h2_write_headers",
    "h2_write_body", "h2_hpack_decode_block", "h2_hpack_decode_field",
    "h2_huffman_decode", "h2_stream_find", "lookup_embedded",
    # handshake plumbing
    "tls_server_handshake", "tls_parse_client_hello",
    "tls_build_server_hello", "tls_certificate_write",
    "tls_certificate_verify_write", "tls_finished_write",
    "tls_derive_handshake_secrets", "tls_derive_application_secrets",
]

HIT_RE = re.compile(r"^\d+:\s+name = '([^']+)'.*?, hit count = (\d+)", re.M)


def run_under_lldb(binary: Path, workload, size, functions, timeout=1800):
    commands = ["-o", f"target create {binary}"]
    for name in functions:
        commands += ["-o", f"breakpoint set -n {name} --auto-continue true"]
    commands += ["-o", "run d"]

    # `breakpoint list` has to go in on stdin rather than as another -o:
    # `run` does not return until the inferior stops, and lldb abandons
    # the remaining -o commands when the stop is a signal.
    proc = subprocess.Popen(
        ["lldb", "-x", *commands],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, cwd=str(REPO))
    try:
        pw._wait_for_listener(pw.PORT, timeout=120)
        workload(size)
    finally:
        subprocess.run(["pkill", "-f", f"{binary} d"], capture_output=True)
        out = proc.communicate("breakpoint list\nquit\n", timeout=timeout)[0]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workload", default="pageload",
                    choices=["pageload", "handshake", "request", "transfer"])
    ap.add_argument("--requests", type=int, default=1,
                    help="pages/connections, or requests for request/transfer")
    ap.add_argument("--binary", type=Path, default=REPO / "sarm")
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--only", nargs="+", default=None,
                    help="count just these functions (much faster)")
    args = ap.parse_args()

    workload = {"pageload": pw.workload_pageload,
                "handshake": pw.workload_handshake,
                "request": lambda n: pw.workload_stream(n, pw.SMALL_ASSET),
                "transfer": lambda n: pw.workload_stream(n, pw.LARGE_ASSET),
                }[args.workload]

    started = time.time()
    out = run_under_lldb(args.binary, workload, args.requests,
                         args.only or FUNCTIONS)
    counts = {name: int(hits) for name, hits in HIT_RE.findall(out)}
    if not counts:
        print(out[-3000:], file=sys.stderr)
        raise SystemExit("lldb reported no breakpoints — see output above")

    # One connection's worth of setup runs before the workload does
    # anything, so counts are reported per connection and per request
    # using what the workload actually asked for.
    conns, reqs = (args.requests, args.requests * 6) \
        if args.workload == "pageload" else \
        (args.requests, args.requests) if args.workload == "handshake" \
        else (1, args.requests)

    print(f"\n── call counts: {args.workload} "
          f"({conns} connection(s), {reqs} request(s), "
          f"{time.time() - started:.0f}s under lldb) ──\n")
    print(f"  {'calls':>9} {'per conn':>10} {'per req':>10}  function")
    for name, hits in sorted(counts.items(), key=lambda kv: -kv[1]):
        if not hits:
            continue
        print(f"  {hits:>9} {hits / conns:>10.1f} {hits / reqs:>10.2f}  {name}")
    zero = [n for n, h in counts.items() if h == 0]
    if zero:
        print(f"\n  never called: {', '.join(sorted(zero))}")

    if args.json:
        args.json.write_text(json.dumps(
            {"workload": args.workload, "connections": conns,
             "requests": reqs, "counts": counts}, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
