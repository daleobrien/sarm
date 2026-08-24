"""AES-GCM CTR length-sweep vector generator (tests/unit/test_gcm/encrypt.c).

src/crypto/gcm/encrypt.S generates the CTR keystream four blocks at a time.
Correctness therefore depends on two things the NIST SP 800-38D vectors
barely exercise: how many leftover full blocks (0-3) follow the last
complete group of four, and how many bytes are in the partial trailing
block. This script emits vectors covering that grid.

Nothing here is trusted without being checked first:

  * ``unrolled_seq`` models the counter sequencing the assembly performs --
    the 12-byte IV invariant in a register, the 32-bit big-endian counter
    written into lane 3, the +1/+2/+3 offsets within a group -- and
    ``check_counter_model`` proves it agrees block-for-block with the
    memory-based ``gcm_inc32`` sequence it replaced. That includes the
    2^32 wraparound, which is *why* those offsets must be 32-bit ``add w``
    and not ``add x``: the wrap is the only place the two would diverge.

  * ``seal`` builds ciphertext and tag on top of that counter sequence,
    and ``self_test`` checks the pair against OpenSSL's own GCM (via the
    python ``cryptography`` package) for every plaintext length 0..300
    plus random keys, IVs, AAD and lengths.

Only after both pass are the C literals written, so no expected value is
ever hand-transcribed from a scratch calculation.

Usage::

    python3 scripts/gcm_ctr_sweep_derivation.py --self-test
    python3 scripts/gcm_ctr_sweep_derivation.py          # emit the C block
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

M32 = 0xFFFFFFFF


# ── the counter sequence, both ways ──────────────────────────────────────

def current_seq(iv12, nblocks, start_ctr=1):
    """The memory-based jbuf + gcm_inc32 sequence encrypt.S used to run."""
    jbuf = bytearray(iv12 + start_ctr.to_bytes(4, "big"))

    def inc32(buf):
        c = (int.from_bytes(buf[12:16], "big") + 1) & M32
        buf[12:16] = c.to_bytes(4, "big")

    j0 = bytes(jbuf)
    inc32(jbuf)
    blocks = []
    for _ in range(nblocks):
        blocks.append(bytes(jbuf))
        inc32(jbuf)
    return j0, blocks, bytes(jbuf)


def unrolled_seq(iv12, nblocks, start_ctr=1):
    """The register-based sequence encrypt.S runs now, four at a time."""
    j0 = iv12 + (start_ctr & M32).to_bytes(4, "big")

    def block(ctr):
        return iv12 + (ctr & M32).to_bytes(4, "big")

    ctr = (start_ctr + 1) & M32
    blocks = []
    groups, rem = divmod(nblocks, 4)
    for _ in range(groups):
        blocks += [block(ctr + k) for k in range(4)]
        ctr = (ctr + 4) & M32
    for _ in range(rem):
        blocks.append(block(ctr))
        ctr = (ctr + 1) & M32
    return j0, blocks, block(ctr)


def check_counter_model(verbose=False):
    """The two sequences must agree byte-for-byte, wraparound included."""
    iv = bytes(range(12))
    fails = 0
    for n in range(0, 200):
        if current_seq(iv, n) != unrolled_seq(iv, n):
            fails += 1
    # start the counter just below 2^32 so the wrap lands at every possible
    # offset inside a four-block group
    for off in range(8):
        sc = (M32 - off) & M32
        for n in range(0, 40):
            if current_seq(iv, n, sc) != unrolled_seq(iv, n, sc):
                fails += 1
                if verbose:
                    print(f"  wrap mismatch start=0x{sc:08x} n={n}")
    for _ in range(2000):
        iv_r, n = os.urandom(12), os.urandom(1)[0]
        sc = int.from_bytes(os.urandom(4), "big")
        if current_seq(iv_r, n, sc) != unrolled_seq(iv_r, n, sc):
            fails += 1
    return fails


# ── GCM on top of that sequence ──────────────────────────────────────────

def ek(key, block):
    """One AES block encryption. Comes from OpenSSL: the block cipher is
    not what this is checking, the counter sequencing around it is."""
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def ghash(h, data):
    y, hi = 0, int.from_bytes(h, "big")
    for i in range(0, len(data), 16):
        y ^= int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big")
        z, v = 0, y
        for bit in range(127, -1, -1):
            if (hi >> bit) & 1:
                z ^= v
            v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
        y = z
    return y.to_bytes(16, "big")


def seal(key, iv12, aad, pt):
    """AES-128-GCM seal, structured exactly as the rewritten encrypt.S."""
    nblocks, rem = divmod(len(pt), 16)
    j0, blocks, tail_block = unrolled_seq(iv12, nblocks)

    ct = bytearray()
    for i, cb in enumerate(blocks):
        ks = ek(key, cb)
        ct += bytes(a ^ b for a, b in zip(pt[i * 16:(i + 1) * 16], ks))
    if rem:
        ks = ek(key, tail_block)
        ct += bytes(a ^ b for a, b in zip(pt[nblocks * 16:], ks[:rem]))
    ct = bytes(ct)

    pad = lambda b: b + b"\0" * ((-len(b)) % 16)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(pt) * 8).to_bytes(8, "big")
    y = ghash(ek(key, b"\0" * 16), pad(aad) + pad(ct) + lens)
    return ct, bytes(a ^ b for a, b in zip(y, ek(key, j0)))


def openssl_seal(key, iv12, aad, pt):
    e = Cipher(algorithms.AES(key), modes.GCM(iv12)).encryptor()
    e.authenticate_additional_data(aad)
    return e.update(pt) + e.finalize(), e.tag


def self_test(verbose=False):
    fails = 0
    key, iv = bytes(range(16)), bytes(range(16, 28))
    for n in range(0, 301):
        pt = bytes((i * 7 + 3) & 0xFF for i in range(n))
        aad = bytes((i * 11) & 0xFF for i in range(n % 37))
        if seal(key, iv, aad, pt) != openssl_seal(key, iv, aad, pt):
            fails += 1
            if verbose:
                print(f"  seal mismatch at len={n}")
    for _ in range(400):
        k, v = os.urandom(16), os.urandom(12)
        pt = os.urandom(os.urandom(1)[0])
        aad = os.urandom(os.urandom(1)[0] % 64)
        if seal(k, v, aad, pt) != openssl_seal(k, v, aad, pt):
            fails += 1
    return fails


# ── emit ─────────────────────────────────────────────────────────────────

# 0-3 leftover full blocks crossed with an empty and a non-empty tail, plus
# the boundaries either side of the first complete group of four.
LENGTHS = [0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65,
           79, 80, 95, 96, 112, 127, 128, 129, 160, 176, 191, 192]

KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
IV = bytes.fromhex("cafebabefacedbaddecaf888")


def carr(name, b):
    if not b:
        return f"static const uint8_t {name}[1] = {{ 0 }};  // len 0, unused"
    lines, cur = [], "    "
    for x in b:
        tok = f"0x{x:02x},"
        if len(cur) + len(tok) > 74:
            lines.append(cur.rstrip())
            cur = "    "
        cur += tok + " "
    lines.append(cur.rstrip().rstrip(","))
    return (f"static const uint8_t {name}[{len(b)}] = {{\n"
            + "\n".join(lines) + "\n};")


def emit():
    out = [
        "// ── CTR length sweep ─────────────────────────────────────────────────",
        "// Generated by scripts/gcm_ctr_sweep_derivation.py -- do not hand-edit.",
        "//",
        "// The NIST vectors above cover plaintext lengths 0, 16, 60 and 64 only.",
        "// encrypt.S runs the CTR keystream four blocks at a time, so correctness",
        "// turns on the number of leftover full blocks (0-3) after the last",
        "// complete group and on the partial-tail size, independently. These",
        "// lengths cover that grid. Expected values come from a reference",
        "// cross-checked against OpenSSL for every length 0..300.",
        "",
        carr("SWEEP_KEY", KEY),
        carr("SWEEP_IV", IV),
        "",
    ]
    for n in LENGTHS:
        pt = bytes((i * 7 + 3) & 0xFF for i in range(n))
        aad = bytes((i * 11) & 0xFF for i in range(n % 37))
        ct, tag = seal(KEY, IV, aad, pt)
        assert (ct, tag) == openssl_seal(KEY, IV, aad, pt), f"ref differs at {n}"
        for suffix, data in (("AAD", aad), ("PT", pt), ("CT", ct), ("TAG", tag)):
            out.append(carr(f"SW{n}_{suffix}", data))
        out.append("")

    out += [
        "struct sweep_vec {",
        "    const char *name;",
        "    const uint8_t *aad; uint64_t aad_len;",
        "    const uint8_t *pt;  uint64_t pt_len;",
        "    const uint8_t *ct;  const uint8_t *tag;",
        "};",
        "",
        "static const struct sweep_vec SWEEP[] = {",
    ]
    for n in LENGTHS:
        out.append(f'    {{ "len={n}", SW{n}_AAD, {n % 37}, SW{n}_PT, {n}, '
                   f"SW{n}_CT, SW{n}_TAG }},")
    out.append("};")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--self-test", action="store_true",
                    help="check the counter model and the GCM reference, emit nothing")
    args = ap.parse_args()

    cfails = check_counter_model(verbose=True)
    print(f"counter model vs gcm_inc32 : "
          f"{'FAIL' if cfails else 'OK'} ({cfails} mismatches)", file=sys.stderr)
    sfails = self_test(verbose=True)
    print(f"seal vs OpenSSL GCM        : "
          f"{'FAIL' if sfails else 'OK'} ({sfails} mismatches)", file=sys.stderr)
    if cfails or sfails:
        raise SystemExit(1)
    if not args.self_test:
        print(emit())


if __name__ == "__main__":
    main()
