#!/usr/bin/env python3
"""P-256 fixed-base comb: derivation, precomputed table, and a
hardware-faithful reference implementation.

This is the generator behind `p256_point_mul_base`
(src/crypto/p256_point/mul_base.S), `p256_point_add_affine`
(src/crypto/p256_point/add_affine.S) and the precomputed table
(src/crypto/p256_point/comb_table.S).

The algorithm is a 4-bit fixed-base comb. The scalar k is read as 64
little-endian nibbles; nibble i (value d, weight 2^(4i)) contributes
d * 2^(4i) * G, which is read straight out of a precomputed table
rather than built by doubling. So a scalar multiplication by the
*generator* costs 64 point additions and **zero** doublings, against
the 256 doublings + 256 additions of the generic double-and-add in
src/crypto/p256_point/mul.S.

Two properties are what make this safe, and both are proved in
`prove` below rather than assumed:

  1. Every addition in the loop is a genuine, generic addition -- the
     accumulator is never equal to +-the table point -- so the cheap
     8M+3S mixed-addition formula (no doubling fallback, no
     equal-point correction) is always the right answer. This is what
     lets `p256_point_add_affine` be 11 field multiplies where the
     general-purpose `p256_point_add` is ~26.
  2. The only case that needs masking is the accumulator still being
     the point at infinity (leading zero nibbles), and that is handled
     by a cmov on a flag derived from Z == 0, not by a branch.

Usage:
    python3 scripts/p256_comb_derivation.py prove          # the two structural proofs above
    python3 scripts/p256_comb_derivation.py check [N]      # N random scalars + edge cases,
                                                           #   comb vs. oracle (default 2000)
    python3 scripts/p256_comb_derivation.py interop [N]    # N scalars vs. the `cryptography`
                                                           #   package (OpenSSL) (default 500)
    python3 scripts/p256_comb_derivation.py gen-table > src/crypto/p256_point/comb_table.S
    python3 scripts/p256_comb_derivation.py gen-test-madd  > tests/unit/test_p256_point/add_affine.c
    python3 scripts/p256_comb_derivation.py gen-test-mulb  > tests/unit/test_p256_point/mul_base.c
"""
import random
import sys

# ── curve parameters (FIPS 186-4, P-256) ─────────────────────────────────
P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = -3 % P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

W = 4                       # comb window, in bits
BLOCKS = 256 // W           # 64 nibbles
ENTRIES = (1 << W) - 1      # 15 stored points per block (digit 0 is implicit)


# ── affine arithmetic, the mathematical oracle ───────────────────────────
# Plain textbook formulas over Python big integers. `None` is infinity.
# Nothing here is what the assembly does; it exists so that the
# hardware-faithful code below has something independent to be wrong
# against.
def aff_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def aff_mul(k, p):
    """Textbook left-to-right double-and-add. The oracle."""
    r = None
    for i in reversed(range(k.bit_length())):
        r = aff_add(r, r)
        if (k >> i) & 1:
            r = aff_add(r, p)
    return r


def on_curve(p):
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + A * x + B)) % P == 0


G = (GX, GY)


# ── the precomputed table ────────────────────────────────────────────────
def build_table():
    """table[i][j-1] = (j * 2^(4i)) * G, affine.

    Built by repeated doubling of the block base rather than by 960
    independent scalar multiplications: base_{i+1} = 16 * base_i.
    Every entry is checked against the oracle's aff_mul, so the cheap
    construction cannot silently drift.
    """
    table = []
    base = G
    for i in range(BLOCKS):
        row = []
        acc = None
        for _ in range(ENTRIES):
            acc = aff_add(acc, base)
            row.append(acc)
        table.append(row)
        for _ in range(W):
            base = aff_add(base, base)
    return table


def verify_table(table):
    """Independent re-derivation of every one of the 960 entries."""
    for i in range(BLOCKS):
        for j in range(1, ENTRIES + 1):
            want = aff_mul(j << (W * i), G)
            got = table[i][j - 1]
            assert got == want, f"table[{i}][{j}] mismatch"
            assert on_curve(got), f"table[{i}][{j}] off curve"
    return BLOCKS * ENTRIES


# ── hardware-faithful reference ──────────────────────────────────────────
# From here down the code is structurally what the assembly does: the
# same Jacobian representation, the same mixed-addition formula in the
# same order, the same cmov masking. If this is right and the port is
# faithful, the assembly is right.
def madd(p1, x2, y2):
    """Jacobian + affine addition, 8M + 3S. Exactly the sequence
    p256_point_add_affine executes, and exactly src/crypto/p256_point/
    add.S with Z2 = 1 substituted (Z2Z2 = 1, Z2cubed = 1, so U1 = X1,
    S1 = Y1, and Z3 = H*Z1 rather than H*Z1*Z2).

    PRECONDITIONS -- the caller must guarantee these; this formula does
    not check them and returns garbage if they are violated:
      * (x2, y2) is a finite point (never infinity),
      * P1 != +-(x2, y2), i.e. H != 0.
    P1 == infinity (Z1 == 0) is *not* a precondition violation in the
    sense of producing a wrong value silently -- it produces Z3 = 0 and
    a meaningless X3/Y3 -- but the caller must cmov the real answer in,
    which is what mul_base does.
    """
    x1, y1, z1 = p1
    z1z1 = z1 * z1 % P                    # S
    u2 = x2 * z1z1 % P                    # M
    z1cubed = z1 * z1z1 % P               # M
    s2 = y2 * z1cubed % P                 # M
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    hh = h * h % P                        # S
    hhh = h * hh % P                      # M
    v = x1 * hh % P                       # M
    x3 = (r * r - hhh - 2 * v) % P        # S
    y3 = (r * ((v - x3) % P) - y1 * hhh) % P   # 2M
    z3 = h * z1 % P                       # M
    return (x3, y3, z3)


def to_affine(p):
    """Jacobian -> affine, matching p256_point_to_affine: inversion is
    by Fermat, so 0^-1 == 0 and an infinity input maps to (0, 0)."""
    x, y, z = p
    if z % P == 0:
        return (0, 0)
    zinv = pow(z, P - 2, P)
    zinv2 = zinv * zinv % P
    return (x * zinv2 % P, y * zinv2 % P * zinv % P)


def comb_mul_base(k, table):
    """k*G by the 4-bit comb -- the exact shape of p256_point_mul_base.

    k is a raw 256-bit value (NOT reduced mod n first); this matches
    p256_point_mul's documented contract, and matters because
    p256_ecdsa_sign_with_k feeds it the nonce straight from
    p256_fe_frombytes.
    """
    rx, ry, rz = 0, 0, 0                 # accumulator = infinity
    for i in range(BLOCKS):
        d = (k >> (W * i)) & 0xF

        # constant-time select: read all ENTRIES rows, keep the one
        # whose index matches. d == 0 leaves (ax, ay) == (0, 0).
        ax = ay = 0
        for j in range(1, ENTRIES + 1):
            mask = -1 if j == d else 0
            ax |= table[i][j - 1][0] & mask
            ay |= table[i][j - 1][1] & mask

        cand = madd((rx, ry, rz), ax, ay)

        r_is_inf = 1 if rz == 0 else 0
        d_is_zero = 1 if d == 0 else 0

        # R = d == 0        ? R
        #   : R is infinity ? (ax, ay, 1)
        #   :                 cand
        nx, ny, nz = cand
        if r_is_inf:
            nx, ny, nz = ax, ay, 1
        if d_is_zero:
            nx, ny, nz = rx, ry, rz
        rx, ry, rz = nx, ny, nz
    return to_affine((rx, ry, rz))


# ── proofs of the two structural preconditions ───────────────────────────
def prove():
    """The mixed-add formula has no doubling/negation fallback, so the
    loop must never present it with R == +-A. Prove it, don't sample it.

    At the start of block i+1 the accumulator holds L*G where L is the
    integer formed by nibbles 0..i of k, so 0 <= L < 2^(4(i+1)), and the
    addend is M*G with M = d*2^(4(i+1)), 1 <= d <= 15 (d == 0 is masked
    out and never reaches the formula).

      R == A   <=>  L == M (mod n).  L < 2^(4(i+1)) <= M, so 0 < M - L.
                    M <= 15*2^252 < n, so 0 < M - L < n: never congruent.

      R == -A  <=>  L + M == 0 (mod n).  L + M is exactly the integer
                    formed by nibbles 0..i+1 of k, so 0 <= L+M < 2^(4(i+2))
                    and L+M > 0 (since d >= 1). For L+M == n we need
                    L+M >= n > 2^255, so 4(i+2) > 255, i.e. i+2 == 64:
                    only the very last block, and only when k == n
                    exactly. k == n means k*G is genuinely infinity; the
                    formula then yields Z3 == 0 and to_affine gives
                    (0, 0), which is what the generic path produces too
                    and what p256_ecdsa_sign_with_k's r == 0 check
                    rejects.
    """
    max_addend = ENTRIES << (W * (BLOCKS - 1))
    assert max_addend < N, "top-block addend must stay below n"
    print(f"  max addend  15*2^252 = {max_addend:#x}")
    print(f"  n                    = {N:#x}")
    print(f"  15*2^252 < n         : {max_addend < N}  -> R == A impossible")

    # R == -A needs the low (i+2) nibbles of k to equal n. n's low
    # 4(i+2) bits can only *be* n when 4(i+2) >= n.bit_length().
    smallest = min(i for i in range(BLOCKS) if (1 << (W * (i + 1))) > N)
    print(f"  first block where L+M can reach n: {smallest} of {BLOCKS - 1}"
          f"  -> only k == n, whose true product is infinity")
    assert smallest == BLOCKS - 1

    # And the masking claim: digit 0 never reaches madd.
    print("  digit 0 is cmov-masked, so the addend is never infinity")

    # Belt and braces: run the loop with an instrumented madd that
    # records every H == 0 -- i.e. every time the accumulator and the
    # addend share an x-coordinate, which is the *only* way the mixed
    # formula can be wrong -- over adversarial scalars. The argument
    # above says the only such case in the whole 2^256 scalar space is
    # k == 0 (mod n), so that is asserted rather than excused.
    table = build_table()
    calls = [0]
    violations = []
    real_madd = madd

    def checked_madd(p1, x2, y2, _real=real_madd):
        x1, y1, z1 = p1
        # (0, 0) is the masked-out digit-0 addend, whose result the
        # cmov discards -- the precondition only has to hold for the
        # additions that actually contribute.
        if z1 != 0 and (x2, y2) != (0, 0):
            calls[0] += 1
            if (x2 * z1 * z1 - x1) % P == 0:
                violations.append((x2, y2))
        return _real(p1, x2, y2)

    scalars = [1, 2, 15, 16, 17, N - 1, N, N + 1, 2**256 - 1,
               0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F,
               0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0]
    scalars += [random.getrandbits(256) for _ in range(200)]
    bad = []
    try:
        globals()['madd'] = checked_madd
        for k in scalars:
            del violations[:]
            got = comb_mul_base(k, table)
            if violations:
                # allowed only for k == 0 (mod n), where the true
                # product is the point at infinity anyway
                if k % N != 0 or got != (0, 0):
                    bad.append(k)
    finally:
        globals()['madd'] = real_madd

    assert not bad, f"unexpected H == 0 for {[hex(k) for k in bad]}"
    print(f"  H != 0 confirmed on all {calls[0]} contributing mixed additions over "
          f"{len(scalars)} scalars,")
    print(f"  the sole exception being k == n, whose product is infinity and whose")
    print(f"  comb output is (0, 0) -- identical to the generic path, and rejected")
    print(f"  by p256_ecdsa_sign_with_k's r == 0 check")
    return True


# ── checks ───────────────────────────────────────────────────────────────
EDGE_SCALARS = [
    0, 1, 2, 3, 15, 16, 17, 255, 256,
    N - 1, N, N + 1, N - 2,
    2**255, 2**255 - 1, 2**256 - 1, 2**256 - 2,
    0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F,
    0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0,
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFF0000000000000000000000000000000F,
    (1 << 252) * 15,
]


def oracle_mul_base(k):
    """k*G through the oracle, in the same (0,0)-for-infinity convention
    to_affine uses."""
    if k % N == 0:
        return (0, 0)
    r = aff_mul(k % N, G)
    return r if r is not None else (0, 0)


def check(count):
    table = build_table()
    n_entries = verify_table(table)
    print(f"table: {n_entries} entries re-derived independently and on-curve")

    cases = list(EDGE_SCALARS) + [random.getrandbits(256) for _ in range(count)]
    # a few short scalars too -- these are the ones with many leading
    # zero nibbles, i.e. the ones that exercise the infinity masking
    cases += [random.getrandbits(b) for b in (1, 4, 5, 8, 63, 64, 65, 128) for _ in range(4)]
    bad = 0
    for k in cases:
        got = comb_mul_base(k, table)
        want = oracle_mul_base(k)
        if got != want:
            bad += 1
            print(f"MISMATCH k={k:#x}\n  got  {got}\n  want {want}")
    print(f"comb vs oracle: {len(cases) - bad}/{len(cases)} agree")
    return bad == 0


def interop(count):
    """Cross-check against an independent, audited implementation."""
    from cryptography.hazmat.primitives.asymmetric import ec

    table = build_table()
    bad = 0
    ks = [1, 2, 3, N - 1, 0x1234567890ABCDEF]
    ks += [random.randrange(1, N) for _ in range(count)]
    for k in ks:
        pub = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
        got = comb_mul_base(k, table)
        if got != (pub.x, pub.y):
            bad += 1
            print(f"INTEROP MISMATCH k={k:#x}")
    print(f"comb vs `cryptography` (OpenSSL): {len(ks) - bad}/{len(ks)} agree")
    return bad == 0


# ── emitters ─────────────────────────────────────────────────────────────
def limbs(v):
    return [(v >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(4)]


def gen_table():
    table = build_table()
    verify_table(table)
    out = []
    out.append("// P-256 fixed-base comb table -- GENERATED, do not edit by hand.")
    out.append("//")
    out.append("// Regenerate with:")
    out.append("//   python3 scripts/p256_comb_derivation.py gen-table \\")
    out.append("//       > src/crypto/p256_point/comb_table.S")
    out.append("//")
    out.append(f"// {BLOCKS} blocks x {ENTRIES} entries. Entry [i][j-1] is the affine point")
    out.append(f"// (j * 2^({W}*i)) * G, stored as x[4] then y[4], 4x64-bit little-endian")
    out.append("// limbs each -- the same field-element layout p256_fe_frombytes")
    out.append("// produces and p256_point_add_affine consumes.")
    out.append("//")
    out.append(f"// Stride: {ENTRIES * 64} bytes per block, {ENTRIES * 64 * BLOCKS} bytes total.")
    out.append("// Every entry was re-derived from the oracle (scripts/")
    out.append("// p256_comb_derivation.py, `check`) before emission.")
    out.append("")
    out.append('#include "../../defs.S"')
    out.append("")
    out.append(".data")
    out.append(".align 4")
    out.append(".global p256_comb_table")
    out.append("p256_comb_table:")
    for i in range(BLOCKS):
        out.append(f"    // block {i}: multiples of 2^{W * i} * G")
        for j in range(1, ENTRIES + 1):
            x, y = table[i][j - 1]
            out.append(f"    // [{i}][{j}]")
            for lb in limbs(x):
                out.append(f"    .quad 0x{lb:016x}")
            for lb in limbs(y):
                out.append(f"    .quad 0x{lb:016x}")
    return "\n".join(out) + "\n"


def c_limbs(name, v, indent="    "):
    ls = limbs(v)
    return (f"{indent}{{{', '.join(f'0x{x:016x}ULL' for x in ls)}}}")


def gen_test_madd():
    """Vectors for p256_point_add_affine: Jacobian P1 + affine P2, with
    P1 in genuinely non-normalized Jacobian form (random Z), which is
    what the comb loop actually feeds it."""
    rnd = random.Random(20260818)
    rows = []
    while len(rows) < 24:
        k1 = rnd.randrange(1, N)
        k2 = rnd.randrange(1, N)
        p1a = aff_mul(k1, G)
        p2a = aff_mul(k2, G)
        if p1a[0] == p2a[0]:
            continue
        z = 1 if not rows else rnd.randrange(1, P)
        # affine (x, y) -> the same point in Jacobian form with this Z
        p1 = (p1a[0] * z % P * z % P, p1a[1] * z % P * z % P * z % P, z)
        got = madd(p1, p2a[0], p2a[1])
        assert to_affine(got) == aff_add(p1a, p2a), "madd disagrees with the oracle"
        rows.append((p1, p2a, got))

    def flat(cs):
        return ", ".join(f"0x{v:016x}ULL" for c in cs for v in limbs(c))

    out = []
    out.append("// Unit tests for src/crypto/p256_point/add_affine.S")
    out.append("//")
    out.append("// GENERATED by scripts/p256_comb_derivation.py gen-test-madd.")
    out.append("// Do not hand-edit: every expected value below came from the same")
    out.append("// validated Python reference the assembly was ported from, and")
    out.append("// each was independently checked against the affine oracle")
    out.append("// (to_affine(madd(...)) == aff_add(...)) before emission.")
    out.append("//")
    out.append("// P1 is deliberately in non-normalized Jacobian form (random Z),")
    out.append("// which is what p256_point_mul_base's accumulator actually is;")
    out.append("// a formula that only handled Z == 1 would pass a naive test.")
    out.append("")
    out.append('#include "test_harness.h"')
    out.append("")
    out.append("extern void p256_point_add_affine(uint64_t out[12], const uint64_t p1[12],")
    out.append("                                  const uint64_t aff[8])")
    out.append('    __asm__("p256_point_add_affine");')
    out.append("")
    out.append("struct madd_vec {")
    out.append("    uint64_t p1[12];")
    out.append("    uint64_t aff[8];")
    out.append("    uint64_t want[12];")
    out.append("};")
    out.append("")
    out.append(f"#define NMADD {len(rows)}")
    out.append("static const struct madd_vec VECS[NMADD] = {")
    for p1, p2, want in rows:
        out.append("    {")
        out.append("        {" + flat(p1) + "},")
        out.append("        {" + flat(p2) + "},")
        out.append("        {" + flat(want) + "},")
        out.append("    },")
    out.append("};")
    out.append("")
    out.append("static int eq12(const uint64_t a[12], const uint64_t b[12]) {")
    out.append("    for (int i = 0; i < 12; i++)")
    out.append("        if (a[i] != b[i])")
    out.append("            return 0;")
    out.append("    return 1;")
    out.append("}")
    out.append("")
    out.append("int main(void) {")
    out.append('    TEST_SUITE("p256_point_add_affine");')
    out.append("")
    out.append("    for (int i = 0; i < NMADD; i++) {")
    out.append("        uint64_t out[12];")
    out.append("        p256_point_add_affine(out, VECS[i].p1, VECS[i].aff);")
    out.append('        ASSERT_EQ("Jacobian + affine matches reference", 1,')
    out.append("                  eq12(out, VECS[i].want));")
    out.append("    }")
    out.append("")
    out.append("    // out aliasing p1 must work: mul_base adds into its accumulator")
    out.append("    // in place.")
    out.append("    {")
    out.append("        uint64_t buf[12];")
    out.append("        for (int i = 0; i < 12; i++)")
    out.append("            buf[i] = VECS[0].p1[i];")
    out.append("        p256_point_add_affine(buf, buf, VECS[0].aff);")
    out.append('        ASSERT_EQ("out aliasing p1 matches reference", 1,')
    out.append("                  eq12(buf, VECS[0].want));")
    out.append("    }")
    out.append("")
    out.append("    test_summary();")
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out) + "\n"


def gen_test_mulb():
    rnd = random.Random(20260819)
    table = build_table()
    ks = [0, 1, 2, 15, 16, 17, 255, N - 1, N, 2**256 - 1,
          0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F,
          0xF0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0]
    ks += [rnd.randrange(1, N) for _ in range(12)]
    ks += [rnd.getrandbits(b) for b in (4, 8, 64, 200)]
    rows = []
    for k in ks:
        got = comb_mul_base(k, table)
        assert got == oracle_mul_base(k), f"comb disagrees with the oracle at k={k:#x}"
        rows.append((k, got))

    out = []
    out.append("// Unit tests for src/crypto/p256_point/mul_base.S")
    out.append("//")
    out.append("// GENERATED by scripts/p256_comb_derivation.py gen-test-mulb.")
    out.append("// Do not hand-edit. Every expected value was produced by the")
    out.append("// hardware-faithful Python reference and independently checked")
    out.append("// against the textbook affine double-and-add oracle, which is in")
    out.append("// turn cross-checked against the `cryptography` package (OpenSSL)")
    out.append("// by `p256_comb_derivation.py interop`.")
    out.append("//")
    out.append("// Includes the cases only the comb has: k = 0 and k = n (product")
    out.append("// is infinity -> (0,0)), scalars with many leading zero nibbles")
    out.append("// (the infinity-masking path), and k >= n unreduced -- which is")
    out.append("// what p256_ecdsa_sign_with_k actually passes, since it feeds the")
    out.append("// nonce straight from p256_fe_frombytes.")
    out.append("")
    out.append('#include "test_harness.h"')
    out.append("")
    out.append("extern void p256_point_mul_base(uint64_t outx[4], uint64_t outy[4],")
    out.append("                                const uint64_t k[4])")
    out.append('    __asm__("p256_point_mul_base");')
    out.append("extern void p256_point_mul(uint64_t outx[4], uint64_t outy[4],")
    out.append("                           const uint64_t k[4], const uint64_t inx[4],")
    out.append("                           const uint64_t iny[4])")
    out.append('    __asm__("p256_point_mul");')
    out.append("")
    out.append("static const uint64_t GX[4] = {" + ", ".join(f"0x{v:016x}ULL" for v in limbs(GX)) + "};")
    out.append("static const uint64_t GY[4] = {" + ", ".join(f"0x{v:016x}ULL" for v in limbs(GY)) + "};")
    out.append("")
    out.append("struct mulb_vec {")
    out.append("    uint64_t k[4];")
    out.append("    uint64_t x[4];")
    out.append("    uint64_t y[4];")
    out.append("};")
    out.append("")
    out.append(f"#define NMULB {len(rows)}")
    out.append("static const struct mulb_vec VECS[NMULB] = {")
    for k, (x, y) in rows:
        out.append("    {")
        out.append("        {" + ", ".join(f"0x{v:016x}ULL" for v in limbs(k)) + "},")
        out.append("        {" + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + "},")
        out.append("        {" + ", ".join(f"0x{v:016x}ULL" for v in limbs(y)) + "},")
        out.append("    },")
    out.append("};")
    out.append("")
    out.append("static int eq4(const uint64_t a[4], const uint64_t b[4]) {")
    out.append("    for (int i = 0; i < 4; i++)")
    out.append("        if (a[i] != b[i])")
    out.append("            return 0;")
    out.append("    return 1;")
    out.append("}")
    out.append("")
    out.append("int main(void) {")
    out.append('    TEST_SUITE("p256_point_mul_base — k*G against the validated reference");')
    out.append("")
    out.append("    for (int i = 0; i < NMULB; i++) {")
    out.append("        uint64_t x[4], y[4];")
    out.append("        p256_point_mul_base(x, y, VECS[i].k);")
    out.append('        ASSERT_EQ("k*G x matches reference", 1, eq4(x, VECS[i].x));')
    out.append('        ASSERT_EQ("k*G y matches reference", 1, eq4(y, VECS[i].y));')
    out.append("    }")
    out.append("")
    out.append('    TEST_SUITE("p256_point_mul_base — agrees with generic p256_point_mul");')
    out.append("")
    out.append("    for (int i = 0; i < NMULB; i++) {")
    out.append("        uint64_t bx[4], by[4], gx[4], gy[4];")
    out.append("        p256_point_mul_base(bx, by, VECS[i].k);")
    out.append("        p256_point_mul(gx, gy, VECS[i].k, GX, GY);")
    out.append('        ASSERT_EQ("comb x == double-and-add x", 1, eq4(bx, gx));')
    out.append('        ASSERT_EQ("comb y == double-and-add y", 1, eq4(by, gy));')
    out.append("    }")
    out.append("")
    out.append("    test_summary();")
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out) + "\n"


# ── main ─────────────────────────────────────────────────────────────────
def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 else None
    if cmd == "prove":
        ok = prove()
    elif cmd == "check":
        ok = check(arg if arg is not None else 2000)
    elif cmd == "interop":
        ok = interop(arg if arg is not None else 500)
    elif cmd == "gen-table":
        sys.stdout.write(gen_table())
        return 0
    elif cmd == "gen-test-madd":
        sys.stdout.write(gen_test_madd())
        return 0
    elif cmd == "gen-test-mulb":
        sys.stdout.write(gen_test_mulb())
        return 0
    else:
        print(__doc__)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
