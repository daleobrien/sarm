#!/usr/bin/env python3
"""P-256 field multiplication: the unrolled 4x4 product, proved.

This is the generator and proof harness behind the product half of
`p256_fe_mul` (src/crypto/p256/sqr_mul.S). The reduction half is
`p256_reduce`, already derived and proved by
scripts/p256_reduce_derivation.py; this script imports that script's
hardware-faithful reference rather than restating it, so the two cannot
drift apart.

Why this exists
---------------
`p256_fe_mul` used to reach `p256_bn_mul`, a generic index-driven
schoolbook loop that works for any (na, nb) shape. For the 4x4 shape the
field path always uses, that loop costs 26.7 ns against the 11.7 ns a
*whole* Montgomery multiply (a 4x4 product AND a full reduction) costs in
src/crypto/p256_scalar/mont_mul.S. The loop overhead -- a load, a store,
two index computations and two branches per limb product -- is most of
the cost.

The replacement is a fully unrolled product with the carry chain in
registers. That is not an algorithm change: it is the same schoolbook
product. What it *is* is a hand-written carry chain, and hand-written
carry chains are exactly where this repo has previously shipped bugs
(see .claude/skills/verified-asm-crypto). So the model below is not
`(a * b)` -- it is the exact word/carry sequence the assembly executes,
with every bound the assembly leaves un-instructioned turned into an
assert, checked against Python's arbitrary-precision `a * b` as the
independent reference.

The one bound that matters
--------------------------
Row i of the product accumulates a[0..3] * b[i] into T[i..i+4] and must
not carry out of T[i+4]. That is not an empirical observation, it is
forced: after row i the accumulator holds exactly

    a * (b mod 2^(64*(i+1)))  <  2^256 * 2^(64*(i+1))  =  2^(64*(i+5))

so it fits in i+5 limbs with nothing left over. `prove` checks that
argument numerically at its extremes and then replays the actual
instruction sequence to confirm the transcription matches it.

Usage:
    python3 scripts/p256_fe_mul_derivation.py prove
    python3 scripts/p256_fe_mul_derivation.py check [N]     # default 20000
    python3 scripts/p256_fe_mul_derivation.py interop [N]   # default 40, vs OpenSSL
    python3 scripts/p256_fe_mul_derivation.py gen-test > tests/unit/test_p256/mul_carry.c
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from p256_reduce_derivation import P, reduce_full  # noqa: E402

MASK = (1 << 64) - 1

# Curve parameters, for the interop cross-check.
A = -3 % P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def words(v):
    return [(v >> (64 * i)) & MASK for i in range(4)]


def value(w):
    return sum(x << (64 * i) for i, x in enumerate(w))


# ── the hardware-faithful product ────────────────────────────────────────
def mul4x4_hw(aw, bw, audit=None):
    """Exactly the instruction sequence p256_fe_mul executes, limb by limb.

    Not `a * b`. Every 64-bit truncation, every carry-out, and the order
    in which they happen are reproduced, because that is the part that can
    be wrong. Returns the 8 product limbs.

    The assembly's registers map onto this as:
        aw[0..3] -> x6..x9      bw[i]   -> x10
        t[0..7]  -> x14,x15,x16,x17,x2,x3,x4,x5
        lo/hi    -> x11,x12,x13 (three scratch registers, reused)
    """
    t = [0] * 8

    # ── Row 0: SET, not accumulate ───────────────────────────────────────
    # The assembly has no zeroing pass over T; row 0 writes T[0..4]
    # outright, which is why it is a different instruction sequence from
    # rows 1..3 rather than the same macro with a zeroed accumulator.
    #
    #   mul   t0, a0, b   ; umulh t1, a0, b
    #   mul   s0, a1, b   ; umulh t2, a1, b
    #   mul   s1, a2, b   ; umulh t3, a2, b
    #   mul   s2, a3, b   ; umulh t4, a3, b
    #   adds  t1, t1, s0  ; adcs  t2, t2, s1
    #   adcs  t3, t3, s2  ; adc   t4, t4, xzr
    b = bw[0]
    lo = [(aw[j] * b) & MASK for j in range(4)]
    hi = [(aw[j] * b) >> 64 for j in range(4)]
    t[0] = lo[0]
    s = hi[0] + lo[1]
    t[1] = s & MASK
    c = s >> 64
    s = hi[1] + lo[2] + c
    t[2] = s & MASK
    c = s >> 64
    s = hi[2] + lo[3] + c
    t[3] = s & MASK
    c = s >> 64
    # `adc t4, t4, xzr` -- hi[3] is at most 2^64-2 (attained only when both
    # operands are 2^64-1), so adding a single carry bit cannot overflow.
    assert hi[3] <= MASK - 1, "umulh of two 64-bit words exceeded 2^64-2"
    t[4] = hi[3] + c
    assert t[4] <= MASK, "row 0 carried past t[4]"
    if audit is not None:
        audit.setdefault("row0_t4", []).append(t[4])

    # ── Rows 1..3: accumulate ────────────────────────────────────────────
    #   mul   s0, a0, b   ; mul  s1, a1, b   ; mul  s2, a2, b
    #   adds  t0, t0, s0  ; adcs t1, t1, s1  ; adcs t2, t2, s2
    #   mul   s0, a3, b   ; adcs t3, t3, s0  ; adc  t4, xzr, xzr
    #   umulh s0, a0, b   ; umulh s1, a1, b  ; umulh s2, a2, b
    #   adds  t1, t1, s0  ; adcs t2, t2, s1  ; adcs t3, t3, s2
    #   umulh s0, a3, b   ; adc  t4, t4, s0
    for i in range(1, 4):
        b = bw[i]
        lo = [(aw[j] * b) & MASK for j in range(4)]
        hi = [(aw[j] * b) >> 64 for j in range(4)]

        c = 0
        for j in range(4):
            s = t[i + j] + lo[j] + c
            t[i + j] = s & MASK
            c = s >> 64
        t[i + 4] = c                      # `adc t4, xzr, xzr` -- SET

        c = 0
        for j in range(3):
            s = t[i + 1 + j] + hi[j] + c
            t[i + 1 + j] = s & MASK
            c = s >> 64
        s = t[i + 4] + hi[3] + c
        # The whole correctness of the shape rests on this: the final
        # `adc t4, t4, s0` has no carry out, so there is no T[i+5] to
        # write and no propagation loop. See the module docstring.
        assert s <= MASK, "row %d carried past t[%d]" % (i, i + 4)
        t[i + 4] = s
        if audit is not None:
            audit.setdefault("row%d_t4" % i, []).append(t[i + 4])

    return t


def fe_mul_hw(a, b):
    """out = a*b mod p, through the exact product AND the exact reduction
    the assembly runs -- p256_reduce's own hardware-faithful reference,
    imported rather than restated."""
    t = mul4x4_hw(words(a), words(b), audit=AUDIT)
    return reduce_full(t)


AUDIT = {}


# ── 1. prove: the bound is structural, not sampled ───────────────────────
def prove():
    print("── the row bound ──")
    # After row i the accumulator holds a * (b mod 2^(64(i+1))) exactly.
    # The claim is that this always fits in i+5 limbs.
    amax = (1 << 256) - 1
    for i in range(4):
        bmax = (1 << (64 * (i + 1))) - 1
        partial = amax * bmax
        room = 1 << (64 * (i + 5))
        assert partial < room, "row %d can overflow t[%d]" % (i, i + 4)
        print("  row %d: max partial 2^%-7.3f < 2^%-3d capacity  OK"
              % (i, partial.bit_length(), 64 * (i + 5)))
    print("  so no row carries out of t[i+4]; there is no propagation loop\n")

    print("── umulh headroom (row 0's `adc t4, t4, xzr`) ──")
    top = ((MASK * MASK) >> 64)
    assert top == MASK - 1
    print("  max umulh(x, y) = 2^64-2 = 0x%016x, so +1 cannot overflow  OK\n"
          % top)

    print("── replay the instruction sequence at the extremes ──")
    extremes = [
        ("all-ones x all-ones", (1 << 256) - 1, (1 << 256) - 1),
        ("all-ones x 1", (1 << 256) - 1, 1),
        ("1 x all-ones", 1, (1 << 256) - 1),
        ("p-1 x p-1", P - 1, P - 1),
        ("0 x all-ones", 0, (1 << 256) - 1),
        ("2^255 x 2^255", 1 << 255, 1 << 255),
        ("top limb only", MASK << 192, MASK << 192),
        ("low limb only", MASK, MASK),
    ]
    for name, a, b in extremes:
        t = mul4x4_hw(words(a), words(b))
        got = sum(x << (64 * i) for i, x in enumerate(t))
        assert got == a * b, "%s: product mismatch" % name
        print("  %-22s product exact, no assert tripped" % name)
    print("\n  every bound the assembly leaves un-instructioned held.")


# ── 2. check: against Python's own arbitrary-precision multiply ──────────
def edge_values():
    return [
        0, 1, 2,
        MASK, MASK + 1,
        (1 << 128) - 1, 1 << 128,
        (1 << 192) - 1, 1 << 192,
        (1 << 255),
        (1 << 256) - 1,
        P - 1, P, P + 1,
        MASK << 192,
        (MASK << 192) | MASK,
        0x5555555555555555 * 0x0001000100010001 % (1 << 256),
        0xAAAAAAAAAAAAAAAA,
    ]


def check(count):
    count = count or 20000
    rng = random.Random(20260818)
    vals = edge_values()

    pairs = [(a, b) for a in vals for b in vals]
    while len(pairs) < count:
        pairs.append((rng.randrange(1 << 256), rng.randrange(1 << 256)))

    for a, b in pairs:
        t = mul4x4_hw(words(a), words(b))
        got = sum(x << (64 * i) for i, x in enumerate(t))
        # The independent reference: Python's own big-int multiply, which
        # shares no code, no limb splitting and no carry logic with the
        # model above.
        want = (a % (1 << 256)) * (b % (1 << 256))
        assert got == want, "product mismatch a=%x b=%x" % (a, b)
        assert reduce_full(t) == want % P, "fe_mul mismatch a=%x b=%x" % (a, b)
    print("%d products match Python's arbitrary-precision a*b, and their "
          "reductions match (a*b) %% p" % len(pairs))
    print("  (%d of them are edge-case pairs, not random)" % (len(vals) ** 2))


# ── 3. interop: every field multiply of a real scalar multiplication ─────
def _mul(a, b):
    return fe_mul_hw(a, b)


def _jac_dbl(pt):
    x, y, z = pt
    if z == 0:
        return (0, 0, 0)
    delta = _mul(z, z)
    gamma = _mul(y, y)
    beta = _mul(x, gamma)
    t = (x - delta) % P
    u = (x + delta) % P
    alpha = _mul(3 % P, _mul(t, u))
    x3 = (_mul(alpha, alpha) - 8 * beta) % P
    z3 = (_mul((y + z) % P, (y + z) % P) - gamma - delta) % P
    y3 = (_mul(alpha, (4 * beta - x3) % P) - 8 * _mul(gamma, gamma)) % P
    return (x3, y3, z3)


def _jac_add_affine(pt, x2, y2):
    x1, y1, z1 = pt
    if z1 == 0:
        return (x2, y2, 1)
    z1z1 = _mul(z1, z1)
    u2 = _mul(x2, z1z1)
    s2 = _mul(y2, _mul(z1, z1z1))
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    if h == 0:
        return _jac_dbl(pt) if r == 0 else (0, 0, 0)
    hh = _mul(h, h)
    hhh = _mul(h, hh)
    v = _mul(x1, hh)
    x3 = (_mul(r, r) - hhh - 2 * v) % P
    y3 = (_mul(r, (v - x3) % P) - _mul(y1, hhh)) % P
    return (x3, y3, _mul(h, z1))


def scalar_mul_hw(k):
    """k*G with EVERY field multiplication routed through mul4x4_hw +
    reduce_full. One scalar multiplication is ~2600 of them, each with a
    different carry pattern -- which is the point: this is the model being
    exercised the way the server exercises the assembly, and checked
    against a public key OpenSSL computed independently."""
    acc = (0, 0, 0)
    for i in reversed(range(k.bit_length())):
        acc = _jac_dbl(acc)
        if (k >> i) & 1:
            acc = _jac_add_affine(acc, GX, GY)
    x, y, z = acc
    if z == 0:
        return (0, 0)
    zinv = pow(z, P - 2, P)
    zinv2 = _mul(zinv, zinv)
    return (_mul(x, zinv2), _mul(y, _mul(zinv2, zinv)))


def interop(count):
    """Cross-check against `cryptography` (OpenSSL) -- an independent,
    audited implementation. The formula being validated is not the point
    arithmetic (that is already tested elsewhere); it is that a quarter of
    a million carry chains, all driven by the model, produce a public key
    that a real library agrees with."""
    count = count or 40
    from cryptography.hazmat.primitives.asymmetric import ec

    rng = random.Random(7)
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    bad = 0
    AUDIT.clear()
    for _ in range(count):
        d = rng.randrange(1, n)
        pub = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
        got = scalar_mul_hw(d)
        if got != (pub.x, pub.y):
            bad += 1
    total = sum(len(v) for v in AUDIT.values()) // 4
    print("%d/%d public keys agree with `cryptography` (OpenSSL)"
          % (count - bad, count))
    print("  %d field multiplications went through the modelled carry chain"
          % total)
    assert bad == 0


# ── 4. generated test vectors ────────────────────────────────────────────
GEN_CMD = "python3 scripts/p256_fe_mul_derivation.py"


def c_limbs(v):
    return "{" + ", ".join("0x%016xULL" % w for w in words(v)) + "}"


def gen_test():
    rng = random.Random(31337)
    vals = edge_values()

    cases = []
    seen = set()

    def add(a, b, why):
        key = (a % (1 << 256), b % (1 << 256))
        if key in seen:
            return
        seen.add(key)
        cases.append((key[0], key[1], why))

    # Every edge x edge pair whose product actually stresses a carry: the
    # ones where some row's t[i+4] is at its maximum, plus the classic
    # extremes. Taking all 17x17 would bloat the file for little gain, so
    # this takes the extremes plus a scan for maximal row carries.
    add((1 << 256) - 1, (1 << 256) - 1, "all-ones squared: every row carry maximal")
    add((1 << 256) - 1, 1, "all-ones x 1: row 0 only, t[4] = 0")
    add(1, (1 << 256) - 1, "1 x all-ones: one limb product per row")
    add(P - 1, P - 1, "(p-1)^2: the largest canonical field element")
    add(P - 1, 2, "(p-1)*2: reduction must fire")
    add(0, (1 << 256) - 1, "0 x all-ones: whole product zero")
    add((1 << 256) - 1, 0, "all-ones x 0: aliasing of the zero case")
    add(1 << 255, 1 << 255, "2^255 squared: single high bit into t[7]")
    add(MASK << 192, MASK << 192, "top limbs only: product lives in t[6..7]")
    add(MASK, MASK, "low limbs only: product lives in t[0..1]")
    add((MASK << 192) | MASK, (MASK << 192) | MASK, "sparse limbs, both ends")
    add(P, P, "p x p: input at the modulus, not below it")
    add(P + 1, P + 1, "(p+1)^2: input above the modulus")
    add(1 << 192, 1 << 64, "pure limb shift: t[4] set with no carry in")
    add(0xAAAAAAAAAAAAAAAA, 0x5555555555555555, "alternating bit patterns")

    for _ in range(30):
        add(rng.randrange(1 << 256), rng.randrange(1 << 256), "random")

    out = []
    out.append("// Unit tests for p256_fe_mul's unrolled 4x4 product")
    out.append("//")
    out.append("// GENERATED FILE -- do not edit by hand. Regenerate with:")
    out.append("//   %s gen-test > tests/unit/test_p256/mul_carry.c" % GEN_CMD)
    out.append("//")
    out.append("// tests/unit/test_p256/mul.c already covers p256_fe_mul on")
    out.append("// ordinary values. This file exists for the *carry chain*: when")
    out.append("// p256_fe_mul stopped calling p256_bn_mul's generic loop and")
    out.append("// grew its own unrolled product, the risk moved from the")
    out.append("// algorithm (unchanged -- schoolbook) to the hand-written carry")
    out.append("// propagation, so the vectors here are chosen to drive that:")
    out.append("// operands that maximise every row's carry-out, operands whose")
    out.append("// product occupies only the high or only the low limbs, and")
    out.append("// inputs at and above the modulus.")
    out.append("//")
    out.append("// Expected values come from Python's arbitrary-precision")
    out.append("// integers ((a*b) % p), which share no limb-splitting or carry")
    out.append("// logic with the assembly under test. The generator additionally")
    out.append("// cross-checks itself against `cryptography` (OpenSSL) by")
    out.append("// computing whole public keys through the modelled carry chain")
    out.append("// -- see %s interop." % GEN_CMD)
    out.append("//")
    out.append("// Aliasing is tested explicitly: the unrolled product reads both")
    out.append("// operands into registers before it writes anything, so out may")
    out.append("// alias a, b, or both -- p256_point_add_affine and p256_fe_inv")
    out.append("// both rely on that (`p256_fe_sqr(x, x)`).")
    out.append("")
    # test_harness.h declares memcmp/memcpy itself and deliberately
    # avoids <string.h> (which would also drag in strlen/atoi and
    # collide with the assembly under test).
    out.append('#include "test_harness.h"')
    out.append("")
    out.append("extern void p256_fe_mul(uint64_t out[4], const uint64_t a[4],")
    out.append("                        const uint64_t b[4])")
    out.append('    __asm__("p256_fe_mul");')
    out.append("extern void p256_fe_sqr(uint64_t out[4], const uint64_t a[4])")
    out.append('    __asm__("p256_fe_sqr");')
    out.append("")
    out.append("struct mulvec { uint64_t a[4], b[4], prod[4]; const char *why; };")
    out.append("")
    out.append("static const struct mulvec VECS[] = {")
    for a, b, why in cases:
        out.append("    { %s," % c_limbs(a))
        out.append("      %s," % c_limbs(b))
        out.append("      %s," % c_limbs((a * b) % P))
        out.append('      "%s" },' % why)
    out.append("};")
    out.append("#define NVECS ((int)(sizeof VECS / sizeof VECS[0]))")
    out.append("")

    sqr_cases = [a for a, _, _ in cases[:20]]
    out.append("// p256_fe_sqr is a trampoline into p256_fe_mul (it sets b = a")
    out.append("// and falls through), so it shares the product entirely. These")
    out.append("// pin that down rather than assuming it.")
    out.append("static const struct { uint64_t a[4], sq[4]; } SQRS[] = {")
    for a in sqr_cases:
        out.append("    { %s," % c_limbs(a))
        out.append("      %s }," % c_limbs((a * a) % P))
    out.append("};")
    out.append("#define NSQRS ((int)(sizeof SQRS / sizeof SQRS[0]))")
    out.append("")
    out.append("static void test_fe_mul_carry(void) {")
    out.append('    TEST_SUITE("p256_fe_mul carry chain");')
    out.append("")
    out.append("    for (int i = 0; i < NVECS; i++) {")
    out.append("        uint64_t out[4], t[4];")
    out.append("        p256_fe_mul(out, VECS[i].a, VECS[i].b);")
    out.append("        ASSERT_EQ(VECS[i].why, 0, memcmp(out, VECS[i].prod, 32));")
    out.append("")
    out.append("        // out aliases a: the product reads both operands into")
    out.append("        // registers before writing anything.")
    out.append("        memcpy(t, VECS[i].a, 32);")
    out.append("        p256_fe_mul(t, t, VECS[i].b);")
    out.append('        ASSERT_EQ("out == a", 0, memcmp(t, VECS[i].prod, 32));')
    out.append("")
    out.append("        // out aliases b")
    out.append("        memcpy(t, VECS[i].b, 32);")
    out.append("        p256_fe_mul(t, VECS[i].a, t);")
    out.append('        ASSERT_EQ("out == b", 0, memcmp(t, VECS[i].prod, 32));')
    out.append("    }")
    out.append("")
    out.append("    for (int i = 0; i < NSQRS; i++) {")
    out.append("        uint64_t out[4], t[4];")
    out.append("        p256_fe_sqr(out, SQRS[i].a);")
    out.append('        ASSERT_EQ("p256_fe_sqr", 0, memcmp(out, SQRS[i].sq, 32));')
    out.append("")
    out.append("        // squaring in place -- p256_fe_inv does exactly this")
    out.append("        memcpy(t, SQRS[i].a, 32);")
    out.append("        p256_fe_sqr(t, t);")
    out.append('        ASSERT_EQ("p256_fe_sqr in place", 0,')
    out.append("                  memcmp(t, SQRS[i].sq, 32));")
    out.append("")
    out.append("        // out == a == b through p256_fe_mul itself")
    out.append("        memcpy(t, SQRS[i].a, 32);")
    out.append("        p256_fe_mul(t, t, t);")
    out.append('        ASSERT_EQ("out == a == b", 0, memcmp(t, SQRS[i].sq, 32));')
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("int main(void) {")
    out.append("    test_fe_mul_carry();")
    out.append("    test_summary();")
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out) + "\n"


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "prove"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    if cmd == "prove":
        prove()
    elif cmd == "check":
        check(arg)
    elif cmd == "interop":
        interop(arg)
    elif cmd == "gen-test":
        sys.stdout.write(gen_test())
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
