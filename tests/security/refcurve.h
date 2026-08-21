// sarm security tests — reference elliptic-curve arithmetic
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/refcurve.h — P-256 and X25519 group
//   operations, built on refbn.h (docs/SECURITY.md, Step 4)
//
// Description: an independent second opinion on the curve assembly.
//   Independence is the whole point, so the coordinate systems are
//   chosen to disagree with the ones under test:
//
//     * src/crypto/p256_point/ works in Jacobian coordinates
//       (x = X/Z^2, y = Y/Z^3). This file works in homogeneous
//       projective coordinates (x = X/Z, y = Y/Z), with the classic
//       Cohen-style formulas. Different denominators, different
//       intermediates, different special cases — a doubling formula
//       mistyped in one has no way to be mistyped the same way in the
//       other.
//
//     * src/crypto/x25519/ runs the RFC 7748 ladder over 5x51-bit
//       limbs with lazy carries. This file runs the same ladder shape
//       over the bit-by-bit reference modulus, so the ladder logic is
//       shared but every field operation underneath it is not — which
//       is the right split, because the carry handling is where the
//       bugs are and the ladder is published pseudocode.
//
//   Comparing across coordinate systems needs no inversion, which is
//   convenient as well as principled: two Jacobian points are equal
//   iff X1*Z2^2 == X2*Z1^2 and Y1*Z2^3 == Y2*Z1^3, so the assembly's
//   output can be checked against a reference affine point by
//   multiplying up rather than dividing down.
//
//   Self-checks live in refcurve_selfcheck() at the bottom: G is on
//   the curve, n*G is the point at infinity, and the group law is
//   consistent under (a+b)*G == a*G + b*G. Those three between them
//   pin the formulas without needing a published point to compare
//   against — n*G == O in particular is not something a mistyped
//   doubling formula survives.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_REFCURVE_H
#define SARM_REFCURVE_H

#include "refbn.h"
#include "../unit/test_harness.h"

// ── P-256 ───────────────────────────────────────────────────────────

// Homogeneous projective: (X : Y : Z) means (X/Z, Y/Z); Z == 0 is the
// point at infinity.
struct refp256 { refbn X, Y, Z; };

static void refp256_b(refbn *r)
{
    static const uint8_t be[32] = {
        0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,
        0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
        0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,
        0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b,
    };
    bn_from_be(r, be, 32);
}

static void refp256_gx(refbn *r)
{
    static const uint8_t be[32] = {
        0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
        0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
        0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
        0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
    };
    bn_from_be(r, be, 32);
}

static void refp256_gy(refbn *r)
{
    static const uint8_t be[32] = {
        0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,
        0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
        0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,
        0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5,
    };
    bn_from_be(r, be, 32);
}

static int refp256_is_inf(const struct refp256 *p) { return bn_is_zero(&p->Z); }

static void refp256_set_inf(struct refp256 *p)
{
    bn_zero(&p->X);
    bn_set_u32(&p->Y, 1);
    bn_zero(&p->Z);
}

static void refp256_from_affine(struct refp256 *p, const refbn *x,
                                const refbn *y)
{
    bn_copy(&p->X, x);
    bn_copy(&p->Y, y);
    bn_set_u32(&p->Z, 1);
}

static void refp256_generator(struct refp256 *p)
{
    refbn x, y;
    refp256_gx(&x);
    refp256_gy(&y);
    refp256_from_affine(p, &x, &y);
}

// y^2 == x^3 - 3x + b (mod p)
static int refp256_on_curve(const refbn *x, const refbn *y)
{
    refbn p, b, lhs, rhs, t, three;
    bn_p256_p(&p);
    refp256_b(&b);
    bn_set_u32(&three, 3);

    bn_mulmod(&lhs, y, y, &p);
    bn_mulmod(&rhs, x, x, &p);
    bn_mulmod(&rhs, &rhs, x, &p);        // x^3
    bn_mulmod(&t, &three, x, &p);        // 3x
    bn_submod(&rhs, &rhs, &t, &p);
    bn_addmod(&rhs, &rhs, &b, &p);
    return bn_eq(&lhs, &rhs);
}

// Projective doubling, a = -3:
//   W = 3(X - Z)(X + Z)   [ == 3X^2 - 3Z^2, i.e. 3X^2 + aZ^2 ]
//   S = YZ, B = XYS, H = W^2 - 8B
//   X' = 2HS, Y' = W(4B - H) - 8Y^2S^2, Z' = 8S^3
static void refp256_dbl(struct refp256 *r, const struct refp256 *q)
{
    if (refp256_is_inf(q)) { refp256_set_inf(r); return; }

    refbn p, w, s, b, h, t, u, three, eight, four, two;
    bn_p256_p(&p);
    bn_set_u32(&two, 2);
    bn_set_u32(&three, 3);
    bn_set_u32(&four, 4);
    bn_set_u32(&eight, 8);

    bn_submod(&t, &q->X, &q->Z, &p);
    bn_addmod(&u, &q->X, &q->Z, &p);
    bn_mulmod(&w, &t, &u, &p);
    bn_mulmod(&w, &w, &three, &p);

    bn_mulmod(&s, &q->Y, &q->Z, &p);
    bn_mulmod(&b, &q->X, &q->Y, &p);
    bn_mulmod(&b, &b, &s, &p);

    bn_mulmod(&h, &w, &w, &p);
    bn_mulmod(&t, &eight, &b, &p);
    bn_submod(&h, &h, &t, &p);

    refbn nx, ny, nz;
    bn_mulmod(&nx, &h, &s, &p);
    bn_mulmod(&nx, &nx, &two, &p);

    bn_mulmod(&t, &four, &b, &p);
    bn_submod(&t, &t, &h, &p);
    bn_mulmod(&ny, &w, &t, &p);
    bn_mulmod(&t, &q->Y, &q->Y, &p);
    bn_mulmod(&u, &s, &s, &p);
    bn_mulmod(&t, &t, &u, &p);
    bn_mulmod(&t, &t, &eight, &p);
    bn_submod(&ny, &ny, &t, &p);

    bn_mulmod(&nz, &s, &s, &p);
    bn_mulmod(&nz, &nz, &s, &p);
    bn_mulmod(&nz, &nz, &eight, &p);

    bn_copy(&r->X, &nx);
    bn_copy(&r->Y, &ny);
    bn_copy(&r->Z, &nz);
}

// Projective addition. Falls back to doubling when the two points
// coincide and to infinity when they are inverses, which is exactly
// the special-casing the Jacobian assembly claims not to need — so a
// disagreement at those inputs is interesting rather than expected.
static void refp256_add(struct refp256 *r, const struct refp256 *q1,
                        const struct refp256 *q2)
{
    if (refp256_is_inf(q1)) { *r = *q2; return; }
    if (refp256_is_inf(q2)) { *r = *q1; return; }

    refbn p, u1, u2, v1, v2, u, v, w, a, t, t2, v2sq, v3, two;
    bn_p256_p(&p);
    bn_set_u32(&two, 2);

    bn_mulmod(&u1, &q2->Y, &q1->Z, &p);
    bn_mulmod(&u2, &q1->Y, &q2->Z, &p);
    bn_mulmod(&v1, &q2->X, &q1->Z, &p);
    bn_mulmod(&v2, &q1->X, &q2->Z, &p);

    if (bn_eq(&v1, &v2)) {
        if (bn_eq(&u1, &u2)) refp256_dbl(r, q1);
        else                 refp256_set_inf(r);
        return;
    }

    bn_submod(&u, &u1, &u2, &p);
    bn_submod(&v, &v1, &v2, &p);
    bn_mulmod(&w, &q1->Z, &q2->Z, &p);

    bn_mulmod(&v2sq, &v, &v, &p);
    bn_mulmod(&v3, &v2sq, &v, &p);

    bn_mulmod(&a, &u, &u, &p);
    bn_mulmod(&a, &a, &w, &p);
    bn_submod(&a, &a, &v3, &p);
    bn_mulmod(&t, &v2sq, &v2, &p);
    bn_mulmod(&t2, &t, &two, &p);
    bn_submod(&a, &a, &t2, &p);

    refbn nx, ny, nz;
    bn_mulmod(&nx, &v, &a, &p);

    bn_submod(&t2, &t, &a, &p);          // V^2*V2 - A
    bn_mulmod(&ny, &u, &t2, &p);
    bn_mulmod(&t2, &v3, &u2, &p);
    bn_submod(&ny, &ny, &t2, &p);

    bn_mulmod(&nz, &v3, &w, &p);

    bn_copy(&r->X, &nx);
    bn_copy(&r->Y, &ny);
    bn_copy(&r->Z, &nz);
}

// Double-and-add, most significant bit first. Not constant-time; the
// reference never sees a value the assembly has not already been given.
static void refp256_mul(struct refp256 *r, const refbn *k,
                        const struct refp256 *q)
{
    struct refp256 acc;
    refp256_set_inf(&acc);

    for (int i = bn_bitlen(k) - 1; i >= 0; i--) {
        refp256_dbl(&acc, &acc);
        if (bn_bit(k, i)) refp256_add(&acc, &acc, q);
    }
    *r = acc;
}

// Normalise to affine. Returns 0 for the point at infinity, which has
// no affine representation.
static int refp256_to_affine(const struct refp256 *q, refbn *x, refbn *y)
{
    if (refp256_is_inf(q)) return 0;

    refbn p, zi;
    bn_p256_p(&p);
    bn_invmod(&zi, &q->Z, &p);
    bn_mulmod(x, &q->X, &zi, &p);
    bn_mulmod(y, &q->Y, &zi, &p);
    return 1;
}

// Does the Jacobian point (X, Y, Z) the assembly produced denote the
// affine point (x, y)? Multiplying up rather than dividing down keeps
// this free of the inversion the assembly is also being tested on.
static int refp256_jacobian_is(const refbn *X, const refbn *Y, const refbn *Z,
                               const refbn *x, const refbn *y)
{
    refbn p, z2, z3, t;
    bn_p256_p(&p);
    if (bn_is_zero(Z)) return 0;         // infinity is never an affine point

    bn_mulmod(&z2, Z, Z, &p);
    bn_mulmod(&z3, &z2, Z, &p);

    bn_mulmod(&t, x, &z2, &p);
    if (!bn_eq(&t, X)) return 0;
    bn_mulmod(&t, y, &z3, &p);
    return bn_eq(&t, Y);
}

// ── X25519 ──────────────────────────────────────────────────────────
// The RFC 7748 §5 ladder, over the reference field. The ladder is
// published pseudocode and is shared with the assembly on purpose;
// what is not shared is every field operation it calls, which is where
// a 51-bit-limb implementation can go wrong and a bit-by-bit one
// cannot.

static void ref_x25519(const uint8_t scalar[32], const uint8_t upoint[32],
                       uint8_t out[32])
{
    refbn p, x1, x2, z2, x3, z3, a24;
    bn_25519_p(&p);
    bn_set_u32(&a24, 121665);

    uint8_t k[32];
    for (int i = 0; i < 32; i++) k[i] = scalar[i];
    k[0]  &= 248;                         // clamp, RFC 7748 §5
    k[31] &= 127;
    k[31] |= 64;

    uint8_t u[32];
    for (int i = 0; i < 32; i++) u[i] = upoint[i];
    u[31] &= 127;                         // the high bit is ignored

    bn_from_le(&x1, u, 32);
    bn_mod(&x1, &x1, &p);

    bn_set_u32(&x2, 1);
    bn_zero(&z2);
    bn_copy(&x3, &x1);
    bn_set_u32(&z3, 1);

    int swap = 0;
    for (int t = 254; t >= 0; t--) {
        const int kt = (k[t >> 3] >> (t & 7)) & 1;
        if (swap != kt) {
            refbn tmp;
            bn_copy(&tmp, &x2); bn_copy(&x2, &x3); bn_copy(&x3, &tmp);
            bn_copy(&tmp, &z2); bn_copy(&z2, &z3); bn_copy(&z3, &tmp);
            swap = kt;
        }

        refbn a, aa, b, bb, e, c, d, da, cb, t1, t2;
        bn_addmod(&a, &x2, &z2, &p);
        bn_mulmod(&aa, &a, &a, &p);
        bn_submod(&b, &x2, &z2, &p);
        bn_mulmod(&bb, &b, &b, &p);
        bn_submod(&e, &aa, &bb, &p);
        bn_addmod(&c, &x3, &z3, &p);
        bn_submod(&d, &x3, &z3, &p);
        bn_mulmod(&da, &d, &a, &p);
        bn_mulmod(&cb, &c, &b, &p);

        bn_addmod(&t1, &da, &cb, &p);
        bn_mulmod(&x3, &t1, &t1, &p);
        bn_submod(&t2, &da, &cb, &p);
        bn_mulmod(&t2, &t2, &t2, &p);
        bn_mulmod(&z3, &x1, &t2, &p);

        bn_mulmod(&x2, &aa, &bb, &p);
        bn_mulmod(&t1, &a24, &e, &p);
        bn_addmod(&t1, &aa, &t1, &p);
        bn_mulmod(&z2, &e, &t1, &p);
    }

    if (swap) {
        refbn tmp;
        bn_copy(&tmp, &x2); bn_copy(&x2, &x3); bn_copy(&x3, &tmp);
        bn_copy(&tmp, &z2); bn_copy(&z2, &z3); bn_copy(&z3, &tmp);
    }

    refbn zi, res;
    bn_invmod(&zi, &z2, &p);
    bn_mulmod(&res, &x2, &zi, &p);
    bn_to_le(&res, out, 32);
}

// ── self-checks ─────────────────────────────────────────────────────
// The reference has to earn the right to judge the assembly. There is
// no published projective-coordinate vector to compare against, so
// these check the structure instead — and n*G == O is not something a
// wrong formula gets right by accident.

static void refcurve_selfcheck(void)
{
    TEST_SUITE("reference self-check — P-256 group law / X25519 ladder");

    refbn gx, gy, n;
    refp256_gx(&gx);
    refp256_gy(&gy);
    bn_p256_n(&n);

    ASSERT_TRUE("G satisfies y^2 = x^3 - 3x + b",
                refp256_on_curve(&gx, &gy));

    struct refp256 g, r;
    refp256_generator(&g);

    refp256_mul(&r, &n, &g);
    ASSERT_TRUE("n*G is the point at infinity", refp256_is_inf(&r));

    // (a + b)*G == a*G + b*G, for a couple of arbitrary small scalars
    {
        refbn a, b, ab;
        bn_set_u32(&a, 0x9e3779b9u);
        bn_set_u32(&b, 0x7f4a7c15u);
        bn_addmod(&ab, &a, &b, &n);

        struct refp256 ga, gb, sum, direct;
        refp256_mul(&ga, &a, &g);
        refp256_mul(&gb, &b, &g);
        refp256_add(&sum, &ga, &gb);
        refp256_mul(&direct, &ab, &g);

        refbn x1, y1, x2, y2;
        const int ok = refp256_to_affine(&sum, &x1, &y1)
                     && refp256_to_affine(&direct, &x2, &y2);
        ASSERT_TRUE("(a+b)*G == a*G + b*G",
                    ok && bn_eq(&x1, &x2) && bn_eq(&y1, &y2));
        ASSERT_TRUE("a*G is on the curve", ok && refp256_on_curve(&x1, &y1));
    }

    // RFC 7748 §5.2, the first X25519 test vector
    {
        static const uint8_t scalar[32] = {
            0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,
            0x82,0x46,0x5e,0xdd,0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,
            0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4,
        };
        static const uint8_t upoint[32] = {
            0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,
            0x24,0xb1,0x5f,0x7c,0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,
            0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c,
        };
        static const uint8_t want[32] = {
            0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,
            0xf2,0x8d,0x08,0x4f,0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,
            0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52,
        };

        uint8_t got[32];
        ref_x25519(scalar, upoint, got);
        int same = 1;
        for (int i = 0; i < 32; i++) if (got[i] != want[i]) same = 0;
        ASSERT_TRUE("reference X25519 matches RFC 7748 §5.2", same);
    }
}

#endif // SARM_REFCURVE_H
