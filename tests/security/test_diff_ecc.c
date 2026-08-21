// sarm security tests — X25519 and P-256 against a reference, over
// random vectors
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 4, for the two curves. Step 3 checked these
// routines by algebraic identity, which is sound but narrow: a field
// multiplier that reduces modulo the wrong prime still satisfies
// a * a^-1 == 1 in the wrong field, and a point addition with a
// mistyped constant still satisfies P + P == 2P if the doubling has
// the same typo. What identities cannot do is say what the value
// *is*. That is what refbn.h and refcurve.h are for.
//
// The counts below are wildly uneven, on purpose. A field
// multiplication gets thousands of vectors; a scalar multiplication
// gets a couple of dozen. Two reasons, and they point the same way:
// the reference reduces modulo a 256-bit prime one bit at a time, so a
// scalar multiplication costs some thousands of those — and the field
// operations are where the bugs actually are. Carry propagation, the
// Solinas fold, the 51-bit limb boundaries: those are the delicate
// parts, and they are the parts getting the vectors.

#include "diff_common.h"
#include "refcurve.h"

// ── X25519 ──────────────────────────────────────────────────────────
#define X25519_LIMBS 5
#define X25519_FE    40

extern void x25519(void *out, const void *scalar, const void *point)
    __asm__("x25519");
extern void x25519_fe_frombytes(void *out, const void *s)
    __asm__("x25519_fe_frombytes");
extern void x25519_fe_tobytes(void *out, const void *in)
    __asm__("x25519_fe_tobytes");
extern void x25519_fe_add(void *out, const void *a, const void *b)
    __asm__("x25519_fe_add");
extern void x25519_fe_sub(void *out, const void *a, const void *b)
    __asm__("x25519_fe_sub");
extern void x25519_fe_mul(void *out, const void *a, const void *b)
    __asm__("x25519_fe_mul");
extern void x25519_fe_sqr(void *out, const void *a) __asm__("x25519_fe_sqr");
extern void x25519_fe_sqr_times(void *out, const void *a, uint64_t count)
    __asm__("x25519_fe_sqr_times");
extern void x25519_fe_scalar_product(void *out, const void *a, uint64_t s)
    __asm__("x25519_fe_scalar_product");
extern void x25519_fe_recip(void *out, const void *a)
    __asm__("x25519_fe_recip");

// ── P-256 ───────────────────────────────────────────────────────────
#define P256_LIMBS 4
#define P256_POINT 96

extern void p256_fe_add(void *out, const void *a, const void *b)
    __asm__("p256_fe_add");
extern void p256_fe_sub(void *out, const void *a, const void *b)
    __asm__("p256_fe_sub");
extern void p256_fe_mul(void *out, const void *a, const void *b)
    __asm__("p256_fe_mul");
extern void p256_fe_sqr(void *out, const void *a) __asm__("p256_fe_sqr");
extern void p256_fe_inv(void *out, const void *a) __asm__("p256_fe_inv");
extern uint64_t p256_fe_eq(const void *a, const void *b) __asm__("p256_fe_eq");
extern void p256_fe_frombytes(void *out, const void *in)
    __asm__("p256_fe_frombytes");
extern void p256_fe_tobytes(void *out, const void *in)
    __asm__("p256_fe_tobytes");
extern void p256_reduce(void *out, const void *t) __asm__("p256_reduce");
extern void p256_bn_mul(void *out, const void *a, uint64_t na,
                        const void *b, uint64_t nb) __asm__("p256_bn_mul");

extern void p256_scalar_mul(void *out, const void *a, const void *b)
    __asm__("p256_scalar_mul");
extern void p256_scalar_reduce(void *out, const void *in)
    __asm__("p256_scalar_reduce");
extern void p256_scalar_mont_mul(void *out, const void *a, const void *b)
    __asm__("p256_scalar_mont_mul");
extern void p256_scalar_inv(void *out, const void *a)
    __asm__("p256_scalar_inv");

extern void p256_point_dbl(void *out, const void *in) __asm__("p256_point_dbl");
extern void p256_point_add(void *out, const void *p1, const void *p2)
    __asm__("p256_point_add");
extern void p256_point_mul(void *outx, void *outy, const void *k,
                           const void *inx, const void *iny)
    __asm__("p256_point_mul");
extern void p256_point_mul_base(void *outx, void *outy, const void *k)
    __asm__("p256_point_mul_base");

extern uint64_t p256_ecdsa_sign_with_k(void *r, void *s, const void *hash,
                                       const void *d, const void *k)
    __asm__("p256_ecdsa_sign_with_k");
extern uint64_t p256_ecdsa_verify(const void *hash, const void *r,
                                  const void *s, const void *qx,
                                  const void *qy) __asm__("p256_ecdsa_verify");

// ── conversions between the two worlds ──────────────────────────────

static void fe_to_bn(refbn *r, const uint64_t *fe) { bn_from_u64s(r, fe, 4); }
static void bn_to_fe(const refbn *a, uint64_t *fe) { bn_to_u64s(a, fe, 4); }

// A uniform field element, as the assembly expects it: fully reduced,
// four little-endian limbs.
static void rand_fe(struct diff_rng *rng, uint64_t *fe, const refbn *m)
{
    uint8_t b[32];
    diff_rng_bytes(rng, b, 32);
    refbn v;
    bn_from_le(&v, b, 32);
    bn_mod(&v, &v, m);
    bn_to_fe(&v, fe);
}

// One in eight vectors is a special value rather than a uniform one.
// Uniform 256-bit values are never near zero, never near p, and never
// have a limb of all ones — which is precisely the set of inputs a
// carry bug needs. Steering a fraction of the vectors at them costs
// almost nothing and covers what randomness alone would take 2^60
// tries to reach.
static void rand_fe_edgy(struct diff_rng *rng, uint64_t *fe, const refbn *m)
{
    if ((diff_rng_u64(rng) & 7u) != 0) { rand_fe(rng, fe, m); return; }

    refbn v;
    switch (diff_rng_u64(rng) & 7u) {
    case 0: bn_zero(&v); break;
    case 1: bn_set_u32(&v, 1); break;
    case 2: {                            // m - 1, the largest legal value
        refbn one; bn_set_u32(&one, 1);
        bn_sub(&v, m, &one);
        break;
    }
    case 3: {                            // 2^255, the top bit alone
        refbn one; bn_set_u32(&one, 1);
        bn_shl(&v, &one, 255);
        bn_mod(&v, &v, m);
        break;
    }
    case 4: {                            // all limbs 0xffffffffffffffff
        uint64_t all[4] = { ~0ull, ~0ull, ~0ull, ~0ull };
        bn_from_u64s(&v, all, 4);
        bn_mod(&v, &v, m);
        break;
    }
    case 5: {                            // a single random limb saturated
        rand_fe(rng, fe, m);
        refbn t; fe_to_bn(&t, fe);
        const int limb = (int)diff_rng_below(rng, 4);
        uint64_t l[4]; bn_to_u64s(&t, l, 4);
        l[limb] = ~0ull;
        bn_from_u64s(&v, l, 4);
        bn_mod(&v, &v, m);
        break;
    }
    case 6: {                            // m - 2
        refbn two; bn_set_u32(&two, 2);
        bn_sub(&v, m, &two);
        break;
    }
    default: {                           // 2^128, straddling the middle
        refbn one; bn_set_u32(&one, 1);
        bn_shl(&v, &one, 128);
        bn_mod(&v, &v, m);
        break;
    }
    }
    bn_to_fe(&v, fe);
}

static int bn_matches_fe(const refbn *want, const uint64_t *fe,
                         const char *what, char *detail, size_t len)
{
    refbn got;
    fe_to_bn(&got, fe);
    if (bn_eq(&got, want)) return 1;

    uint8_t g[32], w[32];
    bn_to_be(&got, g, 32);
    bn_to_be(want, w, 32);
    diff_report(detail, len, what, 32, g, w, 32);
    return 0;
}

// ── X25519 field operations ─────────────────────────────────────────
// The 5x51 representation is not canonical: the same value has many
// limb encodings, and add/sub deliberately leave limbs unreduced. So
// the comparison goes through the integer the limbs denote, never
// through the limbs themselves.

// Limbs are legal inputs anywhere below 2^51; sub is documented to
// tolerate operands that have grown to ~2^52, so both are generated.
static void rand_fe25519(struct diff_rng *rng, uint64_t *fe)
{
    const uint64_t mask = (diff_rng_u64(rng) & 15u) == 0
                        ? ((1ull << 52) - 1)   // an unreduced-but-legal input
                        : ((1ull << 51) - 1);
    for (int i = 0; i < X25519_LIMBS; i++)
        fe[i] = diff_rng_u64(rng) & mask;

    // and now and then, a limb pinned to its maximum
    if ((diff_rng_u64(rng) & 7u) == 0)
        fe[diff_rng_below(rng, X25519_LIMBS)] = mask;
}

static void fe25519_to_bn(refbn *r, const uint64_t *fe)
{
    refbn p;
    bn_25519_p(&p);
    bn_from_limbs51(r, fe, X25519_LIMBS);
    bn_mod(r, r, &p);
}

static int fe25519_is(const refbn *want, const uint64_t *fe,
                      const char *what, char *detail, size_t len)
{
    refbn got;
    fe25519_to_bn(&got, fe);
    if (bn_eq(&got, want)) return 1;

    uint8_t g[32], w[32];
    bn_to_le(&got, g, 32);
    bn_to_le(want, w, 32);
    diff_report(detail, len, what, 32, g, w, 32);
    return 0;
}

static int case_25519_addsub(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, ba, bb, want;
    bn_25519_p(&p);

    uint64_t a[X25519_LIMBS], b[X25519_LIMBS], out[X25519_LIMBS];
    rand_fe25519(rng, a);
    rand_fe25519(rng, b);
    fe25519_to_bn(&ba, a);
    fe25519_to_bn(&bb, b);

    x25519_fe_add(out, a, b);
    bn_addmod(&want, &ba, &bb, &p);
    if (!fe25519_is(&want, out, "x25519_fe_add", detail, len)) return 0;

    x25519_fe_sub(out, a, b);
    bn_submod(&want, &ba, &bb, &p);
    if (!fe25519_is(&want, out, "x25519_fe_sub", detail, len)) return 0;

    // in place, which the ladder relies on
    uint64_t c[X25519_LIMBS];
    for (int i = 0; i < X25519_LIMBS; i++) c[i] = a[i];
    x25519_fe_sub(c, c, b);
    if (!fe25519_is(&want, c, "x25519_fe_sub (aliased)", detail, len))
        return 0;

    return 1;
}

static int case_25519_mul(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, ba, bb, want;
    bn_25519_p(&p);

    uint64_t a[X25519_LIMBS], b[X25519_LIMBS], out[X25519_LIMBS];
    rand_fe25519(rng, a);
    rand_fe25519(rng, b);
    fe25519_to_bn(&ba, a);
    fe25519_to_bn(&bb, b);

    x25519_fe_mul(out, a, b);
    bn_mulmod(&want, &ba, &bb, &p);
    if (!fe25519_is(&want, out, "x25519_fe_mul", detail, len)) return 0;

    x25519_fe_sqr(out, a);
    bn_mulmod(&want, &ba, &ba, &p);
    if (!fe25519_is(&want, out, "x25519_fe_sqr", detail, len)) return 0;

    // sqr_times starts at 1: count == 0 does not terminate, see
    // docs/security/threat-model.md §9.
    const uint64_t count = 1 + diff_rng_below(rng, 16);
    x25519_fe_sqr_times(out, a, count);
    bn_copy(&want, &ba);
    for (uint64_t i = 0; i < count; i++) bn_mulmod(&want, &want, &want, &p);
    if (!fe25519_is(&want, out, "x25519_fe_sqr_times", detail, len)) return 0;

    // scalar_product's multiplier is small by contract (a24 = 121665
    // is the only real caller), so the sweep stays in that range.
    const uint64_t s = diff_rng_below(rng, 1u << 21);
    refbn bs;
    bn_zero(&bs);
    bs.v[0] = (uint32_t)s;
    bs.v[1] = (uint32_t)(s >> 32);
    x25519_fe_scalar_product(out, a, s);
    bn_mulmod(&want, &ba, &bs, &p);
    if (!fe25519_is(&want, out, "x25519_fe_scalar_product", detail, len))
        return 0;

    return 1;
}

static int case_25519_bytes(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, want;
    bn_25519_p(&p);

    uint8_t in[32];
    diff_rng_bytes(rng, in, 32);

    uint64_t fe[X25519_LIMBS];
    x25519_fe_frombytes(fe, in);

    // frombytes ignores the top bit, per RFC 7748.
    uint8_t masked[32];
    for (int i = 0; i < 32; i++) masked[i] = in[i];
    masked[31] &= 0x7f;
    bn_from_le(&want, masked, 32);
    bn_mod(&want, &want, &p);

    if (!fe25519_is(&want, fe, "x25519_fe_frombytes", detail, len)) return 0;

    // tobytes must be canonical: the same value, reduced, little-endian
    DIFF_OUT(out, 32);
    x25519_fe_tobytes(out, fe);
    DIFF_CHECK_TAIL(out, 32, "x25519_fe_tobytes", detail, len);

    uint8_t wb[32];
    bn_to_le(&want, wb, 32);
    if (!diff_eq(out, wb, 32)) {
        diff_report(detail, len, "x25519_fe_tobytes", 32, out, wb, 32);
        return 0;
    }
    return 1;
}

static int case_25519_recip(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, ba, want;
    bn_25519_p(&p);

    uint64_t a[X25519_LIMBS], out[X25519_LIMBS];
    rand_fe25519(rng, a);
    fe25519_to_bn(&ba, a);

    x25519_fe_recip(out, a);
    bn_invmod(&want, &ba, &p);
    return fe25519_is(&want, out, "x25519_fe_recip", detail, len);
}

static int case_25519_full(struct diff_rng *rng, char *detail, size_t len)
{
    uint8_t scalar[32], point[32], want[32];
    diff_rng_bytes(rng, scalar, 32);
    diff_rng_bytes(rng, point, 32);

    DIFF_OUT(got, 32);
    x25519(got, scalar, point);
    DIFF_CHECK_TAIL(got, 32, "x25519", detail, len);

    ref_x25519(scalar, point, want);
    if (!diff_eq(got, want, 32)) {
        diff_report(detail, len, "x25519 scalar multiplication", 32,
                    got, want, 32);
        return 0;
    }
    return 1;
}

// ── P-256 field operations ──────────────────────────────────────────

static int case_p256_field(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, ba, bb, want;
    bn_p256_p(&p);

    uint64_t a[P256_LIMBS], b[P256_LIMBS], out[P256_LIMBS];
    rand_fe_edgy(rng, a, &p);
    rand_fe_edgy(rng, b, &p);
    fe_to_bn(&ba, a);
    fe_to_bn(&bb, b);

    p256_fe_add(out, a, b);
    bn_addmod(&want, &ba, &bb, &p);
    if (!bn_matches_fe(&want, out, "p256_fe_add", detail, len)) return 0;

    p256_fe_sub(out, a, b);
    bn_submod(&want, &ba, &bb, &p);
    if (!bn_matches_fe(&want, out, "p256_fe_sub", detail, len)) return 0;

    p256_fe_mul(out, a, b);
    bn_mulmod(&want, &ba, &bb, &p);
    if (!bn_matches_fe(&want, out, "p256_fe_mul", detail, len)) return 0;

    p256_fe_sqr(out, a);
    bn_mulmod(&want, &ba, &ba, &p);
    if (!bn_matches_fe(&want, out, "p256_fe_sqr", detail, len)) return 0;

    // aliasing: every one of these is documented to allow out == a
    for (int i = 0; i < P256_LIMBS; i++) out[i] = a[i];
    p256_fe_mul(out, out, b);
    bn_mulmod(&want, &ba, &bb, &p);
    if (!bn_matches_fe(&want, out, "p256_fe_mul (aliased)", detail, len))
        return 0;

    // fe_eq is the comparison the rest of the code trusts
    const uint64_t same = p256_fe_eq(a, a);
    const uint64_t diff = p256_fe_eq(a, b);
    if (same != 1 || (bn_eq(&ba, &bb) ? diff != 1 : diff != 0)) {
        snprintf(detail, len,
                 "p256_fe_eq: a==a gave %llu, a==b gave %llu",
                 (unsigned long long)same, (unsigned long long)diff);
        return 0;
    }
    return 1;
}

// The Solinas fold, on its own. This is the routine that turns a
// 512-bit product into a canonical residue with a table of signed
// coefficients, and it is the single most intricate piece of integer
// arithmetic in the codebase — so it gets a full-width random input
// rather than a product of two field elements, which would only ever
// reach the subset of 512-bit values that factor that way.
static int case_p256_reduce(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, t, want;
    bn_p256_p(&p);

    uint64_t wide[8];
    for (int i = 0; i < 8; i++) wide[i] = diff_rng_u64(rng);

    // one vector in eight has saturated limbs, where the fold's carries
    // are at their worst
    if ((diff_rng_u64(rng) & 7u) == 0)
        for (int i = 0; i < 8; i++)
            if (diff_rng_u64(rng) & 1u) wide[i] = ~0ull;

    bn_from_u64s(&t, wide, 8);
    bn_mod(&want, &t, &p);

    uint64_t out[P256_LIMBS];
    p256_reduce(out, wide);
    return bn_matches_fe(&want, out, "p256_reduce", detail, len);
}

static int case_p256_inv(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, ba, want;
    bn_p256_p(&p);

    uint64_t a[P256_LIMBS], out[P256_LIMBS];
    rand_fe_edgy(rng, a, &p);
    fe_to_bn(&ba, a);

    p256_fe_inv(out, a);
    bn_invmod(&want, &ba, &p);
    return bn_matches_fe(&want, out, "p256_fe_inv", detail, len);
}

static int case_p256_bytes(struct diff_rng *rng, char *detail, size_t len)
{
    refbn p, v;
    bn_p256_p(&p);

    uint64_t a[P256_LIMBS];
    rand_fe_edgy(rng, a, &p);
    fe_to_bn(&v, a);

    uint8_t want[32];
    bn_to_be(&v, want, 32);              // SEC1: big-endian

    DIFF_OUT(bytes, 32);
    p256_fe_tobytes(bytes, a);
    DIFF_CHECK_TAIL(bytes, 32, "p256_fe_tobytes", detail, len);
    if (!diff_eq(bytes, want, 32)) {
        diff_report(detail, len, "p256_fe_tobytes", 32, bytes, want, 32);
        return 0;
    }

    uint64_t back[P256_LIMBS];
    p256_fe_frombytes(back, want);
    return bn_matches_fe(&v, back, "p256_fe_frombytes", detail, len);
}

// The generic schoolbook multiplier, at every limb-count shape the
// scalar code asks of it.
static int case_p256_bn_mul(struct diff_rng *rng, char *detail, size_t len)
{
    const uint64_t na = 1 + diff_rng_below(rng, 8);
    const uint64_t nb = 1 + diff_rng_below(rng, 8);

    uint64_t a[8], b[8];
    for (uint64_t i = 0; i < na; i++) a[i] = diff_rng_u64(rng);
    for (uint64_t i = 0; i < nb; i++) b[i] = diff_rng_u64(rng);
    if ((diff_rng_u64(rng) & 7u) == 0) {
        for (uint64_t i = 0; i < na; i++) a[i] = ~0ull;
        for (uint64_t i = 0; i < nb; i++) b[i] = ~0ull;
    }

    DIFF_OUT(out, 16 * 8);
    p256_bn_mul(out, a, na, b, nb);
    DIFF_CHECK_TAIL(out, (na + nb) * 8, "p256_bn_mul", detail, len);

    refbn ba, bb, want;
    bn_from_u64s(&ba, a, (size_t)na);
    bn_from_u64s(&bb, b, (size_t)nb);
    bn_mul(&want, &ba, &bb);

    uint64_t wlimbs[16];
    bn_to_u64s(&want, wlimbs, (size_t)(na + nb));
    if (!diff_eq(out, (const uint8_t *)wlimbs, (size_t)(na + nb) * 8)) {
        char msg[64];
        snprintf(msg, sizeof msg, "p256_bn_mul %llux%llu limbs",
                 (unsigned long long)na, (unsigned long long)nb);
        diff_report(detail, len, msg, (size_t)(na + nb) * 8,
                    out, (const uint8_t *)wlimbs, (size_t)(na + nb) * 8);
        return 0;
    }
    return 1;
}

// ── P-256 scalar ring ───────────────────────────────────────────────

static int case_p256_scalar(struct diff_rng *rng, char *detail, size_t len)
{
    refbn n, ba, bb, want;
    bn_p256_n(&n);

    uint64_t a[P256_LIMBS], b[P256_LIMBS], out[P256_LIMBS];
    rand_fe_edgy(rng, a, &n);
    rand_fe_edgy(rng, b, &n);
    fe_to_bn(&ba, a);
    fe_to_bn(&bb, b);

    p256_scalar_mul(out, a, b);
    bn_mulmod(&want, &ba, &bb, &n);
    if (!bn_matches_fe(&want, out, "p256_scalar_mul", detail, len)) return 0;

    // out = a*b*R^-1 mod n, R = 2^256
    refbn r, rinv;
    bn_r256(&r);
    bn_invmod(&rinv, &r, &n);
    bn_mulmod(&want, &ba, &bb, &n);
    bn_mulmod(&want, &want, &rinv, &n);
    p256_scalar_mont_mul(out, a, b);
    if (!bn_matches_fe(&want, out, "p256_scalar_mont_mul", detail, len))
        return 0;

    // reduce takes an arbitrary 4-limb value, not a reduced one
    uint8_t wide[32];
    diff_rng_bytes(rng, wide, 32);
    refbn raw;
    bn_from_le(&raw, wide, 32);
    uint64_t in[P256_LIMBS];
    bn_to_fe(&raw, in);
    bn_mod(&want, &raw, &n);
    p256_scalar_reduce(out, in);
    if (!bn_matches_fe(&want, out, "p256_scalar_reduce", detail, len))
        return 0;

    return 1;
}

static int case_p256_scalar_inv(struct diff_rng *rng, char *detail, size_t len)
{
    refbn n, ba, want;
    bn_p256_n(&n);

    uint64_t a[P256_LIMBS], out[P256_LIMBS];
    rand_fe_edgy(rng, a, &n);
    fe_to_bn(&ba, a);

    p256_scalar_inv(out, a);
    bn_invmod(&want, &ba, &n);
    return bn_matches_fe(&want, out, "p256_scalar_inv", detail, len);
}

// ── P-256 group law ─────────────────────────────────────────────────

// A random point on the curve, obtained the only cheap honest way:
// multiply the generator by a small scalar in the reference. Small
// keeps the reference's double-and-add short; the coordinates that
// come out are still effectively random field elements.
static int rand_point(struct diff_rng *rng, refbn *x, refbn *y)
{
    refbn k;
    bn_zero(&k);
    k.v[0] = (uint32_t)diff_rng_u64(rng);
    k.v[1] = (uint32_t)(diff_rng_u64(rng) & 0xffu);
    if (bn_is_zero(&k)) bn_set_u32(&k, 7);

    struct refp256 g, r;
    refp256_generator(&g);
    refp256_mul(&r, &k, &g);
    return refp256_to_affine(&r, x, y);
}

// Build a Jacobian representation of (x, y) with a non-trivial Z, so
// the assembly is not being handed the easy Z == 1 case every time.
static void jacobian_of(struct diff_rng *rng, const refbn *x, const refbn *y,
                        uint64_t point[12])
{
    refbn p, z, z2, z3, X, Y;
    bn_p256_p(&p);

    uint8_t zb[32];
    diff_rng_bytes(rng, zb, 32);
    bn_from_le(&z, zb, 32);
    bn_mod(&z, &z, &p);
    if (bn_is_zero(&z)) bn_set_u32(&z, 1);

    bn_mulmod(&z2, &z, &z, &p);
    bn_mulmod(&z3, &z2, &z, &p);
    bn_mulmod(&X, x, &z2, &p);
    bn_mulmod(&Y, y, &z3, &p);

    bn_to_u64s(&X, point + 0, 4);
    bn_to_u64s(&Y, point + 4, 4);
    bn_to_u64s(&z, point + 8, 4);
}

static int case_p256_dbl_add(struct diff_rng *rng, char *detail, size_t len)
{
    refbn x1, y1, x2, y2;
    if (!rand_point(rng, &x1, &y1) || !rand_point(rng, &x2, &y2)) {
        snprintf(detail, len, "could not build a random curve point");
        return 0;
    }

    uint64_t P[12], Q[12], R[12];
    jacobian_of(rng, &x1, &y1, P);
    jacobian_of(rng, &x2, &y2, Q);

    struct refp256 rp, rq, rr;
    refp256_from_affine(&rp, &x1, &y1);
    refp256_from_affine(&rq, &x2, &y2);

    // doubling
    p256_point_dbl(R, P);
    refp256_dbl(&rr, &rp);
    refbn wx, wy;
    if (!refp256_to_affine(&rr, &wx, &wy)) {
        snprintf(detail, len, "reference doubling produced infinity");
        return 0;
    }
    {
        refbn X, Y, Z;
        bn_from_u64s(&X, R + 0, 4);
        bn_from_u64s(&Y, R + 4, 4);
        bn_from_u64s(&Z, R + 8, 4);
        if (!refp256_jacobian_is(&X, &Y, &Z, &wx, &wy)) {
            uint8_t g[32], w[32];
            bn_to_be(&X, g, 32);
            bn_to_be(&wx, w, 32);
            diff_report(detail, len, "p256_point_dbl", 32, g, w, 32);
            return 0;
        }
    }

    // addition
    p256_point_add(R, P, Q);
    refp256_add(&rr, &rp, &rq);
    if (!refp256_to_affine(&rr, &wx, &wy)) {
        snprintf(detail, len, "reference addition produced infinity");
        return 0;
    }
    {
        refbn X, Y, Z;
        bn_from_u64s(&X, R + 0, 4);
        bn_from_u64s(&Y, R + 4, 4);
        bn_from_u64s(&Z, R + 8, 4);
        if (!refp256_jacobian_is(&X, &Y, &Z, &wx, &wy)) {
            uint8_t g[32], w[32];
            bn_to_be(&X, g, 32);
            bn_to_be(&wx, w, 32);
            diff_report(detail, len, "p256_point_add", 32, g, w, 32);
            return 0;
        }
    }

    // P + P through the *addition* routine, which is the input the
    // Jacobian formulas have to special-case and the one an
    // implementation is most likely to get wrong
    p256_point_add(R, P, P);
    refp256_dbl(&rr, &rp);
    if (!refp256_to_affine(&rr, &wx, &wy)) {
        snprintf(detail, len, "reference doubling produced infinity");
        return 0;
    }
    {
        refbn X, Y, Z;
        bn_from_u64s(&X, R + 0, 4);
        bn_from_u64s(&Y, R + 4, 4);
        bn_from_u64s(&Z, R + 8, 4);
        if (!refp256_jacobian_is(&X, &Y, &Z, &wx, &wy)) {
            snprintf(detail, len,
                     "p256_point_add(P, P) does not equal 2P");
            return 0;
        }
    }

    return 1;
}

static int case_p256_mul(struct diff_rng *rng, char *detail, size_t len)
{
    refbn n, k;
    bn_p256_n(&n);

    uint64_t kfe[P256_LIMBS];
    rand_fe(rng, kfe, &n);
    fe_to_bn(&k, kfe);
    if (bn_is_zero(&k)) bn_set_u32(&k, 1);
    bn_to_fe(&k, kfe);

    struct refp256 g, r;
    refp256_generator(&g);
    refp256_mul(&r, &k, &g);

    refbn wx, wy;
    if (!refp256_to_affine(&r, &wx, &wy)) {
        snprintf(detail, len, "reference k*G produced infinity");
        return 0;
    }

    // the fixed-base comb
    DIFF_OUT(bx, 32);
    DIFF_OUT(by, 32);
    p256_point_mul_base(bx, by, kfe);
    DIFF_CHECK_TAIL(bx, 32, "p256_point_mul_base X", detail, len);
    DIFF_CHECK_TAIL(by, 32, "p256_point_mul_base Y", detail, len);
    if (!bn_matches_fe(&wx, (const uint64_t *)(const void *)bx,
                       "p256_point_mul_base X", detail, len)) return 0;
    if (!bn_matches_fe(&wy, (const uint64_t *)(const void *)by,
                       "p256_point_mul_base Y", detail, len)) return 0;

    // and the general-base ladder, on the same scalar and the same base
    refbn gx, gy;
    refp256_gx(&gx);
    refp256_gy(&gy);
    uint64_t gxfe[P256_LIMBS], gyfe[P256_LIMBS];
    bn_to_fe(&gx, gxfe);
    bn_to_fe(&gy, gyfe);

    uint64_t mx[P256_LIMBS], my[P256_LIMBS];
    p256_point_mul(mx, my, kfe, gxfe, gyfe);
    if (!bn_matches_fe(&wx, mx, "p256_point_mul X", detail, len)) return 0;
    if (!bn_matches_fe(&wy, my, "p256_point_mul Y", detail, len)) return 0;

    return 1;
}

// ── ECDSA ───────────────────────────────────────────────────────────
// The signature equation, computed a second time from the definition:
//   (Rx, Ry) = k*G;  r = Rx mod n;  s = k^-1 (z + r*d) mod n.
// Nothing about the reference's route to r and s resembles the
// assembly's, and both have to produce the same 64 bytes.

static int case_ecdsa(struct diff_rng *rng, char *detail, size_t len)
{
    refbn n;
    bn_p256_n(&n);

    uint64_t dfe[P256_LIMBS], kfe[P256_LIMBS];
    rand_fe(rng, dfe, &n);
    rand_fe(rng, kfe, &n);
    refbn d, k;
    fe_to_bn(&d, dfe);
    fe_to_bn(&k, kfe);
    if (bn_is_zero(&d)) bn_set_u32(&d, 3);
    if (bn_is_zero(&k)) bn_set_u32(&k, 5);

    uint8_t hash[32], dbe[32], kbe[32];
    diff_rng_bytes(rng, hash, 32);
    bn_to_be(&d, dbe, 32);
    bn_to_be(&k, kbe, 32);

    DIFF_OUT(r, 32);
    DIFF_OUT(s, 32);
    const uint64_t rc = p256_ecdsa_sign_with_k(r, s, hash, dbe, kbe);
    DIFF_CHECK_TAIL(r, 32, "p256_ecdsa_sign_with_k r", detail, len);
    DIFF_CHECK_TAIL(s, 32, "p256_ecdsa_sign_with_k s", detail, len);
    if (rc != 0) {
        snprintf(detail, len, "sign_with_k failed (returned %llu)",
                 (unsigned long long)rc);
        return 0;
    }

    // the reference signature
    struct refp256 g, kg;
    refp256_generator(&g);
    refp256_mul(&kg, &k, &g);

    refbn rx, ry;
    if (!refp256_to_affine(&kg, &rx, &ry)) {
        snprintf(detail, len, "reference k*G produced infinity");
        return 0;
    }

    refbn wr, ws, z, kinv, t;
    bn_mod(&wr, &rx, &n);
    bn_from_be(&z, hash, 32);
    bn_mod(&z, &z, &n);
    bn_invmod(&kinv, &k, &n);
    bn_mulmod(&t, &wr, &d, &n);
    bn_addmod(&t, &t, &z, &n);
    bn_mulmod(&ws, &kinv, &t, &n);

    uint8_t want_r[32], want_s[32];
    bn_to_be(&wr, want_r, 32);
    bn_to_be(&ws, want_s, 32);

    if (!diff_eq(r, want_r, 32)) {
        diff_report(detail, len, "ecdsa r", 32, r, want_r, 32);
        return 0;
    }
    if (!diff_eq(s, want_s, 32)) {
        diff_report(detail, len, "ecdsa s", 32, s, want_s, 32);
        return 0;
    }

    // and the verifier must accept it, and reject it once touched
    refbn qx, qy;
    struct refp256 pub;
    refp256_mul(&pub, &d, &g);
    if (!refp256_to_affine(&pub, &qx, &qy)) {
        snprintf(detail, len, "reference public key is infinity");
        return 0;
    }
    uint64_t qxfe[P256_LIMBS], qyfe[P256_LIMBS];
    bn_to_fe(&qx, qxfe);
    bn_to_fe(&qy, qyfe);

    uint8_t qxb[32], qyb[32];
    bn_to_be(&qx, qxb, 32);
    bn_to_be(&qy, qyb, 32);
    (void)qxfe; (void)qyfe;

    if (p256_ecdsa_verify(hash, r, s, qxb, qyb) != 1) {
        snprintf(detail, len,
                 "verify rejected a signature the same code just made");
        return 0;
    }

    const uint64_t bit = diff_rng_below(rng, 32 * 8);
    hash[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    const uint64_t v = p256_ecdsa_verify(hash, r, s, qxb, qyb);
    hash[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    if (v != 0) {
        snprintf(detail, len,
                 "FORGERY ACCEPTED: the signature still verified after "
                 "flipping bit %llu of the message hash",
                 (unsigned long long)bit);
        return 0;
    }

    return 1;
}

int main(void)
{
    diff_init("differential: X25519 / P-256");

    refcurve_selfcheck();

    TEST_SUITE("differential — X25519 field arithmetic");
    diff_sweep("x25519_fe_add / fe_sub", case_25519_addsub, 12000);
    diff_sweep("x25519_fe_mul / sqr / sqr_times / scalar_product",
               case_25519_mul, 4000);
    diff_sweep("x25519_fe_frombytes / fe_tobytes", case_25519_bytes, 6000);
    diff_sweep("x25519_fe_recip", case_25519_recip, 60);

    TEST_SUITE("differential — X25519 scalar multiplication");
    diff_sweep("x25519", case_25519_full, 12);

    TEST_SUITE("differential — P-256 field arithmetic");
    diff_sweep("p256_fe_add / sub / mul / sqr / eq", case_p256_field, 4000);
    diff_sweep("p256_reduce", case_p256_reduce, 8000);
    diff_sweep("p256_bn_mul", case_p256_bn_mul, 6000);
    diff_sweep("p256_fe_tobytes / frombytes", case_p256_bytes, 6000);
    diff_sweep("p256_fe_inv", case_p256_inv, 60);

    TEST_SUITE("differential — P-256 scalar ring");
    diff_sweep("p256_scalar_mul / mont_mul / reduce", case_p256_scalar, 60);
    diff_sweep("p256_scalar_inv", case_p256_scalar_inv, 60);

    TEST_SUITE("differential — P-256 group law");
    diff_sweep("p256_point_dbl / add", case_p256_dbl_add, 40);
    diff_sweep("p256_point_mul / mul_base", case_p256_mul, 10);

    TEST_SUITE("differential — ECDSA");
    diff_sweep("p256_ecdsa_sign_with_k vs the signature equation",
               case_ecdsa, 10);

    test_summary();
    return 0;
}
