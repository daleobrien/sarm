// sarm security tests — X25519 and P-256 against exactly-sized buffers
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 3, for the routines that have no length
// argument at all: every operand is a fixed size fixed by the curve.
//
// For those the boundary question is not "which lengths?" but "does it
// stay inside the size its header declares?" — and that is exactly what
// a guarded buffer of precisely that size answers. A field element is
// 32 bytes (P-256) or 40 (X25519's 5-limb representation); a Jacobian
// point is 96; a round key schedule is 176. Assembly that loads a
// 16-byte vector pair where 32 bytes were promised, or writes a 4-limb
// result into a 3-limb buffer, traps here and nowhere else — the
// globals these normally run against have neighbours, not guard pages
// (docs/SECURITY.md §5).
//
// Correctness at these sizes is checked by algebraic identity rather
// than by a reference implementation: a - a == 0, a * a^-1 == 1,
// P + P == 2P, k*G == k*(G as a point), sign-then-verify. Identities
// need no second implementation to be trustworthy, and the full
// reference-versus-assembly comparison over random vectors is Step 4's
// job, not this one's. The exception is p256_bn_mul, which does take
// limb counts: those are swept against a schoolbook reference below.

#include "bounds_common.h"

// ── X25519 ──────────────────────────────────────────────────────────
#define X25519_FE 40   // 5 x u64 limbs, 51 bits each

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
extern void x25519_fe_recip(void *out, const void *a)
    __asm__("x25519_fe_recip");

// ── P-256 ───────────────────────────────────────────────────────────
#define P256_FE    32   // 4 x u64 limbs
#define P256_POINT 96   // Jacobian X, Y, Z

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
extern void p256_point_to_affine(void *outx, void *outy, const void *in)
    __asm__("p256_point_to_affine");
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
extern uint64_t p256_ecdsa_der_sig_encode(void *out, const void *r,
                                          const void *s)
    __asm__("p256_ecdsa_der_sig_encode");

extern const uint64_t p256_gx[4] __asm__("p256_gx");
extern const uint64_t p256_gy[4] __asm__("p256_gy");

struct side_case { enum guard_side side; };

// ── X25519: the RFC 7748 §5.2 vector, in guarded 32-byte buffers ────

static void probe_x25519_kat(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    static const uint8_t scalar[32] = {
        0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,
        0x82,0x46,0x5e,0xdd,0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,
        0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4,
    };
    static const uint8_t point[32] = {
        0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,
        0x24,0xb1,0x5f,0x7c,0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,
        0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c,
    };
    static const uint8_t want[32] = {
        0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,
        0xf2,0x8d,0x08,0x4f,0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,
        0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52,
    };

    struct guarded_buffer k, u, out;
    if (bounds_out(&k, 32, c->side) != 0 ||
        bounds_out(&u, 32, c->side) != 0 ||
        bounds_out(&out, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    for (int i = 0; i < 32; i++) { k.data[i] = scalar[i]; u.data[i] = point[i]; }

    x25519(out.data, k.data, u.data);

    _exit(bounds_eq(out.data, want, 32) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

// Field-element identities in exactly-40-byte guarded buffers.
static void probe_x25519_fe(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer bytes, a, b, t1, t2, out;
    if (bounds_in(&bytes, 32, c->side, 0x4f) != 0 ||
        bounds_out(&a, X25519_FE, c->side) != 0 ||
        bounds_out(&b, X25519_FE, c->side) != 0 ||
        bounds_out(&t1, X25519_FE, c->side) != 0 ||
        bounds_out(&t2, X25519_FE, c->side) != 0 ||
        bounds_out(&out, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    bytes.data[31] &= 0x7f;                 // canonical: clear the top bit
    x25519_fe_frombytes(a.data, bytes.data);

    // tobytes(frombytes(x)) == x
    x25519_fe_tobytes(out.data, a.data);
    if (!bounds_eq(out.data, bytes.data, 32))
        _exit(BOUNDS_MISMATCH);

    // (a + a) - a == a
    x25519_fe_add(t1.data, a.data, a.data);
    x25519_fe_sub(t2.data, t1.data, a.data);
    uint8_t back[32];
    x25519_fe_tobytes(back, t2.data);
    if (!bounds_eq(back, bytes.data, 32))
        _exit(BOUNDS_MISMATCH);

    // sqr(a) == mul(a, a)
    x25519_fe_sqr(t1.data, a.data);
    x25519_fe_mul(t2.data, a.data, a.data);
    uint8_t s1[32], s2[32];
    x25519_fe_tobytes(s1, t1.data);
    x25519_fe_tobytes(s2, t2.data);
    if (!bounds_eq(s1, s2, 32))
        _exit(BOUNDS_MISMATCH);

    // a * a^-1 == 1  (a is overwhelmingly unlikely to be zero here)
    x25519_fe_recip(t1.data, a.data);
    x25519_fe_mul(t2.data, a.data, t1.data);
    x25519_fe_tobytes(s1, t2.data);
    if (s1[0] != 1)
        _exit(BOUNDS_MISMATCH);
    for (int i = 1; i < 32; i++)
        if (s1[i] != 0)
            _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

// sqr_times(a, n) must equal n applications of sqr — including n == 0,
// which must be the identity and not one squaring.
struct sqr_times_case { uint64_t count; enum guard_side side; };

static void probe_sqr_times(void *ctx)
{
    const struct sqr_times_case *c = (const struct sqr_times_case *)ctx;

    struct guarded_buffer bytes, a, viaLoop, viaTimes;
    if (bounds_in(&bytes, 32, c->side, 0x2b) != 0 ||
        bounds_out(&a, X25519_FE, c->side) != 0 ||
        bounds_out(&viaLoop, X25519_FE, c->side) != 0 ||
        bounds_out(&viaTimes, X25519_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    bytes.data[31] &= 0x7f;
    x25519_fe_frombytes(a.data, bytes.data);

    for (size_t i = 0; i < X25519_FE; i++)
        viaLoop.data[i] = a.data[i];
    for (uint64_t i = 0; i < c->count; i++)
        x25519_fe_sqr(viaLoop.data, viaLoop.data);

    x25519_fe_sqr_times(viaTimes.data, a.data, c->count);

    uint8_t s1[32], s2[32];
    x25519_fe_tobytes(s1, viaLoop.data);
    x25519_fe_tobytes(s2, viaTimes.data);
    _exit(bounds_eq(s1, s2, 32) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_x25519(void)
{
    TEST_SUITE("x25519 — RFC 7748 vector in exactly-32-byte buffers");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "RFC 7748 §5.2 vector, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_x25519_kat, &c);
    }

    TEST_SUITE("x25519 field arithmetic — 40-byte element identities");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label),
                 "frombytes/tobytes/add/sub/sqr/mul/recip, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_x25519_fe, &c);
    }

    TEST_SUITE("x25519_fe_sqr_times — repeat counts (contract: count >= 1)");
    // The sweep starts at 1, not 0, because the loop is a do-while:
    // "subs x8, x8, #1 / b.ne" (sqr_times.S), so a count of 0 wraps to
    // 2^64-1 iterations and the call never returns. That is the
    // documented shape — the header says "count >= 1 in practice" and
    // "the loop always runs at least once, matching the C" of
    // curve25519-donna — and every one of the eleven call sites in the
    // tree passes a compile-time constant >= 1 (nine in fe_recip.S's
    // addition chain, one from fe_sqr's tail call).
    //
    // Still worth knowing, and this suite is how it was found: the
    // first run hung here until guard_probe grew a child-side alarm.
    // A precondition whose violation is an infinite loop rather than a
    // wrong answer is a different risk class from one that returns
    // garbage, so it is recorded in docs/SECURITY.md.
    static const uint64_t counts[] = { 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 50, 100, 255 };
    for (size_t i = 0; i < BOUNDS_N(counts); i++) {
        struct sqr_times_case c = { counts[i], GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "count %3llu",
                 (unsigned long long)counts[i]);
        bounds_case(label, probe_sqr_times, &c);
    }
}

// ── P-256 field arithmetic ──────────────────────────────────────────

static void probe_p256_fe(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer bytes, a, t1, t2, out;
    if (bounds_in(&bytes, 32, c->side, 0x17) != 0 ||
        bounds_out(&a, P256_FE, c->side) != 0 ||
        bounds_out(&t1, P256_FE, c->side) != 0 ||
        bounds_out(&t2, P256_FE, c->side) != 0 ||
        bounds_out(&out, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // keep the value comfortably below p by clearing the top byte
    bytes.data[0] = 0x00;
    p256_fe_frombytes(a.data, bytes.data);

    // tobytes(frombytes(x)) == x
    p256_fe_tobytes(out.data, a.data);
    if (!bounds_eq(out.data, bytes.data, 32))
        _exit(BOUNDS_MISMATCH);

    // (a + a) - a == a
    p256_fe_add(t1.data, a.data, a.data);
    p256_fe_sub(t2.data, t1.data, a.data);
    if (!p256_fe_eq(t2.data, a.data))
        _exit(BOUNDS_MISMATCH);

    // a - a == 0
    p256_fe_sub(t1.data, a.data, a.data);
    uint8_t zero_fe[P256_FE] = {0};
    if (!p256_fe_eq(t1.data, zero_fe))
        _exit(BOUNDS_MISMATCH);

    // sqr(a) == mul(a, a)
    p256_fe_sqr(t1.data, a.data);
    p256_fe_mul(t2.data, a.data, a.data);
    if (!p256_fe_eq(t1.data, t2.data))
        _exit(BOUNDS_MISMATCH);

    // a * a^-1 == 1
    p256_fe_inv(t1.data, a.data);
    p256_fe_mul(t2.data, a.data, t1.data);
    p256_fe_tobytes(out.data, t2.data);
    for (int i = 0; i < 31; i++)
        if (out.data[i] != 0)
            _exit(BOUNDS_MISMATCH);
    if (out.data[31] != 1)
        _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

// p256_reduce takes an 8-limb product and writes 4 limbs. Guarding both
// at exactly their declared sizes is the whole test: a reduction that
// reads a ninth limb, or writes a fifth, traps.
static void probe_p256_reduce(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer t, out, a, b, prod;
    if (bounds_in(&t, 64, c->side, 0x8d) != 0 ||
        bounds_out(&out, P256_FE, c->side) != 0 ||
        bounds_in(&a, P256_FE, c->side, 0x35) != 0 ||
        bounds_in(&b, P256_FE, c->side, 0x9c) != 0 ||
        bounds_out(&prod, 64, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    p256_reduce(out.data, t.data);

    // Cross-check against the path the field multiplier takes: reducing
    // the 8-limb product of a and b must equal p256_fe_mul(a, b).
    struct guarded_buffer viaMul, viaReduce;
    if (bounds_out(&viaMul, P256_FE, c->side) != 0 ||
        bounds_out(&viaReduce, P256_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    p256_bn_mul(prod.data, a.data, 4, b.data, 4);
    p256_reduce(viaReduce.data, prod.data);
    p256_fe_mul(viaMul.data, a.data, b.data);

    _exit(p256_fe_eq(viaMul.data, viaReduce.data) ? BOUNDS_PASS
                                                  : BOUNDS_MISMATCH);
}

// ── p256_bn_mul: the one P-256 routine with a length argument ───────

struct bn_case {
    size_t na;
    size_t nb;
    enum guard_side side;
};

// schoolbook multiply over u64 limbs, little-endian, via __uint128_t
static void ref_bn_mul(uint64_t *out, const uint64_t *a, size_t na,
                       const uint64_t *b, size_t nb)
{
    for (size_t i = 0; i < na + nb; i++)
        out[i] = 0;
    for (size_t i = 0; i < na; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < nb; j++) {
            __uint128_t acc = (__uint128_t)a[i] * b[j];
            acc += out[i + j];
            acc += carry;
            out[i + j] = (uint64_t)acc;
            carry = (uint64_t)(acc >> 64);
        }
        out[i + nb] += carry;
    }
}

static void probe_bn_mul(void *ctx)
{
    const struct bn_case *c = (const struct bn_case *)ctx;

    struct guarded_buffer a, b, out;
    if (bounds_in(&a, c->na * 8, c->side, 0x51) != 0 ||
        bounds_in(&b, c->nb * 8, c->side, 0xa7) != 0 ||
        bounds_out(&out, (c->na + c->nb) * 8, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    p256_bn_mul(out.data, a.data, c->na, b.data, c->nb);

    uint64_t want[32];
    ref_bn_mul(want, (const uint64_t *)a.data, c->na,
               (const uint64_t *)b.data, c->nb);

    _exit(bounds_eq(out.data, (const uint8_t *)want, (c->na + c->nb) * 8)
          ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_p256_field(void)
{
    TEST_SUITE("p256 field arithmetic — 32-byte element identities");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label),
                 "frombytes/tobytes/add/sub/sqr/mul/inv, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_p256_fe, &c);
    }

    TEST_SUITE("p256_reduce — 8 limbs in, 4 limbs out");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "reduce(bn_mul(a,b)) == fe_mul(a,b), %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_p256_reduce, &c);
    }

    TEST_SUITE("p256_bn_mul — limb counts vs a schoolbook reference");
    // The in-tree callers only ever ask for 4x4, so every other shape
    // here is testing a path the server never takes — which is the
    // point: the function's contract is na x nb, and Step 5's checked
    // arithmetic audit needs to know whether the contract holds.
    for (size_t na = 1; na <= 8; na++) {
        for (size_t nb = 1; nb <= 8; nb++) {
            struct bn_case c = { na, nb, GUARD_OVERRUN };
            char label[96];
            snprintf(label, sizeof(label), "%zu x %zu limbs", na, nb);
            bounds_case(label, probe_bn_mul, &c);
        }
    }
    for (size_t na = 1; na <= 4; na++) {
        struct bn_case c = { na, 4, GUARD_UNDERRUN };
        char label[96];
        snprintf(label, sizeof(label), "%zu x 4 limbs, underrun-guarded", na);
        bounds_case(label, probe_bn_mul, &c);
    }
}

// ── P-256 scalar arithmetic (mod n) ─────────────────────────────────

static void probe_p256_scalar(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer raw, a, b, t1, t2, one, r1, r2;
    if (bounds_in(&raw, P256_FE, c->side, 0x63) != 0 ||
        bounds_out(&a, P256_FE, c->side) != 0 ||
        bounds_in(&b, P256_FE, c->side, 0xc1) != 0 ||
        bounds_out(&t1, P256_FE, c->side) != 0 ||
        bounds_out(&t2, P256_FE, c->side) != 0 ||
        bounds_out(&one, P256_FE, c->side) != 0 ||
        bounds_out(&r1, P256_FE, c->side) != 0 ||
        bounds_out(&r2, P256_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // bring both operands below n
    ((uint64_t *)raw.data)[3] &= 0x00ffffffffffffffULL;
    ((uint64_t *)b.data)[3]   &= 0x00ffffffffffffffULL;
    p256_scalar_reduce(a.data, raw.data);

    // mont_mul is commutative
    p256_scalar_mont_mul(t1.data, a.data, b.data);
    p256_scalar_mont_mul(t2.data, b.data, a.data);
    if (!bounds_eq(t1.data, t2.data, P256_FE))
        _exit(BOUNDS_MISMATCH);

    // mont_mul(a, a^-1) == mont_mul(1, 1): both are R^-1 mod n, so the
    // identity holds without needing to know R.
    for (size_t i = 0; i < P256_FE; i++)
        one.data[i] = 0;
    ((uint64_t *)one.data)[0] = 1;

    p256_scalar_inv(t1.data, a.data);
    p256_scalar_mont_mul(r1.data, a.data, t1.data);
    p256_scalar_mont_mul(r2.data, one.data, one.data);
    if (!bounds_eq(r1.data, r2.data, P256_FE))
        _exit(BOUNDS_MISMATCH);

    // scalar_mul agrees with reduce(bn_mul(a,b)) by construction; check
    // it at least agrees with itself under commutation
    p256_scalar_mul(t1.data, a.data, b.data);
    p256_scalar_mul(t2.data, b.data, a.data);
    if (!bounds_eq(t1.data, t2.data, P256_FE))
        _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

// ── P-256 group arithmetic ──────────────────────────────────────────

static void probe_p256_point(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer g, dbl, add, ax, ay, bx, by;
    if (bounds_out(&g, P256_POINT, c->side) != 0 ||
        bounds_out(&dbl, P256_POINT, c->side) != 0 ||
        bounds_out(&add, P256_POINT, c->side) != 0 ||
        bounds_out(&ax, P256_FE, c->side) != 0 ||
        bounds_out(&ay, P256_FE, c->side) != 0 ||
        bounds_out(&bx, P256_FE, c->side) != 0 ||
        bounds_out(&by, P256_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // G in Jacobian coordinates: (gx, gy, 1)
    uint64_t *gp = (uint64_t *)g.data;
    for (int i = 0; i < 4; i++) gp[i] = p256_gx[i];
    for (int i = 0; i < 4; i++) gp[4 + i] = p256_gy[i];
    for (int i = 0; i < 4; i++) gp[8 + i] = 0;
    // Z = 1 in whatever representation fe_frombytes produces for 1
    {
        uint8_t one_be[32] = {0};
        one_be[31] = 1;
        p256_fe_frombytes(g.data + 64, one_be);
    }

    // G + G == 2G
    p256_point_dbl(dbl.data, g.data);
    p256_point_add(add.data, g.data, g.data);
    p256_point_to_affine(ax.data, ay.data, dbl.data);
    p256_point_to_affine(bx.data, by.data, add.data);
    if (!p256_fe_eq(ax.data, bx.data) || !p256_fe_eq(ay.data, by.data))
        _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

// k*G computed by the fixed-base comb must equal k*(G as a general
// point) through the generic ladder. Two different code paths, one
// answer — which is the only check either can be given without a
// reference implementation.
struct scalarmul_case { uint64_t k; enum guard_side side; };

static void probe_p256_mul_base(void *ctx)
{
    const struct scalarmul_case *c = (const struct scalarmul_case *)ctx;

    struct guarded_buffer k, gx, gy, bx, by, mx, my;
    if (bounds_out(&k, P256_FE, c->side) != 0 ||
        bounds_out(&gx, P256_FE, c->side) != 0 ||
        bounds_out(&gy, P256_FE, c->side) != 0 ||
        bounds_out(&bx, P256_FE, c->side) != 0 ||
        bounds_out(&by, P256_FE, c->side) != 0 ||
        bounds_out(&mx, P256_FE, c->side) != 0 ||
        bounds_out(&my, P256_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    uint64_t *kp = (uint64_t *)k.data;
    kp[0] = c->k; kp[1] = 0; kp[2] = 0; kp[3] = 0;
    for (int i = 0; i < 4; i++) ((uint64_t *)gx.data)[i] = p256_gx[i];
    for (int i = 0; i < 4; i++) ((uint64_t *)gy.data)[i] = p256_gy[i];

    p256_point_mul_base(bx.data, by.data, k.data);
    p256_point_mul(mx.data, my.data, k.data, gx.data, gy.data);

    if (!p256_fe_eq(bx.data, mx.data) || !p256_fe_eq(by.data, my.data))
        _exit(BOUNDS_MISMATCH);
    _exit(BOUNDS_PASS);
}

static void test_p256_group(void)
{
    TEST_SUITE("p256 scalar arithmetic — 32-byte operands mod n");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "reduce/mont_mul/inv/mul, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_p256_scalar, &c);
    }

    TEST_SUITE("p256 group arithmetic — 96-byte Jacobian points");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "G + G == 2G, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_p256_point, &c);
    }

    TEST_SUITE("p256_point_mul_base vs p256_point_mul (comb vs ladder)");
    // 1 and 2 exercise the smallest scalars; the powers of two land on
    // comb-window boundaries; the odd values in between do not.
    static const uint64_t ks[] = { 1, 2, 3, 4, 5, 15, 16, 17, 255, 256, 257, 65535, 65536 };
    for (size_t i = 0; i < BOUNDS_N(ks); i++) {
        struct scalarmul_case c = { ks[i], GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "k = %llu", (unsigned long long)ks[i]);
        bounds_case(label, probe_p256_mul_base, &c);
    }
}

// ── ECDSA ───────────────────────────────────────────────────────────

static void probe_ecdsa(void *ctx)
{
    const struct side_case *c = (const struct side_case *)ctx;

    struct guarded_buffer d, k, hash, r, s, qx, qy, der;
    if (bounds_in(&d, 32, c->side, 0x19) != 0 ||
        bounds_in(&k, 32, c->side, 0x7d) != 0 ||
        bounds_in(&hash, 32, c->side, 0xb5) != 0 ||
        bounds_out(&r, 32, c->side) != 0 ||
        bounds_out(&s, 32, c->side) != 0 ||
        bounds_out(&qx, P256_FE, c->side) != 0 ||
        bounds_out(&qy, P256_FE, c->side) != 0 ||
        bounds_out(&der, 72, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // keep d and k in range: clear the top byte of each big-endian value
    d.data[0] = 0x01;
    k.data[0] = 0x01;

    if (p256_ecdsa_sign_with_k(r.data, s.data, hash.data, d.data, k.data) != 0)
        _exit(BOUNDS_MISMATCH);

    // Q = d*G, the public key the signature must verify against
    struct guarded_buffer dscalar;
    if (bounds_out(&dscalar, P256_FE, c->side) != 0)
        _exit(BOUNDS_BADSETUP);
    // d arrives big-endian; the point routines want limbs
    p256_fe_frombytes(dscalar.data, d.data);
    p256_point_mul_base(qx.data, qy.data, dscalar.data);

    uint8_t qx_be[32], qy_be[32];
    p256_fe_tobytes(qx_be, qx.data);
    p256_fe_tobytes(qy_be, qy.data);

    if (p256_ecdsa_verify(hash.data, r.data, s.data, qx_be, qy_be) != 1)
        _exit(BOUNDS_MISMATCH);

    // a tampered hash must not verify
    hash.data[31] ^= 0x01;
    if (p256_ecdsa_verify(hash.data, r.data, s.data, qx_be, qy_be) != 0)
        _exit(BOUNDS_MISMATCH);
    hash.data[31] ^= 0x01;

    // a tampered r must not verify
    r.data[31] ^= 0x01;
    if (p256_ecdsa_verify(hash.data, r.data, s.data, qx_be, qy_be) != 0)
        _exit(BOUNDS_MISMATCH);
    r.data[31] ^= 0x01;

    // DER encoding must fit the 72-byte buffer its header promises
    const uint64_t der_len = p256_ecdsa_der_sig_encode(der.data, r.data, s.data);
    if (der_len < 8 || der_len > 72)
        _exit(BOUNDS_MISMATCH);
    if (der.data[0] != 0x30 || der.data[1] != (uint8_t)(der_len - 2))
        _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

static void test_ecdsa(void)
{
    TEST_SUITE("p256 ECDSA — sign, verify, reject tampering, DER encode");
    for (int s = 0; s < 2; s++) {
        struct side_case c = { s ? GUARD_UNDERRUN : GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label),
                 "sign_with_k -> verify -> der_encode, %s",
                 bounds_side_name(c.side));
        bounds_case(label, probe_ecdsa, &c);
    }
}

int main(void)
{
    bounds_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  bounds: X25519 + P-256                   ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    test_x25519();
    test_p256_field();
    test_p256_group();
    test_ecdsa();

    test_summary();
    return 0;
}
