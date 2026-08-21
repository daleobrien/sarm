// sarm security tests — a deliberately naive big-integer reference
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/refbn.h — arbitrary-precision modular
//   arithmetic, for judging the ECC assembly (docs/SECURITY.md, Step 4)
//
// Description: Step 3 checked the curve routines by algebraic identity
//   (a * a^-1 == 1, P + P == 2P) because identities need no second
//   implementation. Identities are sound but narrow: they hold for the
//   correct answer and for any bug that happens to be self-consistent
//   under the same identity — a field multiplier that reduces modulo
//   the wrong prime still satisfies a * a^-1 == 1 in the wrong field.
//   Step 4 wants the actual value, which needs an actual reference.
//
//   So: schoolbook multiplication into 32-bit limbs, and reduction by
//   shift-and-subtract long division, one bit at a time. No Montgomery
//   form, no Solinas reduction, no lazy carries, no 64-bit limbs —
//   every trick the assembly uses is absent here on purpose. A
//   reference that shares the representation shares the carry bug; the
//   whole value of a differential test is that the two sides fail
//   differently.
//
//   Speed is the price. A single modular multiplication is a few
//   thousand word operations and a modular inverse is a few hundred of
//   those, which is why the ECC suite runs thousands of vectors through
//   the field operations and only a handful through scalar
//   multiplication. That ratio is deliberate, not a shortcut: the field
//   operations are where the carry bugs live.
//
// Representation: little-endian uint32_t limbs, fixed width, values
//   always non-negative. Everything is fixed-width and branch-happy;
//   nothing here is constant-time and nothing here needs to be — the
//   reference never touches a secret that the assembly under test has
//   not already been handed.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_REFBN_H
#define SARM_REFBN_H

#include <stdint.h>
#include <stddef.h>

// 1280 bits. The widest thing anything here multiplies is the 8x8-limb
// (512 x 512 bit) shape p256_bn_mul supports, whose product is 1024
// bits, plus room for the intermediate shifts in bn_mod — so no
// operation can silently truncate. Sizing this to the 512-bit products
// of the *field* code would be enough for P-256 and wrong for
// p256_bn_mul, which is exactly the sort of quiet truncation that
// makes a reference lie.
#define REFBN_LIMBS 40
#define REFBN_BITS  (REFBN_LIMBS * 32)

typedef struct { uint32_t v[REFBN_LIMBS]; } refbn;

static void bn_zero(refbn *r)
{
    for (int i = 0; i < REFBN_LIMBS; i++) r->v[i] = 0;
}

static void bn_copy(refbn *r, const refbn *a)
{
    for (int i = 0; i < REFBN_LIMBS; i++) r->v[i] = a->v[i];
}

static void bn_set_u32(refbn *r, uint32_t x)
{
    bn_zero(r);
    r->v[0] = x;
}

static int bn_is_zero(const refbn *a)
{
    uint32_t acc = 0;
    for (int i = 0; i < REFBN_LIMBS; i++) acc |= a->v[i];
    return acc == 0;
}

// -1, 0, +1
static int bn_cmp(const refbn *a, const refbn *b)
{
    for (int i = REFBN_LIMBS - 1; i >= 0; i--) {
        if (a->v[i] != b->v[i]) return a->v[i] < b->v[i] ? -1 : 1;
    }
    return 0;
}

static int bn_eq(const refbn *a, const refbn *b) { return bn_cmp(a, b) == 0; }

static int bn_bit(const refbn *a, int i)
{
    if (i < 0 || i >= REFBN_BITS) return 0;
    return (int)((a->v[i >> 5] >> (i & 31)) & 1u);
}

// Number of significant limbs; used to skip work on limbs that are
// known to be zero. Skipping zeros changes no algorithm here — the
// multiply is still schoolbook and the reduction is still bit by bit —
// it just stops a 256-bit operand from paying for 1280 bits of padding
// on every operation.
static int bn_limbs(const refbn *a)
{
    for (int i = REFBN_LIMBS - 1; i >= 0; i--)
        if (a->v[i]) return i + 1;
    return 0;
}

// Index of the highest set bit, plus one; 0 for zero.
static int bn_bitlen(const refbn *a)
{
    const int n = bn_limbs(a);
    if (n == 0) return 0;
    uint32_t top = a->v[n - 1];
    int bits = 0;
    while (top) { bits++; top >>= 1; }
    return (n - 1) * 32 + bits;
}

// r = a + b, discarding any carry out of the top limb. Every caller
// here works well below 768 bits, so a carry out would be a bug in the
// caller rather than a value to represent.
static void bn_add(refbn *r, const refbn *a, const refbn *b)
{
    uint64_t carry = 0;
    for (int i = 0; i < REFBN_LIMBS; i++) {
        const uint64_t t = (uint64_t)a->v[i] + b->v[i] + carry;
        r->v[i] = (uint32_t)t;
        carry = t >> 32;
    }
}

// r = a - b, requiring a >= b.
static void bn_sub(refbn *r, const refbn *a, const refbn *b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < REFBN_LIMBS; i++) {
        const uint64_t t = (uint64_t)a->v[i] - b->v[i] - borrow;
        r->v[i] = (uint32_t)t;
        borrow = (t >> 32) & 1u;
    }
}

static void bn_shl(refbn *r, const refbn *a, int bits)
{
    refbn t;
    bn_zero(&t);
    const int words = bits >> 5, sh = bits & 31;
    for (int i = REFBN_LIMBS - 1; i >= 0; i--) {
        const int src = i - words;
        if (src < 0) continue;
        uint32_t x = a->v[src] << sh;
        if (sh && src > 0) x |= a->v[src - 1] >> (32 - sh);
        t.v[i] = x;
    }
    bn_copy(r, &t);
}

// r = a * b, schoolbook, truncated at 768 bits.
static void bn_mul(refbn *r, const refbn *a, const refbn *b)
{
    refbn t;
    bn_zero(&t);
    const int nb = bn_limbs(b);
    for (int i = 0; i < REFBN_LIMBS; i++) {
        if (a->v[i] == 0) continue;
        uint64_t carry = 0;
        int j = 0;
        for (; j < nb && i + j < REFBN_LIMBS; j++) {
            const uint64_t p = (uint64_t)a->v[i] * b->v[j]
                             + t.v[i + j] + carry;
            t.v[i + j] = (uint32_t)p;
            carry = p >> 32;
        }
        for (; carry && i + j < REFBN_LIMBS; j++) {
            const uint64_t p = (uint64_t)t.v[i + j] + carry;
            t.v[i + j] = (uint32_t)p;
            carry = p >> 32;
        }
    }
    bn_copy(r, &t);
}

// r = a mod m, by long division one bit at a time. The whole point is
// that this shares no structure with the assembly's reduction: no
// precomputed mu, no exploitation of the shape of the prime, nothing
// that could be wrong in the same direction.
static void bn_mod(refbn *r, const refbn *a, const refbn *m)
{
    const int mb = bn_bitlen(m);
    if (mb == 0) { bn_zero(r); return; }

    // The remainder is always < m, so it only ever occupies as many
    // limbs as m does (plus one for the bit shifted in before the
    // subtract). Working at that width instead of the full 768 bits is
    // the difference between a reference that is slow and one that is
    // too slow to run millions of times.
    int nl = (mb + 31) / 32 + 1;
    if (nl > REFBN_LIMBS) nl = REFBN_LIMBS;

    uint32_t rem[REFBN_LIMBS];
    for (int i = 0; i < nl; i++) rem[i] = 0;

    for (int i = bn_bitlen(a) - 1; i >= 0; i--) {
        uint32_t carry = (uint32_t)bn_bit(a, i);
        for (int j = 0; j < nl; j++) {
            const uint32_t next = rem[j] >> 31;
            rem[j] = (rem[j] << 1) | carry;
            carry = next;
        }

        int ge = 1;
        for (int j = nl - 1; j >= 0; j--) {
            if (rem[j] != m->v[j]) { ge = rem[j] > m->v[j]; break; }
        }
        if (ge) {
            uint64_t borrow = 0;
            for (int j = 0; j < nl; j++) {
                const uint64_t t = (uint64_t)rem[j] - m->v[j] - borrow;
                rem[j] = (uint32_t)t;
                borrow = (t >> 32) & 1u;
            }
        }
    }

    bn_zero(r);
    for (int i = 0; i < nl; i++) r->v[i] = rem[i];
}

static void bn_addmod(refbn *r, const refbn *a, const refbn *b, const refbn *m)
{
    refbn t;
    bn_add(&t, a, b);
    bn_mod(r, &t, m);
}

static void bn_submod(refbn *r, const refbn *a, const refbn *b, const refbn *m)
{
    refbn ra, rb, t;
    bn_mod(&ra, a, m);
    bn_mod(&rb, b, m);
    if (bn_cmp(&ra, &rb) >= 0) {
        bn_sub(&t, &ra, &rb);
    } else {
        bn_add(&t, &ra, m);
        bn_sub(&t, &t, &rb);
    }
    bn_copy(r, &t);
}

static void bn_mulmod(refbn *r, const refbn *a, const refbn *b, const refbn *m)
{
    refbn t;
    bn_mul(&t, a, b);
    bn_mod(r, &t, m);
}

// Square-and-multiply, most significant bit first. Not constant-time,
// deliberately: see the header comment.
static void bn_powmod(refbn *r, const refbn *a, const refbn *e, const refbn *m)
{
    refbn acc, base;
    bn_set_u32(&acc, 1);
    bn_mod(&base, a, m);

    for (int i = bn_bitlen(e) - 1; i >= 0; i--) {
        bn_mulmod(&acc, &acc, &acc, m);
        if (bn_bit(e, i)) bn_mulmod(&acc, &acc, &base, m);
    }
    bn_copy(r, &acc);
}

// a^(m-2) mod m, i.e. the inverse for prime m. Zero has no inverse and
// comes back as zero, matching what the assembly does with it.
static void bn_invmod(refbn *r, const refbn *a, const refbn *m)
{
    refbn e, two;
    bn_set_u32(&two, 2);
    bn_sub(&e, m, &two);
    bn_powmod(r, a, &e, m);
}

// ── conversions ─────────────────────────────────────────────────────

static void bn_from_le(refbn *r, const uint8_t *p, size_t len)
{
    bn_zero(r);
    for (size_t i = 0; i < len && i < REFBN_LIMBS * 4u; i++)
        r->v[i >> 2] |= (uint32_t)p[i] << ((i & 3) * 8);
}

static void bn_from_be(refbn *r, const uint8_t *p, size_t len)
{
    bn_zero(r);
    for (size_t i = 0; i < len; i++) {
        const size_t j = len - 1 - i;
        if (i >= REFBN_LIMBS * 4u) break;
        r->v[i >> 2] |= (uint32_t)p[j] << ((i & 3) * 8);
    }
}

static void bn_to_le(const refbn *a, uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (i < REFBN_LIMBS * 4u)
             ? (uint8_t)(a->v[i >> 2] >> ((i & 3) * 8)) : 0u;
}

static void bn_to_be(const refbn *a, uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        const size_t j = len - 1 - i;
        p[j] = (i < REFBN_LIMBS * 4u)
             ? (uint8_t)(a->v[i >> 2] >> ((i & 3) * 8)) : 0u;
    }
}

// Little-endian uint64 limbs, which is how both curves lay a field
// element out in memory.
static void bn_from_u64s(refbn *r, const uint64_t *l, size_t n)
{
    bn_zero(r);
    for (size_t i = 0; i < n && (2 * i + 1) < REFBN_LIMBS; i++) {
        r->v[2 * i]     = (uint32_t)l[i];
        r->v[2 * i + 1] = (uint32_t)(l[i] >> 32);
    }
}

static void bn_to_u64s(const refbn *a, uint64_t *l, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const uint64_t lo = (2 * i)     < REFBN_LIMBS ? a->v[2 * i]     : 0u;
        const uint64_t hi = (2 * i + 1) < REFBN_LIMBS ? a->v[2 * i + 1] : 0u;
        l[i] = lo | (hi << 32);
    }
}

// X25519 keeps a field element as five limbs of 51 bits, which are not
// reduced to a canonical value between operations. Comparing against a
// reference therefore has to go through the integer the limbs denote,
// not the bytes they are stored in.
static void bn_from_limbs51(refbn *r, const uint64_t *l, size_t n)
{
    bn_zero(r);
    for (size_t i = 0; i < n; i++) {
        refbn t, s;
        bn_zero(&t);
        t.v[0] = (uint32_t)l[i];
        t.v[1] = (uint32_t)(l[i] >> 32);
        bn_shl(&s, &t, (int)(51 * i));
        bn_add(r, r, &s);
    }
}

// ── the two primes and the two group orders ─────────────────────────

// p256: 2^256 - 2^224 + 2^192 + 2^96 - 1
static void bn_p256_p(refbn *r)
{
    static const uint8_t be[32] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    };
    bn_from_be(r, be, 32);
}

// the order of the P-256 base point
static void bn_p256_n(refbn *r)
{
    static const uint8_t be[32] = {
        0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,
        0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51,
    };
    bn_from_be(r, be, 32);
}

// 2^255 - 19
static void bn_25519_p(refbn *r)
{
    refbn one, t;
    bn_set_u32(&one, 1);
    bn_shl(&t, &one, 255);
    bn_set_u32(&one, 19);
    bn_sub(r, &t, &one);
}

// R = 2^256, the Montgomery radix both scalar routines use
static void bn_r256(refbn *r)
{
    refbn one;
    bn_set_u32(&one, 1);
    bn_shl(r, &one, 256);
}

#endif // SARM_REFBN_H
