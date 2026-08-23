// Unit tests for src/crypto/x25519.S
//
// The asm file exports eleven symbols:
//   x25519                — X25519 scalar multiplication: out = scalar * point
//                           (out=x0, scalar=x1, point=x2), RFC 7748 §5
//   x25519_fe_frombytes   — expand 32 little-endian bytes to 5x51 limbs
//                           (out=x0, in=x1)
//   x25519_fe_tobytes     — contract to 32 little-endian bytes, canonical mod p
//                           (out=x0, in=x1)
//   x25519_fe_add         — a + b mod p (out=x0, a=x1, b=x2)
//   x25519_fe_sub         — a - b mod p (out=x0, a=x1, b=x2)
//   x25519_fe_mul         — a * b mod p (out=x0, a=x1, b=x2)
//   x25519_fe_sqr         — a^2 mod p (out=x0, a=x1)
//   x25519_fe_sqr_times   — a^(2^count) mod p (out=x0, a=x1, count=x2)
//   x25519_fe_scalar_product — a * scalar mod p (out=x0, a=x1, scalar=x2)
//   x25519_fe_recip       — a^(p-2) mod p, the field inversion (out=x0, a=x1)
//   x25519_swap_conditional — constant-time conditional swap (x=x0, qpx=x1,
//                             iswap=x2)
//
// A field element ("fe") is 5 x 51-bit limbs in little-endian order
// (limb 0 least significant), 40 bytes total, working mod p = 2^255-19.
// All helpers are safe when out aliases a and/or b (the ladder relies on
// in-place semantics like sub(nqz, nqx, nqz)).
//
// The asm symbols are bare (no leading underscore, matching the rest of
// the codebase), so the C declarations below pin them with __asm__ labels
// to bypass the Mach-O underscore mangling of C names.
//
// These tests drive the asm against:
//   1. the RFC 7748 §5.2 known-answer vectors,
//   2. the RFC 7748 §6.1 iterative test (1 and 1000 iterations) and the
//      §6.1 Diffie-Hellman vector,
//   3. an independent plain-C reference implementation in this file (the
//      same 5x51 curve25519-donna algorithm the asm is a translation of),
//      cross-checked limb-exact over deterministic sweeps of random
//      inputs, buffer-alias cases, and edge values,
//   4. hard-coded expected values for edge cases (all-zero point, the
//      clamped-zero scalar, non-canonical u-coordinates) that were
//      independently computed with a big-integer RFC 7748 implementation.
//
// The 1,000,000-iteration RFC 7748 §6.1 test is intentionally not run:
// a million ladder evaluations would exceed the test harness's 5-second
// SIGALRM timeout (each call is ~100-200 us). The 1- and 1000-iteration
// values pin the chain.

#include "test_harness.h"

extern void x25519_fe_frombytes(uint64_t out[5], const uint8_t s[32])
    __asm__("x25519_fe_frombytes");
extern void x25519_fe_tobytes(uint8_t out[32], const uint64_t in[5])
    __asm__("x25519_fe_tobytes");
extern void x25519_fe_add(uint64_t out[5], const uint64_t a[5],
                          const uint64_t b[5]) __asm__("x25519_fe_add");
extern void x25519_fe_sub(uint64_t out[5], const uint64_t a[5],
                          const uint64_t b[5]) __asm__("x25519_fe_sub");
extern void x25519_fe_mul(uint64_t out[5], const uint64_t a[5],
                          const uint64_t b[5]) __asm__("x25519_fe_mul");
extern void x25519_fe_sqr(uint64_t out[5], const uint64_t a[5])
    __asm__("x25519_fe_sqr");
extern void x25519_fe_sqr_times(uint64_t out[5], const uint64_t a[5],
                                uint64_t count)
    __asm__("x25519_fe_sqr_times");
extern void x25519_fe_scalar_product(uint64_t out[5], const uint64_t a[5],
                                     uint64_t scalar)
    __asm__("x25519_fe_scalar_product");
extern void x25519_fe_recip(uint64_t out[5], const uint64_t a[5])
    __asm__("x25519_fe_recip");
extern void x25519_swap_conditional(uint64_t x[5], uint64_t qpx[5],
                                    uint64_t iswap)
    __asm__("x25519_swap_conditional");
extern void x25519(uint8_t out[32], const uint8_t scalar[32],
                   const uint8_t point[32]) __asm__("x25519");

// ── RFC 7748 test vectors ─────────────────────────────────────────────

static const char *V1_SCALAR =
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
static const char *V1_POINT =
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
static const char *V1_OUT =
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
static const char *V2_SCALAR =
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
static const char *V2_POINT =
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
static const char *V2_OUT =
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";

// RFC 7748 §6.1 Diffie-Hellman vector (a, b and the shared secret).
static const char *DH_A =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
static const char *DH_B =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
static const char *DH_A_PUB =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
static const char *DH_B_PUB =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
static const char *DH_K =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

// RFC 7748 §6.1 iterative chain, k = u = 09 00...00.
static const char *IT_ONE =
    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079";
static const char *IT_1000 =
    "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";

// Edge expectations computed with an independent big-integer RFC 7748
// implementation (Python).
static const char *ZERO_SCALAR_BASEPOINT =
    "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74";
static const char *NONCANON_A =
    "359668d79a67267a57ffef8f0f4a9882a7c0e3122cb1999c5626346383f9f811";

// ── plain-C reference (curve25519-donna algorithm, 5x51 limbs) ────────

typedef uint64_t fe[5];

#define M51 0x7FFFFFFFFFFFFULL           // 2^51 - 1
#define TWO54M152 0x3fffffffffff68ULL    // 2^54 - 152: sub's p-multiple
#define TWO54M8 0x3ffffffffffff8ULL      // 2^54 - 8

static void ref_frombytes(fe out, const uint8_t *s) {
    uint64_t x0, x1, x2, x3;
    memcpy(&x0, s + 0, 8);
    memcpy(&x1, s + 8, 8);
    memcpy(&x2, s + 16, 8);
    memcpy(&x3, s + 24, 8);
    out[0] = x0 & M51; x0 = (x0 >> 51) | (x1 << 13);
    out[1] = x0 & M51; x1 = (x1 >> 38) | (x2 << 26);
    out[2] = x1 & M51; x2 = (x2 >> 25) | (x3 << 39);
    out[3] = x2 & M51; x3 = (x3 >> 12);
    out[4] = x3 & M51;
}

static void ref_tobytes(uint8_t *out, const fe in) {
    uint64_t t[5];
    memcpy(t, in, 40);
#define CARRY() do { \
    t[1] += t[0] >> 51; t[0] &= M51; \
    t[2] += t[1] >> 51; t[1] &= M51; \
    t[3] += t[2] >> 51; t[2] &= M51; \
    t[4] += t[3] >> 51; t[3] &= M51; } while (0)
#define CARRY_FULL() do { CARRY(); t[0] += 19 * (t[4] >> 51); t[4] &= M51; } while (0)
#define CARRY_FINAL() do { CARRY(); t[4] &= M51; } while (0)
    CARRY_FULL();
    CARRY_FULL();
    t[0] += 19;
    CARRY_FULL();
    // 2^255-offset: (2^51-19, 2^51-1, ...) is exactly p, so a final
    // carry pass canonicalises v + p mod 2^255 to v mod p.
    t[0] += 0x8000000000000ULL - 19;
    t[1] += 0x8000000000000ULL - 1;
    t[2] += 0x8000000000000ULL - 1;
    t[3] += 0x8000000000000ULL - 1;
    t[4] += 0x8000000000000ULL - 1;
    CARRY_FINAL();
    uint64_t f;
    f = t[0] | (t[1] << 51);
    for (int i = 0; i < 8; i++) { out[i] = (uint8_t)f; f >>= 8; }
    f = (t[1] >> 13) | (t[2] << 38);
    for (int i = 0; i < 8; i++) { out[i + 8] = (uint8_t)f; f >>= 8; }
    f = (t[2] >> 26) | (t[3] << 25);
    for (int i = 0; i < 8; i++) { out[i + 16] = (uint8_t)f; f >>= 8; }
    f = (t[3] >> 39) | (t[4] << 12);
    for (int i = 0; i < 8; i++) { out[i + 24] = (uint8_t)f; f >>= 8; }
#undef CARRY
#undef CARRY_FULL
#undef CARRY_FINAL
}

static void ref_add(fe out, const fe a, const fe b) {
    for (int i = 0; i < 5; i++) out[i] = a[i] + b[i];
}

static void ref_sub(fe out, const fe a, const fe b) {
    out[0] = a[0] + TWO54M152 - b[0];
    for (int i = 1; i < 5; i++) out[i] = a[i] + TWO54M8 - b[i];
}

static void ref_mul(fe out, const fe a, const fe b) {
    __uint128_t t[5];
    uint64_t r[5], s[5], c;
    for (int i = 0; i < 5; i++) { s[i] = a[i]; r[i] = b[i]; }
    t[0] = (__uint128_t)r[0] * s[0];
    t[1] = (__uint128_t)r[0] * s[1] + (__uint128_t)r[1] * s[0];
    t[2] = (__uint128_t)r[0] * s[2] + (__uint128_t)r[2] * s[0] + (__uint128_t)r[1] * s[1];
    t[3] = (__uint128_t)r[0] * s[3] + (__uint128_t)r[3] * s[0] + (__uint128_t)r[1] * s[2] + (__uint128_t)r[2] * s[1];
    t[4] = (__uint128_t)r[0] * s[4] + (__uint128_t)r[4] * s[0] + (__uint128_t)r[3] * s[1] + (__uint128_t)r[1] * s[3] + (__uint128_t)r[2] * s[2];
    r[1] *= 19; r[2] *= 19; r[3] *= 19; r[4] *= 19;
    t[0] += (__uint128_t)r[4] * s[1] + (__uint128_t)r[1] * s[4] + (__uint128_t)r[2] * s[3] + (__uint128_t)r[3] * s[2];
    t[1] += (__uint128_t)r[4] * s[2] + (__uint128_t)r[2] * s[4] + (__uint128_t)r[3] * s[3];
    t[2] += (__uint128_t)r[4] * s[3] + (__uint128_t)r[3] * s[4];
    t[3] += (__uint128_t)r[4] * s[4];
    out[0] = (uint64_t)t[0] & M51; c = (uint64_t)(t[0] >> 51);
    t[1] += c; out[1] = (uint64_t)t[1] & M51; c = (uint64_t)(t[1] >> 51);
    t[2] += c; out[2] = (uint64_t)t[2] & M51; c = (uint64_t)(t[2] >> 51);
    t[3] += c; out[3] = (uint64_t)t[3] & M51; c = (uint64_t)(t[3] >> 51);
    t[4] += c; out[4] = (uint64_t)t[4] & M51; c = (uint64_t)(t[4] >> 51);
    out[0] += c * 19; c = out[0] >> 51; out[0] &= M51;
    out[1] += c;
}

static void ref_square(fe out, const fe in) {
    __uint128_t t[5];
    uint64_t r0 = in[0], r1 = in[1], r2 = in[2], r3 = in[3], r4 = in[4], c;
    uint64_t d0 = r0 * 2, d1 = r1 * 2, d2 = r2 * 2 * 19, d419 = r4 * 19, d4 = d419 * 2;
    t[0] = (__uint128_t)r0 * r0 + (__uint128_t)d4 * r1 + (__uint128_t)d2 * r3;
    t[1] = (__uint128_t)d0 * r1 + (__uint128_t)d4 * r2 + (__uint128_t)r3 * (r3 * 19);
    t[2] = (__uint128_t)d0 * r2 + (__uint128_t)r1 * r1 + (__uint128_t)d4 * r3;
    t[3] = (__uint128_t)d0 * r3 + (__uint128_t)d1 * r2 + (__uint128_t)r4 * d419;
    t[4] = (__uint128_t)d0 * r4 + (__uint128_t)d1 * r3 + (__uint128_t)r2 * r2;
    out[0] = (uint64_t)t[0] & M51; c = (uint64_t)(t[0] >> 51);
    t[1] += c; out[1] = (uint64_t)t[1] & M51; c = (uint64_t)(t[1] >> 51);
    t[2] += c; out[2] = (uint64_t)t[2] & M51; c = (uint64_t)(t[2] >> 51);
    t[3] += c; out[3] = (uint64_t)t[3] & M51; c = (uint64_t)(t[3] >> 51);
    t[4] += c; out[4] = (uint64_t)t[4] & M51; c = (uint64_t)(t[4] >> 51);
    out[0] += c * 19; c = out[0] >> 51; out[0] &= M51;
    out[1] += c;
}

static void ref_sqr_times(fe out, const fe in, uint64_t count) {
    fe cur;
    memcpy(cur, in, 40);
    do {
        ref_square(cur, cur);
    } while (--count);
    memcpy(out, cur, 40);
}

static void ref_scalar_product(fe out, const fe in, uint64_t scalar) {
    __uint128_t a;
    uint64_t c;
    a = (__uint128_t)in[0] * scalar; out[0] = (uint64_t)a & M51; c = (uint64_t)(a >> 51);
    a = (__uint128_t)in[1] * scalar + c; out[1] = (uint64_t)a & M51; c = (uint64_t)(a >> 51);
    a = (__uint128_t)in[2] * scalar + c; out[2] = (uint64_t)a & M51; c = (uint64_t)(a >> 51);
    a = (__uint128_t)in[3] * scalar + c; out[3] = (uint64_t)a & M51; c = (uint64_t)(a >> 51);
    a = (__uint128_t)in[4] * scalar + c; out[4] = (uint64_t)a & M51; c = (uint64_t)(a >> 51);
    out[0] += c * 19;
}

static void ref_swap_conditional(fe x, fe qpx, uint64_t iswap) {
    uint64_t swap = (uint64_t)(-(int64_t)iswap);
    for (int i = 0; i < 5; i++) {
        uint64_t m = swap & (x[i] ^ qpx[i]);
        x[i] ^= m;
        qpx[i] ^= m;
    }
}

static void ref_recip(fe out, const fe z) {
    fe a, t0, b, c;
    ref_square(a, z);
    ref_sqr_times(t0, a, 2);
    ref_mul(b, t0, z);
    ref_mul(a, b, a);
    ref_square(t0, a);
    ref_mul(b, t0, b);
    ref_sqr_times(t0, b, 5);
    ref_mul(b, t0, b);
    ref_sqr_times(t0, b, 10);
    ref_mul(c, t0, b);
    ref_sqr_times(t0, c, 20);
    ref_mul(t0, t0, c);
    ref_sqr_times(t0, t0, 10);
    ref_mul(b, t0, b);
    ref_sqr_times(t0, b, 50);
    ref_mul(c, t0, b);
    ref_sqr_times(t0, c, 100);
    ref_mul(t0, t0, c);
    ref_sqr_times(t0, t0, 50);
    ref_mul(b, t0, b);
    ref_sqr_times(b, b, 5);
    ref_mul(out, b, a);
}

// The Montgomery ladder from curve25519-donna: 252 main-loop iterations
// (bits 253..2) with a constant-time conditional swap at bit ^ lastbit,
// then 3 doubling-only steps for the clamped-zero low bits.
static void ref_x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
    fe nqpqx = {1}, nqpqz = {0}, nqz = {1}, nqx, q, qx, qpqx, qqx, zzz, zmone;
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    ref_frombytes(q, point);
    memcpy(nqx, q, 40);
    int32_t lastbit = 1;
    for (int32_t i = 253; i >= 2; i--) {
        ref_add(qx, nqx, nqz);
        ref_sub(nqz, nqx, nqz);
        ref_add(qpqx, nqpqx, nqpqz);
        ref_sub(nqpqz, nqpqx, nqpqz);
        ref_mul(nqpqx, qpqx, nqz);
        ref_mul(nqpqz, qx, nqpqz);
        ref_add(qqx, nqpqx, nqpqz);
        ref_sub(nqpqz, nqpqx, nqpqz);
        ref_square(nqpqz, nqpqz);
        ref_square(nqpqx, qqx);
        ref_mul(nqpqz, nqpqz, q);
        ref_square(qx, qx);
        ref_square(nqz, nqz);
        ref_mul(nqx, qx, nqz);
        ref_sub(nqz, qx, nqz);
        ref_scalar_product(zzz, nqz, 121665);
        ref_add(zzz, zzz, qx);
        ref_mul(nqz, nqz, zzz);
        int bit = (e[i / 8] >> (i & 7)) & 1;
        ref_swap_conditional(nqx, nqpqx, (uint64_t)(bit ^ lastbit));
        ref_swap_conditional(nqz, nqpqz, (uint64_t)(bit ^ lastbit));
        lastbit = bit;
    }
    for (int i = 0; i < 3; i++) {
        ref_add(qx, nqx, nqz);
        ref_sub(nqz, nqx, nqz);
        ref_square(qx, qx);
        ref_square(nqz, nqz);
        ref_mul(nqx, qx, nqz);
        ref_sub(nqz, qx, nqz);
        ref_scalar_product(zzz, nqz, 121665);
        ref_add(zzz, zzz, qx);
        ref_mul(nqz, nqz, zzz);
    }
    ref_recip(zmone, nqz);
    ref_mul(nqz, nqx, zmone);
    ref_tobytes(out, nqz);
}

// ── helpers ─────────────────────────────────────────────────────────────

// Deterministic LCG (Numerical Recipes) — same vectors on every run.
static uint32_t rng_state = 0x9e3779b9u;
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

// 52 random bits (a limb in the ladder's add range [0, 2^52)).
static uint64_t rng_limb52(void) {
    return ((uint64_t)rng_next() << 20) | (rng_next() & 0xFFFFFu);
}

// 51 random bits.
static uint64_t rng_limb51(void) {
    return ((uint64_t)rng_next() << 19) | (rng_next() & 0x7FFFFu);
}

static void rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)rng_next();
}

static void parse_hex(uint8_t *out, const char *hex) {
    while (*hex) {
        int hi = 0, lo = 0;
        char c = *hex++;
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        c = *hex++;
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        *out++ = (uint8_t)((hi << 4) | lo);
    }
}

static int fe_eq(const fe a, const fe b) {
    return memcmp(a, b, 40) == 0;
}

// ── tests ───────────────────────────────────────────────────────────────

// RFC 7748 §5.2 known-answer vectors through the asm
// (acceptance: RFC 7748 vectors pass).
static void test_x25519_rfc7748_vectors(void) {
    TEST_SUITE("x25519 RFC 7748 §5.2 vectors");
    uint8_t scalar[32], point[32], out[32], want[32];
    int failures = 0;
    parse_hex(scalar, V1_SCALAR);
    parse_hex(point, V1_POINT);
    parse_hex(want, V1_OUT);
    x25519(out, scalar, point);
    if (memcmp(out, want, 32) != 0) _FAIL("vector 1 mismatch");
    failures += memcmp(out, want, 32) != 0;
    parse_hex(scalar, V2_SCALAR);
    parse_hex(point, V2_POINT);
    parse_hex(want, V2_OUT);
    x25519(out, scalar, point);
    if (memcmp(out, want, 32) != 0) _FAIL("vector 2 mismatch");
    failures += memcmp(out, want, 32) != 0;
    ASSERT_EQ("both §5.2 vectors pass", 0, failures);
}

// The same vectors through the C reference — proves the reference is
// trustworthy before it is used to cross-check the asm.
static void test_x25519_rfc7748_reference(void) {
    TEST_SUITE("reference passes RFC 7748 §5.2");
    uint8_t scalar[32], point[32], out[32], want[32];
    int failures = 0;
    parse_hex(scalar, V1_SCALAR);
    parse_hex(point, V1_POINT);
    parse_hex(want, V1_OUT);
    ref_x25519(out, scalar, point);
    if (memcmp(out, want, 32) != 0) _FAIL("reference vector 1 mismatch");
    failures += memcmp(out, want, 32) != 0;
    parse_hex(scalar, V2_SCALAR);
    parse_hex(point, V2_POINT);
    parse_hex(want, V2_OUT);
    ref_x25519(out, scalar, point);
    if (memcmp(out, want, 32) != 0) _FAIL("reference vector 2 mismatch");
    failures += memcmp(out, want, 32) != 0;
    ASSERT_EQ("reference matches both §5.2 vectors", 0, failures);
}

// RFC 7748 §6.1 iterative chain through the asm: k = u = 09 00...00,
// and each iteration sets k to the result and u to the old value of k.
// The 1,000,000-iteration value is skipped (would exceed the harness
// timeout); 1 and 1000 pin the chain.
static void test_x25519_rfc7748_iterative(void) {
    TEST_SUITE("x25519 RFC 7748 §6.1 iterative");
    uint8_t k[32], u[32], out[32], want[32];
    memset(k, 0, 32); k[0] = 9;
    memcpy(u, k, 32);
    parse_hex(want, IT_ONE);
    x25519(out, k, u);
    memcpy(u, k, 32);
    memcpy(k, out, 32);
    ASSERT_EQ("after 1 iteration", 0, memcmp(k, want, 32));
    parse_hex(want, IT_1000);
    for (int it = 2; it <= 1000; it++) {
        x25519(out, k, u);
        memcpy(u, k, 32);
        memcpy(k, out, 32);
    }
    ASSERT_EQ("after 1000 iterations", 0, memcmp(k, want, 32));
}

// RFC 7748 §6.1 Diffie-Hellman vector: X25519(a, 9), X25519(b, 9) and
// the shared secret X25519(a, X25519(b, 9)).
static void test_x25519_rfc7748_dh(void) {
    TEST_SUITE("x25519 RFC 7748 §6.1 Diffie-Hellman");
    uint8_t base[32], a[32], b[32], out[32], want[32];
    memset(base, 0, 32); base[0] = 9;
    parse_hex(a, DH_A);
    parse_hex(b, DH_B);
    int failures = 0;

    parse_hex(want, DH_A_PUB);
    x25519(out, a, base);
    if (memcmp(out, want, 32) != 0) _FAIL("Alice's public key mismatch");
    failures += memcmp(out, want, 32) != 0;

    parse_hex(want, DH_B_PUB);
    x25519(out, b, base);
    if (memcmp(out, want, 32) != 0) _FAIL("Bob's public key mismatch");
    failures += memcmp(out, want, 32) != 0;

    parse_hex(want, DH_K);
    parse_hex(base, DH_B_PUB);
    x25519(out, a, base);
    if (memcmp(out, want, 32) != 0) _FAIL("shared secret mismatch");
    failures += memcmp(out, want, 32) != 0;

    ASSERT_EQ("DH vector matches", 0, failures);
}

// frombytes/tobytes: limb-exact asm vs reference over random 32-byte
// inputs (including values >= p and with the top bit set — RFC 7748
// requires masking the top bit), plus known round-trips.
static void test_x25519_frombytes_tobytes(void) {
    TEST_SUITE("x25519_fe_frombytes/tobytes vs reference");
    uint8_t s[32], got[32], want[32];
    fe ga, wa;
    int failures = 0;

    for (int v = 0; v < 200; v++) {
        rng_bytes(s, 32);
        ref_frombytes(wa, s);
        x25519_fe_frombytes(ga, s);
        if (!fe_eq(ga, wa)) {
            if (failures < 3) _FAIL("frombytes vector %d limb mismatch", v);
            failures++;
        }
        ref_tobytes(want, wa);
        x25519_fe_tobytes(got, ga);
        if (memcmp(got, want, 32) != 0) {
            if (failures < 3) _FAIL("tobytes vector %d byte mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("200 random 32-byte values match reference", 0, failures);

    // canonical round-trips: contract(expand(x)) == x for x < p
    uint8_t one[32], zero[32];
    memset(one, 0, 32); one[0] = 1;
    memset(zero, 0, 32);
    fe fo;
    x25519_fe_frombytes(fo, one);
    x25519_fe_tobytes(got, fo);
    ASSERT_EQ("expand/contract(1) == 1", 0, memcmp(got, one, 32));
    x25519_fe_frombytes(fo, zero);
    x25519_fe_tobytes(got, fo);
    ASSERT_EQ("expand/contract(0) == 0", 0, memcmp(got, zero, 32));
    parse_hex(s, V1_POINT);
    x25519_fe_frombytes(fo, s);
    x25519_fe_tobytes(got, fo);
    ASSERT_EQ("§5.2 u-coordinate round-trips", 0, memcmp(got, s, 32));
}

// add/sub: limb-exact asm vs reference, with aliasing and edge inputs.
static void test_x25519_add_sub(void) {
    TEST_SUITE("x25519_fe_add/sub vs reference");
    fe a, b, got, want;
    int failures = 0;

    for (int v = 0; v < 500; v++) {
        for (int i = 0; i < 5; i++) {
            a[i] = rng_limb52();
            b[i] = rng_limb52();
        }
        ref_add(want, a, b);
        x25519_fe_add(got, a, b);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("add vector %d limb mismatch", v);
            failures++;
        }
        ref_sub(want, a, b);
        x25519_fe_sub(got, a, b);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("sub vector %d limb mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("500 random add/sub vectors match reference", 0, failures);

    // out aliasing a and b (the ladder relies on it); a0 keeps the
    // original a so the "out==b" case compares against the true sum.
    fe a0;
    memcpy(a0, a, 40);
    ref_add(want, a0, b);
    x25519_fe_add(a, a, b);
    ASSERT_EQ("add out==a", 0, memcmp(a, want, 40));
    memcpy(a, a0, 40);
    x25519_fe_add(b, a, b);
    ASSERT_EQ("add out==b", 0, memcmp(b, want, 40));
    ref_sub(want, a0, b);
    x25519_fe_sub(a, a, b);
    ASSERT_EQ("sub out==a", 0, memcmp(a, want, 40));
    memcpy(a, a0, 40);
    x25519_fe_sub(b, a, b);
    ASSERT_EQ("sub out==b", 0, memcmp(b, want, 40));

    // edge inputs: all zeros, all max limbs, max add-range limbs
    for (int i = 0; i < 5; i++) { a[i] = 0; b[i] = 0; }
    x25519_fe_add(got, a, b);
    ASSERT_EQ("add(0,0) == 0", 0, memcmp(got, a, 40));
    for (int i = 0; i < 5; i++) { a[i] = M51; b[i] = M51; }
    ref_add(want, a, b);
    x25519_fe_add(got, a, b);
    ASSERT_EQ("add(max,max) == reference", 0, memcmp(got, want, 40));
    for (int i = 0; i < 5; i++) { a[i] = (1ULL << 52) - 1; b[i] = (1ULL << 52) - 1; }
    ref_sub(want, a, b);
    x25519_fe_sub(got, a, b);
    ASSERT_EQ("sub(2^52-1,2^52-1) == reference", 0, memcmp(got, want, 40));
}

// mul/square: limb-exact asm vs reference over random inputs in the
// ladder's realistic ranges, plus stress inputs at the sub-output bound.
static void test_x25519_mul_sqr(void) {
    TEST_SUITE("x25519_fe_mul/sqr vs reference");
    fe a, b, got, want;
    int failures = 0;

    for (int v = 0; v < 500; v++) {
        for (int i = 0; i < 5; i++) {
            a[i] = rng_limb52();
            b[i] = rng_limb52();
        }
        ref_mul(want, a, b);
        x25519_fe_mul(got, a, b);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("mul vector %d limb mismatch", v);
            failures++;
        }
        ref_square(want, a);
        x25519_fe_sqr(got, a);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("sqr vector %d limb mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("500 random mul/sqr vectors match reference", 0, failures);

    // stress: limbs at the sub-output bound (~2^54) the ladder feeds
    // into mul — the 128-bit accumulators must not overflow.
    failures = 0;
    for (int v = 0; v < 100; v++) {
        for (int i = 0; i < 5; i++) {
            a[i] = ((uint64_t)rng_next() << 22) | (rng_next() & 0x3FFFFFu);
            b[i] = ((uint64_t)rng_next() << 22) | (rng_next() & 0x3FFFFFu);
        }
        ref_mul(want, a, b);
        x25519_fe_mul(got, a, b);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("mul stress vector %d limb mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("100 stress vectors (limbs < 2^54) match reference", 0, failures);

    // aliasing + edge operands; a0 keeps the original a for the
    // out==b case
    fe a0;
    memcpy(a0, a, 40);
    ref_mul(want, a0, b);
    x25519_fe_mul(a, a, b);
    ASSERT_EQ("mul out==a", 0, memcmp(a, want, 40));
    memcpy(a, a0, 40);
    x25519_fe_mul(b, a, b);
    ASSERT_EQ("mul out==b", 0, memcmp(b, want, 40));
    ref_square(want, a0);
    x25519_fe_sqr(a, a);
    ASSERT_EQ("sqr out==in", 0, memcmp(a, want, 40));
    memcpy(a, a0, 40);
    for (int i = 0; i < 5; i++) { a[i] = 0; }
    x25519_fe_mul(got, a, b);
    ASSERT_EQ("mul(0,b) == 0", 0, memcmp(got, a, 40));
    a[0] = 1; a[1] = 0; a[2] = 0; a[3] = 0; a[4] = 0;
    x25519_fe_mul(got, a, a);
    ASSERT_EQ("mul(1,1) == 1", 0, memcmp(got, a, 40));
}

// square_times: limb-exact vs reference for the counts the inversion
// chain uses.
static void test_x25519_sqr_times(void) {
    TEST_SUITE("x25519_fe_sqr_times vs reference");
    static const uint64_t counts[] = {1, 2, 3, 5, 10, 50, 100, 250};
    fe a, got, want;
    int failures = 0;
    for (int v = 0; v < 50; v++) {
        for (int i = 0; i < 5; i++) a[i] = rng_limb52();
        for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
            ref_sqr_times(want, a, counts[c]);
            x25519_fe_sqr_times(got, a, counts[c]);
            if (!fe_eq(got, want)) {
                if (failures < 3) _FAIL("vector %d count %llu mismatch", v,
                                        (unsigned long long)counts[c]);
                printf("  DEBUG v=%d count=%llu input=%016llx %016llx %016llx %016llx %016llx\n",
                       v, (unsigned long long)counts[c],
                       (unsigned long long)a[0], (unsigned long long)a[1],
                       (unsigned long long)a[2], (unsigned long long)a[3],
                       (unsigned long long)a[4]);
                failures++;
            }
        }
    }
    ASSERT_EQ("50 x 8 count combinations match reference", 0, failures);
}

// scalar_product: limb-exact vs reference for the ladder's a24 and
// assorted scalars.
static void test_x25519_scalar_product(void) {
    TEST_SUITE("x25519_fe_scalar_product vs reference");
    static const uint64_t scalars[] = {0, 1, 19, 121665, 0xFFFFFFFFULL,
                                       0xFFFFFFFFFFFFFFFFULL};
    fe a, got, want;
    int failures = 0;
    for (int v = 0; v < 100; v++) {
        for (int i = 0; i < 5; i++) a[i] = rng_limb52();
        for (size_t s = 0; s < sizeof(scalars) / sizeof(scalars[0]); s++) {
            ref_scalar_product(want, a, scalars[s]);
            x25519_fe_scalar_product(got, a, scalars[s]);
            if (!fe_eq(got, want)) {
                if (failures < 3) _FAIL("vector %d scalar %llu mismatch", v,
                                        (unsigned long long)scalars[s]);
                failures++;
            }
        }
        // a random scalar too
        uint64_t rs = ((uint64_t)rng_next() << 32) | rng_next();
        ref_scalar_product(want, a, rs);
        x25519_fe_scalar_product(got, a, rs);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("vector %d random scalar mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("100 x 7 scalar combinations match reference", 0, failures);
}

// recip: limb-exact vs reference, and the identity a * a^(p-2) == 1.
static void test_x25519_recip(void) {
    TEST_SUITE("x25519_fe_recip vs reference");
    uint8_t s[32], one[32], enc[32];
    fe a, got, want, prod;
    int failures = 0;
    memset(one, 0, 32); one[0] = 1;

    for (int v = 0; v < 100; v++) {
        rng_bytes(s, 32);
        s[0] |= 1;                      // keep it non-zero
        ref_frombytes(a, s);
        ref_recip(want, a);
        x25519_fe_recip(got, a);
        if (!fe_eq(got, want)) {
            if (failures < 3) _FAIL("recip vector %d limb mismatch", v);
            failures++;
        }
        // a * a^-1 == 1 (encoded)
        ref_mul(prod, a, got);
        ref_tobytes(enc, prod);
        if (memcmp(enc, one, 32) != 0) {
            if (failures < 3) _FAIL("recip vector %d inverse identity", v);
            failures++;
        }
    }
    ASSERT_EQ("100 recip vectors match reference and invert", 0, failures);
}

// swap_conditional: constant-time conditional swap behaviour.
static void test_x25519_swap_conditional(void) {
    TEST_SUITE("x25519_swap_conditional");
    fe x, qpx, x0, q0;
    for (int i = 0; i < 5; i++) { x0[i] = rng_limb52(); q0[i] = rng_limb52(); }

    memcpy(x, x0, 40);
    memcpy(qpx, q0, 40);
    x25519_swap_conditional(x, qpx, 0);
    ASSERT_EQ("swap 0 leaves both unchanged", 0,
              memcmp(x, x0, 40) | memcmp(qpx, q0, 40));

    memcpy(x, x0, 40);
    memcpy(qpx, q0, 40);
    x25519_swap_conditional(x, qpx, 1);
    ASSERT_EQ("swap 1 exchanges", 0,
              memcmp(x, q0, 40) | memcmp(qpx, x0, 40));

    memcpy(x, x0, 40);
    memcpy(qpx, q0, 40);
    x25519_swap_conditional(x, qpx, 1);
    x25519_swap_conditional(x, qpx, 1);
    ASSERT_EQ("swap twice restores", 0,
              memcmp(x, x0, 40) | memcmp(qpx, q0, 40));

    // matches the reference for a random 0/1 pattern
    fe rx, rq, wx, wq;
    memcpy(rx, x0, 40);
    memcpy(rq, q0, 40);
    memcpy(wx, x0, 40);
    memcpy(wq, q0, 40);
    for (int v = 0; v < 20; v++) {
        uint64_t sw = rng_next() & 1;
        x25519_swap_conditional(rx, rq, sw);
        ref_swap_conditional(wx, wq, sw);
    }
    ASSERT_EQ("matches reference over 20 random swaps", 0,
              memcmp(rx, wx, 40) | memcmp(rq, wq, 40));
}

// Full X25519: asm vs reference over random (scalar, point) pairs,
// including unclamped scalars (clamping must match the RFC exactly).
static void test_x25519_reference_matches(void) {
    TEST_SUITE("x25519 asm vs reference (random pairs)");
    uint8_t scalar[32], point[32], got[32], want[32];
    int failures = 0;
    for (int v = 0; v < 25; v++) {
        rng_bytes(scalar, 32);
        rng_bytes(point, 32);
        point[31] &= 0x7f;              // as RFC 7748: mask the top bit
        ref_x25519(want, scalar, point);
        x25519(got, scalar, point);
        if (memcmp(got, want, 32) != 0) {
            if (failures < 3) _FAIL("pair %d mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("25 random scalar/point pairs match reference", 0, failures);
}

// Edge cases: small-order input, clamped-zero scalar, non-canonical
// u-coordinates, and clamping invariance.
static void test_x25519_edges(void) {
    TEST_SUITE("x25519 edge cases");
    uint8_t zero[32], out[32], want[32], base[32], a[32], maxu[32];
    int failures = 0;

    memset(zero, 0, 32);
    memset(base, 0, 32); base[0] = 9;
    parse_hex(a, DH_A);

    // X25519(k, 0) == 0 for any k (small-order point → all-zero output)
    for (int v = 0; v < 5; v++) {
        uint8_t k[32];
        rng_bytes(k, 32);
        x25519(out, k, zero);
        if (memcmp(out, zero, 32) != 0) _FAIL("X25519(k, 0) != 0 (case %d)", v);
        failures += memcmp(out, zero, 32) != 0;
    }

    // X25519(0, 9): the clamped scalar is 2^254; known answer computed
    // independently.
    parse_hex(want, ZERO_SCALAR_BASEPOINT);
    x25519(out, zero, base);
    if (memcmp(out, want, 32) != 0) _FAIL("X25519(0, 9) mismatch");
    failures += memcmp(out, want, 32) != 0;

    // non-canonical u = 2^255-1 must be accepted (RFC 7748 §5) and
    // match both the reference and the independent big-int computation.
    memset(maxu, 0xff, 32); maxu[31] = 0x7f;
    ref_x25519(want, a, maxu);
    x25519(out, a, maxu);
    failures += memcmp(out, want, 32) != 0;
    parse_hex(want, NONCANON_A);
    if (memcmp(out, want, 32) != 0) _FAIL("non-canonical u mismatch");
    failures += memcmp(out, want, 32) != 0;

    // clamping invariance: x25519(scalar) == x25519(clamped(scalar))
    for (int v = 0; v < 3; v++) {
        uint8_t k[32], c[32];
        rng_bytes(k, 32);
        memcpy(c, k, 32);
        c[0] &= 248;
        c[31] &= 127;
        c[31] |= 64;
        uint8_t k_out[32], c_out[32];
        x25519(k_out, k, base);
        x25519(c_out, c, base);
        if (memcmp(k_out, c_out, 32) != 0) _FAIL("clamp invariance case %d", v);
        failures += memcmp(k_out, c_out, 32) != 0;
    }

    ASSERT_EQ("all edge cases pass", 0, failures);
}

int main(void) {
    test_x25519_rfc7748_vectors();
    test_x25519_rfc7748_reference();
    test_x25519_rfc7748_iterative();
    test_x25519_rfc7748_dh();
    test_x25519_frombytes_tobytes();
    test_x25519_add_sub();
    test_x25519_mul_sqr();
    test_x25519_sqr_times();
    test_x25519_scalar_product();
    test_x25519_recip();
    test_x25519_swap_conditional();
    test_x25519_reference_matches();
    test_x25519_edges();
    test_summary();
    return 0;
}
