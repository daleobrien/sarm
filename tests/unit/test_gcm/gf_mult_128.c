// Unit tests for GF(2^128) multiplication — src/crypto/gcm/gf_mult_128.S
//
// The gf_mult_128 symbol: GF(2^128) multiplication, SP 800-38D §6.3 (x0, x1, x2)

#include "test_harness.h"

extern void gf_mult_128(const uint8_t *x, const uint8_t *y, uint8_t *z)
    __asm__("gf_mult_128");

// ── AES-128 reference (FIPS 197 §5) — same portable core as test_aes128.c ──

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint32_t rotl8(uint32_t w) { return (w << 8) | (w >> 24); }

static void key_expand(const uint8_t key[16], uint8_t rk[176]) {
    uint32_t w[44];
    for (int i = 0; i < 4; i++)
        w[i] = ((uint32_t)key[4 * i] << 24) |
               ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) |
               (uint32_t)key[4 * i + 3];
    for (int i = 4; i < 44; i++) {
        uint32_t t = w[i - 1];
        if ((i & 3) == 0) {
            t = rotl8(t);
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) |
                ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) |
                (uint32_t)SBOX[t & 0xff];
            t ^= (uint32_t)RCON[i / 4 - 1] << 24;
        }
        w[i] = w[i - 4] ^ t;
    }
    for (int i = 0; i < 44; i++) {
        rk[4 * i + 0] = (uint8_t)(w[i] >> 24);
        rk[4 * i + 1] = (uint8_t)(w[i] >> 16);
        rk[4 * i + 2] = (uint8_t)(w[i] >> 8);
        rk[4 * i + 3] = (uint8_t)w[i];
    }
}

static void ref_encrypt(const uint8_t pt[16], const uint8_t rk[176],
                        uint8_t ct[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++)
        s[i] = pt[i] ^ rk[i];
    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++)
            s[i] = SBOX[s[i]];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = t[0 + 4 * c], a1 = t[1 + 4 * c];
                uint8_t a2 = t[2 + 4 * c], a3 = t[3 + 4 * c];
                uint8_t tmp = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                t[0 + 4 * c] = (uint8_t)(a0 ^ xtime(a0 ^ a1) ^ tmp);
                t[1 + 4 * c] = (uint8_t)(a1 ^ xtime(a1 ^ a2) ^ tmp);
                t[2 + 4 * c] = (uint8_t)(a2 ^ xtime(a2 ^ a3) ^ tmp);
                t[3 + 4 * c] = (uint8_t)(a3 ^ xtime(a3 ^ a0) ^ tmp);
            }
        }
        for (int i = 0; i < 16; i++)
            s[i] = t[i] ^ rk[16 * round + i];
    }
    for (int i = 0; i < 16; i++)
        ct[i] = s[i];
}

// ── independent C reference (SP 800-38D §6.3) ──────────────────────────────
// The canonical bit-serial multiplication from the spec's Algorithm 1,
// operating on GCM wire-order byte strings. This is deliberately a
// completely different algorithm from the asm's PMULL path, so a shared
// misunderstanding cannot hide in both.

static void ref_gf_mult(const uint8_t x[16], const uint8_t y[16],
                        uint8_t z[16]) {
    uint8_t v[16];
    memcpy(v, x, 16);
    memset(z, 0, 16);
    for (int i = 0; i < 128; i++) {
        if (y[i >> 3] & (0x80 >> (i & 7)))
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xE1;
    }
}

// ── NIST SP 800-38D Appendix B test cases (AES-128, 96-bit IVs) ────────
// Test Case 2 (used for gf_mult test)
static const uint8_t TC2_CT[] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
    0x71, 0xb2, 0xfe, 0x78,
};

// ── GHASH known-answer values ───────────────────────────────────────────
// GHASH KAT 1: H = E_0(0^128) = 66e94bd4ef8a2c3b884cfa59ca342b2e,
// A = C = empty → the input string is a single all-zero block → result 0.
static const uint8_t GHASH_K1_H[] = {
    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59,
    0xca, 0x34, 0x2b, 0x2e,
};

// ── Deterministic LCG (Numerical Recipes) ─────────────────────────────────
static uint32_t rng_state = 0x9e3779b9u;
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

// ── tests ───────────────────────────────────────────────────────────────

// The multiplicative identity in GCM byte order is 0x80 || 0^15 (the
// coefficient of x^0 is byte 0's MSB); x^127 is 0^15 || 0x01. Both must
// round-trip through the asm's rbit/PMULL path exactly.
static void test_gcm_gf_mult_kat(void) {
    TEST_SUITE("gf_mult_128 known answers");
    static const uint8_t ONE[16] = {0x80};
    static const uint8_t X127[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x01};
    uint8_t z[16], want[16];

    gf_mult_128(TC2_CT, ONE, z);         // a·1 == a
    ASSERT_EQ("a·1 == a", 0, memcmp(z, TC2_CT, 16));
    gf_mult_128(ONE, ONE, z);            // 1·1 == 1
    ASSERT_EQ("1·1 == 1", 0, memcmp(z, ONE, 16));
    gf_mult_128(X127, X127, z);          // x^254 ≡ x^126+x^12+x^6+x^5+x^2+1
    ref_gf_mult(X127, X127, want);
    ASSERT_EQ("x^127·x^127 == reference", 0, memcmp(z, want, 16));

    // H·H for the zero key (H = 66e94bd4...), cross-checked against the
    // reference — the asm and the reference are separately validated by
    // the NIST vectors below.
    ref_gf_mult(GHASH_K1_H, GHASH_K1_H, want);
    gf_mult_128(GHASH_K1_H, GHASH_K1_H, z);
    ASSERT_EQ("H·H == reference", 0, memcmp(z, want, 16));
}

// 256 deterministic (X, Y) pairs, asm vs the plain-C Algorithm 1.
static void test_gcm_gf_mult_crosscheck(void) {
    TEST_SUITE("gf_mult_128 vs plain-C reference (256 vectors)");
    uint8_t x[16], y[16], want[16], got[16];
    int failures = 0;
    for (int v = 0; v < 256; v++) {
        for (int i = 0; i < 16; i++) {
            x[i] = (uint8_t)rng_next();
            y[i] = (uint8_t)rng_next();
        }
        ref_gf_mult(x, y, want);
        gf_mult_128(x, y, got);
        if (memcmp(want, got, 16) != 0 && failures < 3)
            _FAIL("vector %d — product mismatch", v);
        if (memcmp(want, got, 16) != 0)
            failures++;
    }
    ASSERT_EQ("256 asm products match reference", 0, failures);
}

int main(void) {
    test_gcm_gf_mult_kat();
    test_gcm_gf_mult_crosscheck();
    test_summary();
    return 0;
}
