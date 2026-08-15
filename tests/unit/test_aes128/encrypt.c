// Unit tests for src/crypto/aes128/encrypt.S
//
// The asm file exports:
//   aes128_encrypt — AES-128 block encryption (FIPS-197 §5.1)
//     (plaintext=x0, round_keys=x1, ciphertext=x2) — encrypts a single
//     16-byte block; the caller supplies the schedule from
//     aes128_key_expand.
//
// These tests drive the asm against:
//   1. the FIPS-197 Appendix A.1 / C.1 known-answer vector (external
//      ground truth: the published ciphertext),
//   2. the NIST SP 800-38A F.1.1 ECB-AES128 vector through the full asm
//      pipeline (asm key expansion + asm encryption),
//   3. an independent plain-C AES-128 implementation in this file,
//      cross-checked over a deterministic key/plaintext sweep,
//   4. single-bit avalanche properties (diffusion of bit flips).

#include "test_harness.h"

extern void aes128_encrypt(const uint8_t *plaintext, const uint8_t *round_keys,
                           uint8_t *ciphertext) __asm__("aes128_encrypt");

extern void aes128_key_expand(const uint8_t *key, uint8_t *round_keys)
    __asm__("aes128_key_expand");

// ── FIPS-197 S-box and Rcon ──────────────────────────────────────────

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

// ── independent C reference (FIPS 197 §5.2 / §5.1) ───────────────────

// Expand a 16-byte key into the 176-byte schedule (11 round keys).
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
        if ((i & 3) == 0) {                       // RotWord + SubWord + Rcon
            t = rotl8(t);
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) |
                ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) |
                (uint32_t)SBOX[t & 0xff];
            t ^= (uint32_t)RCON[i / 4 - 1] << 24;
        }
        w[i] = w[i - 4] ^ t;
    }
    for (int i = 0; i < 44; i++) {                // big-endian byte order
        rk[4 * i + 0] = (uint8_t)(w[i] >> 24);
        rk[4 * i + 1] = (uint8_t)(w[i] >> 16);
        rk[4 * i + 2] = (uint8_t)(w[i] >> 8);
        rk[4 * i + 3] = (uint8_t)w[i];
    }
}

// Encrypt one block. State is column-major: byte (r,c) lives at r + 4c.
static void ref_encrypt(const uint8_t pt[16], const uint8_t rk[176],
                        uint8_t ct[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++)
        s[i] = pt[i] ^ rk[i];                     // AddRoundKey(RK0)

    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++)              // SubBytes
            s[i] = SBOX[s[i]];
        for (int r = 0; r < 4; r++)               // ShiftRows: row r shifts left r
            for (int c = 0; c < 4; c++)
                t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        if (round < 10) {                         // MixColumns (last round skips it)
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
        for (int i = 0; i < 16; i++)              // AddRoundKey(RKround)
            s[i] = t[i] ^ rk[16 * round + i];
    }
    for (int i = 0; i < 16; i++)
        ct[i] = s[i];
}

// ── FIPS-197 Appendix C.1 known-answer vector ────────────────────────

static const uint8_t KAT_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t KAT_PT[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t KAT_CT[16] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

// The published C.1 round keys RK0..RK10, 16 bytes each — the exact
// byte layout aes128_encrypt expects at [round_keys + 16 * round].
static const uint8_t KAT_RK[176] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
    0xd6,0xaa,0x74,0xfd, 0xd2,0xaf,0x72,0xfa, 0xda,0xa6,0x78,0xf1, 0xd6,0xab,0x76,0xfe,
    0xb6,0x92,0xcf,0x0b, 0x64,0x3d,0xbd,0xf1, 0xbe,0x9b,0xc5,0x00, 0x68,0x30,0xb3,0xfe,
    0xb6,0xff,0x74,0x4e, 0xd2,0xc2,0xc9,0xbf, 0x6c,0x59,0x0c,0xbf, 0x04,0x69,0xbf,0x41,
    0x47,0xf7,0xf7,0xbc, 0x95,0x35,0x3e,0x03, 0xf9,0x6c,0x32,0xbc, 0xfd,0x05,0x8d,0xfd,
    0x3c,0xaa,0xa3,0xe8, 0xa9,0x9f,0x9d,0xeb, 0x50,0xf3,0xaf,0x57, 0xad,0xf6,0x22,0xaa,
    0x5e,0x39,0x0f,0x7d, 0xf7,0xa6,0x92,0x96, 0xa7,0x55,0x3d,0xc1, 0x0a,0xa3,0x1f,0x6b,
    0x14,0xf9,0x70,0x1a, 0xe3,0x5f,0xe2,0x8c, 0x44,0x0a,0xdf,0x4d, 0x4e,0xa9,0xc0,0x26,
    0x47,0x43,0x87,0x35, 0xa4,0x1c,0x65,0xb9, 0xe0,0x16,0xba,0xf4, 0xae,0xbf,0x7a,0xd2,
    0x54,0x99,0x32,0xd1, 0xf0,0x85,0x57,0x68, 0x10,0x93,0xed,0x9c, 0xbe,0x2c,0x97,0x4e,
    0x13,0x11,0x1d,0x7f, 0xe3,0x94,0x4a,0x17, 0xf3,0x07,0xa7,0x8b, 0x4d,0x2b,0x30,0xc5,
};

// ── NIST SP 800-38A Appendix F.1.1 (ECB-AES128) ──────────────────────
// A second independent NIST known-answer vector on a completely
// different key, run through the full asm pipeline (key expansion +
// encryption).

static const uint8_t SP800_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

static const uint8_t SP800_PT[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};

static const uint8_t SP800_CT[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
};

// ── helpers ──────────────────────────────────────────────────────────

static int blk_eq(const uint8_t a[16], const uint8_t b[16]) {
    return memcmp(a, b, 16) == 0;
}

static int diff_bits(const uint8_t a[16], const uint8_t b[16]) {
    int n = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t d = a[i] ^ b[i];
        while (d) {
            n += d & 1;
            d >>= 1;
        }
    }
    return n;
}

// Deterministic LCG (Numerical Recipes) — same vectors on every run.
static uint32_t rng_state = 0x9e3779b9u;
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

// ── tests ────────────────────────────────────────────────────────────

// The FIPS-197 C.1 vector through the asm: external ground truth.
static void test_aes128_kat(void) {
    TEST_SUITE("aes128 known-answer vector");
    uint8_t ct[16];

    aes128_encrypt(KAT_PT, KAT_RK, ct);
    ASSERT_TRUE("asm == FIPS-197 C.1 ciphertext", blk_eq(KAT_CT, ct));

    // The C reference must agree too — otherwise the cross-checks below
    // would compare two equally-broken implementations.
    ref_encrypt(KAT_PT, KAT_RK, ct);
    ASSERT_TRUE("reference agrees on C.1", blk_eq(KAT_CT, ct));
}

// The SP 800-38A vector through the full asm pipeline: asm key
// expansion feeding asm encryption (PLAN.MD 6.2 acceptance: NIST AES
// vectors).
static void test_aes128_sp800_38a(void) {
    TEST_SUITE("aes128 NIST SP 800-38A F.1.1 (ECB-AES128)");
    uint8_t rk[176], ct[16], want[16];

    aes128_key_expand(SP800_KEY, rk);
    aes128_encrypt(SP800_PT, rk, ct);
    ASSERT_TRUE("asm pipeline == SP 800-38A ciphertext", blk_eq(SP800_CT, ct));

    // The C reference must agree too — guards against two equally-broken
    // implementations agreeing with each other.
    key_expand(SP800_KEY, rk);
    ref_encrypt(SP800_PT, rk, want);
    ASSERT_TRUE("reference agrees on SP 800-38A", blk_eq(SP800_CT, want));
}

// 256 deterministic (key, plaintext) pairs, asm vs plain-C reference —
// both the key schedule and the block cipher, so the full asm pipeline
// (aes128_key_expand -> aes128_encrypt) is exercised end to end.
static void test_aes128_crosscheck(void) {
    TEST_SUITE("aes128 vs plain-C reference (256 vectors)");
    uint8_t key[16], pt[16], rk_c[176], rk_a[176], want[16], got[16];
    int failures = 0;
    int ks_failures = 0;

    for (int v = 0; v < 256; v++) {
        for (int i = 0; i < 16; i++)
            key[i] = (uint8_t)rng_next();
        for (int i = 0; i < 16; i++)
            pt[i] = (uint8_t)rng_next();
        key_expand(key, rk_c);
        aes128_key_expand(key, rk_a);
        if (memcmp(rk_c, rk_a, 176) != 0) {
            if (ks_failures < 3)
                _FAIL("vector %d — key schedule mismatch", v);
            ks_failures++;
        }
        ref_encrypt(pt, rk_c, want);
        aes128_encrypt(pt, rk_a, got);
        if (!blk_eq(want, got)) {
            if (failures < 3)
                _FAIL("vector %d — ciphertext mismatch", v);
            failures++;
        }
    }
    ASSERT_EQ("256 asm key schedules match reference", 0, ks_failures);
    ASSERT_EQ("256 ciphertexts match reference", 0, failures);
}

// A single-bit flip anywhere in the key or plaintext must diffuse through
// the whole block. Guards against the asm degrading into an identity or a
// plain copy (a real AES-128 always differs in far more than 16 bits).
static void test_aes128_avalanche(void) {
    TEST_SUITE("aes128 avalanche (single-bit flips)");
    uint8_t key[16], pt[16], rk[176], c0[16], c1[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(0xA5 * (i + 1));
        pt[i] = (uint8_t)(0x3C * (i + 1));
    }
    key_expand(key, rk);
    aes128_encrypt(pt, rk, c0);

    int min_diff = 128, fail = 0;
    for (int b = 0; b < 128; b++) {               // flip each plaintext bit
        pt[b >> 3] ^= (uint8_t)(1u << (b & 7));
        aes128_encrypt(pt, rk, c1);
        pt[b >> 3] ^= (uint8_t)(1u << (b & 7));
        int d = diff_bits(c0, c1);
        if (d < min_diff)
            min_diff = d;
        if (d < 16)
            fail++;
    }
    if (fail)
        _FAIL("%d plaintext bit flips produced < 16 differing bits (min %d)",
              fail, min_diff);
    else {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "single plaintext bit flips diffuse (min %d bits differ)",
                 min_diff);
        _PASS(msg);
    }

    min_diff = 128;
    fail = 0;
    for (int b = 0; b < 128; b++) {               // flip each key bit
        key[b >> 3] ^= (uint8_t)(1u << (b & 7));
        key_expand(key, rk);
        aes128_encrypt(pt, rk, c1);
        key[b >> 3] ^= (uint8_t)(1u << (b & 7));
        int d = diff_bits(c0, c1);
        if (d < min_diff)
            min_diff = d;
        if (d < 16)
            fail++;
    }
    if (fail)
        _FAIL("%d key bit flips produced < 16 differing bits (min %d)",
              fail, min_diff);
    else {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "single key bit flips diffuse (min %d bits differ)",
                 min_diff);
        _PASS(msg);
    }
}

int main(void) {
    test_aes128_kat();
    test_aes128_sp800_38a();
    test_aes128_crosscheck();
    test_aes128_avalanche();
    test_summary();
    return 0;
}
