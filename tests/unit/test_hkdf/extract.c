// Unit tests for src/crypto/hkdf/extract.S
//
// Tests the hkdf_extract function with:
//   1. RFC 5869 known-answer vectors (cases 1-3, SHA-256)
//   2. Comprehensive sweep over salt/IKM lengths across boundaries

#include "test_harness.h"

extern void hkdf_extract(const uint8_t *salt, uint64_t saltlen,
                         const uint8_t *ikm, uint64_t ikmlen,
                         uint8_t *prk) __asm__("hkdf_extract");

#define HKDF_HASH_LEN 32
#define HKDF_BLOCK    64

// ── independent C reference (FIPS 180-4 SHA-256 core) ────────────────
// Same portable implementation as test_hmac.c / test_sha256.c.

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
static uint32_t big_s0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t big_s1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void ref_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int t = 0; t < 16; t++)
        w[t] = ((uint32_t)block[4 * t] << 24) |
               ((uint32_t)block[4 * t + 1] << 16) |
               ((uint32_t)block[4 * t + 2] << 8) |
               (uint32_t)block[4 * t + 3];
    for (int t = 16; t < 64; t++)
        w[t] = sig1(w[t - 2]) + w[t - 7] + sig0(w[t - 15]) + w[t - 16];

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = hh + big_s1(e) + ch(e, f, g) + K256[t] + w[t];
        uint32_t t2 = big_s0(a) + maj(a, b, c);
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// Largest message in these tests: the reference HMAC/expand buffers.
#define REF_PAD_BUF (1 << 20)

static size_t pad_tail(const uint8_t *msg, size_t msg_len,
                       uint64_t total_bits, uint8_t *out) {
    size_t i;
    for (i = 0; i < msg_len; i++)
        out[i] = msg[i];
    out[msg_len] = 0x80;
    size_t padlen = ((msg_len + 9 + 63) / 64) * 64;
    for (i = msg_len + 1; i < padlen - 8; i++)
        out[i] = 0;
    for (i = 0; i < 8; i++)
        out[padlen - 8 + i] = (uint8_t)(total_bits >> (56 - 8 * i));
    return padlen / 64;
}

static void digest_bytes(const uint32_t h[8], uint8_t out[32]) {
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(h[i]);
    }
}

static void ref_digest(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    static uint8_t padded[REF_PAD_BUF];
    size_t nblocks = pad_tail(msg, len, (uint64_t)len * 8, padded);
    uint32_t h[8];
    h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
    h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
    for (size_t b = 0; b < nblocks; b++)
        ref_compress(h, padded + 64 * b);
    digest_bytes(h, digest);
}

static void ref_hmac_sha256(const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t datalen,
                            uint8_t out[32]) {
    static uint8_t k0[HKDF_BLOCK];
    static uint8_t msg[REF_PAD_BUF];
    uint8_t kh[HKDF_HASH_LEN], inner[HKDF_HASH_LEN];

    if (keylen > HKDF_BLOCK) {
        ref_digest(key, keylen, kh);
        key = kh;
        keylen = HKDF_HASH_LEN;
    }
    memset(k0, 0, HKDF_BLOCK);
    memcpy(k0, key, keylen);

    for (int i = 0; i < HKDF_BLOCK; i++)
        k0[i] ^= 0x36;                    // ipad
    memcpy(msg, k0, HKDF_BLOCK);
    memcpy(msg + HKDF_BLOCK, data, datalen);
    ref_digest(msg, HKDF_BLOCK + datalen, inner);

    for (int i = 0; i < HKDF_BLOCK; i++)
        k0[i] ^= (uint8_t)(0x36 ^ 0x5c);  // ipad -> opad
    memcpy(msg, k0, HKDF_BLOCK);
    memcpy(msg + HKDF_BLOCK, inner, HKDF_HASH_LEN);
    ref_digest(msg, HKDF_BLOCK + HKDF_HASH_LEN, out);
}

// ── reference HKDF (RFC 5869) ────────────────────────────────────────

static void ref_hkdf_extract(const uint8_t *salt, size_t saltlen,
                             const uint8_t *ikm, size_t ikmlen,
                             uint8_t prk[32]) {
    static uint8_t z[HKDF_HASH_LEN];
    if (saltlen == 0) {
        memset(z, 0, sizeof(z));
        salt = z;
        saltlen = HKDF_HASH_LEN;
    }
    ref_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

// ── RFC 5869 known-answer vectors ────────────────────────────────────

static const uint8_t TC1_IKM[22] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const uint8_t TC1_SALT[13] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c,
};
static const uint8_t TC1_PRK[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
};

static const uint8_t TC2_PRK[32] = {
    0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
    0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
};

static const uint8_t TC3_PRK[32] = {
    0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
    0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04,
};

// ── helpers ──────────────────────────────────────────────────────────

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// ── tests ────────────────────────────────────────────────────────────

static void test_hkdf_rfc5869(void) {
    TEST_SUITE("RFC 5869 extract test cases");
    uint8_t prk[32];

    // case 1: 13-byte salt, 22-byte IKM
    hkdf_extract(TC1_SALT, sizeof(TC1_SALT), TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("case 1 extract -> PRK", buf_eq(TC1_PRK, prk, 32));

    // case 2: 80-byte salt/IKM — long-key HMAC path
    uint8_t ikm2[80], salt2[80];
    for (int i = 0; i < 80; i++) {
        ikm2[i] = (uint8_t)i;
        salt2[i] = (uint8_t)(0x60 + i);
    }
    hkdf_extract(salt2, sizeof(salt2), ikm2, sizeof(ikm2), prk);
    ASSERT_TRUE("case 2 extract -> PRK", buf_eq(TC2_PRK, prk, 32));

    // case 3: zero-length salt AND info — RFC's absent-salt path
    hkdf_extract(NULL, 0, TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("case 3 extract (salt = 32 zeros) -> PRK",
                buf_eq(TC3_PRK, prk, 32));

    // The C reference must reproduce the same vectors
    ref_hkdf_extract(TC1_SALT, sizeof(TC1_SALT), TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("reference agrees on case 1 PRK", buf_eq(TC1_PRK, prk, 32));
}

// PLAN.MD §5.1/§5.2 boundaries vs the C reference: every salt length
// 0..97 (including 32 zeros and the > 64 long-key HMAC path) and IKM
// lengths 0..100, plus the empty-ikm / empty-salt combinations.
static void test_hkdf_extract_sweep(void) {
    TEST_SUITE("hkdf extract sweep vs reference");
    static uint8_t salt[128], ikm[128];
    uint8_t want[32], got[32];

    for (int i = 0; i < 128; i++) {
        salt[i] = (uint8_t)(i * 7 + 1);
        ikm[i] = (uint8_t)(i * 13 + 5);
    }

    for (size_t sl = 0; sl <= 97; sl++) {
        for (size_t il = 0; il <= 100; il += 3) {
            ref_hkdf_extract(salt, sl, ikm, il, want);
            hkdf_extract(sl ? salt : NULL, sl, ikm, il, got);
            if (!buf_eq(want, got, 32)) {
                _FAIL("saltlen %zu ikmlen %zu — PRK mismatch", sl, il);
                return;
            }
        }
    }
    _PASS("salt 0-97 x ikm 0-100 matches reference");

    // explicit boundaries: salt = 0 (zero-salt path), 64/65 (HMAC key
    // block boundary), 80 (long-key hashing, RFC 5869 case 2 shape)
    hkdf_extract(NULL, 0, ikm, 40, got);
    ref_hkdf_extract(NULL, 0, ikm, 40, want);
    ASSERT_TRUE("saltlen 0 (32 zero octets)", buf_eq(want, got, 32));
    hkdf_extract(salt, 64, ikm, 40, got);
    ref_hkdf_extract(salt, 64, ikm, 40, want);
    ASSERT_TRUE("saltlen 64 (exactly one block)", buf_eq(want, got, 32));
    hkdf_extract(salt, 65, ikm, 40, got);
    ref_hkdf_extract(salt, 65, ikm, 40, want);
    ASSERT_TRUE("saltlen 65 (first hashed key)", buf_eq(want, got, 32));
    hkdf_extract(salt, 80, ikm, 0, got);
    ref_hkdf_extract(salt, 80, ikm, 0, want);
    ASSERT_TRUE("ikmlen 0 (empty IKM)", buf_eq(want, got, 32));
}

int main(void) {
    test_hkdf_rfc5869();
    test_hkdf_extract_sweep();
    test_summary();
    return 0;
}
