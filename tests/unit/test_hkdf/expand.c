// Unit tests for src/crypto/hkdf/expand.S
//
// Tests the hkdf_expand function with:
//   1. Comprehensive sweep over OKM lengths crossing T-block boundaries
//   2. Info lengths from empty to large
//   3. The 255-block counter maximum (RFC 5869 L = 255*32)

#include "test_harness.h"

extern void hkdf_expand(const uint8_t *prk, uint64_t prklen,
                        const uint8_t *info, uint64_t infolen,
                        uint8_t *okm, uint64_t okmlen) __asm__("hkdf_expand");

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

static void ref_hkdf_expand(const uint8_t *prk, size_t prklen,
                            const uint8_t *info, size_t infolen,
                            uint8_t *okm, size_t okmlen) {
    static uint8_t block[HKDF_HASH_LEN + 600 + 1]; // prev + info + counter
    uint8_t t[HKDF_HASH_LEN];
    size_t off = 0, prevlen = 0;

    for (uint8_t i = 1; off < okmlen; i++) {
        if (prevlen)
            memcpy(block, t, HKDF_HASH_LEN);
        if (infolen)
            memcpy(block + prevlen, info, infolen);
        block[prevlen + infolen] = i;
        ref_hmac_sha256(prk, prklen, block, prevlen + infolen + 1, t);
        size_t copy = okmlen - off;
        if (copy > HKDF_HASH_LEN)
            copy = HKDF_HASH_LEN;
        memcpy(okm + off, t, copy);
        off += copy;
        prevlen = HKDF_HASH_LEN;
    }
}

// ── helpers ──────────────────────────────────────────────────────────

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// ── tests ────────────────────────────────────────────────────────────

// PLAN.MD §5.2: OKM lengths across the T-block boundary (32/33, 64/65,
// 96/97), the RFC 5869 L = 255*32 counter maximum, and info lengths
// from empty to large, all vs the C reference.
static void test_hkdf_expand_sweep(void) {
    TEST_SUITE("hkdf expand sweep vs reference");
    static uint8_t prk[40], info[600];
    uint8_t want[8160], got[8160];

    for (int i = 0; i < 40; i++)
        prk[i] = (uint8_t)(i * 11 + 7);
    for (int i = 0; i < 600; i++)
        info[i] = (uint8_t)(i * 17 + 3);

    static const size_t okm_lens[] = {
        1, 2, 31, 32, 33, 63, 64, 65, 96, 97, 255, 256, 300, 8160,
    };
    static const size_t info_lens[] = {
        0, 1, 10, 31, 32, 33, 63, 64, 65, 100, 255, 500, 600,
    };
    for (size_t oi = 0; oi < sizeof(okm_lens) / sizeof(okm_lens[0]); oi++) {
        for (size_t ii = 0; ii < sizeof(info_lens) / sizeof(info_lens[0]); ii++) {
            size_t ol = okm_lens[oi], il = info_lens[ii];
            ref_hkdf_expand(prk, sizeof(prk), info, il, want, ol);
            hkdf_expand(prk, sizeof(prk), info, il, got, ol);
            if (!buf_eq(want, got, ol)) {
                _FAIL("okmlen %zu infolen %zu — OKM mismatch", ol, il);
                return;
            }
        }
    }
    _PASS("okm {1..8160} x info {0..600} matches reference");

    // full okmlen sweep 0..97 with a fixed info — every boundary hit
    for (size_t ol = 0; ol <= 97; ol++) {
        ref_hkdf_expand(prk, sizeof(prk), info, 13, want, ol);
        hkdf_expand(prk, sizeof(prk), info, 13, got, ol);
        if (!buf_eq(want, got, ol)) {
            _FAIL("okmlen %zu — OKM mismatch", ol);
            return;
        }
    }
    _PASS("okmlen 0-97 matches reference");

    // 32/33 boundary explicitly (1 vs 2 T blocks)
    ref_hkdf_expand(prk, sizeof(prk), info, 13, want, 32);
    hkdf_expand(prk, sizeof(prk), info, 13, got, 32);
    ASSERT_TRUE("okmlen 32 (one T block)", buf_eq(want, got, 32));
    ref_hkdf_expand(prk, sizeof(prk), info, 13, want, 33);
    hkdf_expand(prk, sizeof(prk), info, 13, got, 33);
    ASSERT_TRUE("okmlen 33 (two T blocks)", buf_eq(want, got, 33));

    // empty info and empty PRK edge cases
    hkdf_expand(prk, sizeof(prk), NULL, 0, got, 64);
    ref_hkdf_expand(prk, sizeof(prk), NULL, 0, want, 64);
    ASSERT_TRUE("empty info, 64-byte OKM", buf_eq(want, got, 64));
    hkdf_expand(NULL, 0, info, 13, got, 32);
    ref_hkdf_expand(NULL, 0, info, 13, want, 32);
    ASSERT_TRUE("zero-length PRK", buf_eq(want, got, 32));
}

int main(void) {
    test_hkdf_expand_sweep();
    test_summary();
    return 0;
}
