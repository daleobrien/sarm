// Integration tests for HKDF module
//
// Tests that span multiple functions:
//   1. RFC 5869 known-answer vectors (both extract and expand)
//   2. Buffer alignment across all functions
//   3. In-place (aliased) output buffers

#include "test_harness.h"

extern void hkdf_extract(const uint8_t *salt, uint64_t saltlen,
                         const uint8_t *ikm, uint64_t ikmlen,
                         uint8_t *prk) __asm__("hkdf_extract");
extern void hkdf_expand(const uint8_t *prk, uint64_t prklen,
                        const uint8_t *info, uint64_t infolen,
                        uint8_t *okm, uint64_t okmlen) __asm__("hkdf_expand");
extern void hkdf_expand_label(const uint8_t *secret,
                              const uint8_t *label, uint64_t label_len,
                              const uint8_t *context, uint64_t context_len,
                              uint8_t *out, uint64_t outlen)
    __asm__("hkdf_expand_label");

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

static void ref_hkdf_expand_label(const uint8_t *secret,
                                  const uint8_t *label, size_t label_len,
                                  const uint8_t *ctx, size_t ctx_len,
                                  uint8_t *out, size_t out_len) {
    static uint8_t hkdf_label[520];
    hkdf_label[0] = (uint8_t)(out_len >> 8);
    hkdf_label[1] = (uint8_t)out_len;
    hkdf_label[2] = (uint8_t)(6 + label_len);
    memcpy(hkdf_label + 3, "tls13 ", 6);
    if (label_len)
        memcpy(hkdf_label + 9, label, label_len);
    hkdf_label[9 + label_len] = (uint8_t)ctx_len;
    if (ctx_len)
        memcpy(hkdf_label + 10 + label_len, ctx, ctx_len);
    ref_hkdf_expand(secret, HKDF_HASH_LEN, hkdf_label,
                    10 + label_len + ctx_len, out, out_len);
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
static const uint8_t TC1_INFO[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
};
static const uint8_t TC1_PRK[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
};
static const uint8_t TC1_OKM[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
};

static const uint8_t TC2_PRK[32] = {
    0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
    0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
};
static const uint8_t TC2_OKM[82] = {
    0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
    0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
    0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
    0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
    0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
    0x1d, 0x87,
};

static const uint8_t TC3_PRK[32] = {
    0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
    0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04,
};
static const uint8_t TC3_OKM[42] = {
    0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
    0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
    0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
};

// ── helpers ──────────────────────────────────────────────────────────

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// ── tests ────────────────────────────────────────────────────────────

static void test_hkdf_rfc5869(void) {
    TEST_SUITE("RFC 5869 known-answer vectors (extract and expand)");
    uint8_t prk[32], okm[128];

    // case 1: 13-byte salt, 22-byte IKM, 10-byte info, L = 42
    hkdf_extract(TC1_SALT, sizeof(TC1_SALT), TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("case 1 extract -> PRK", buf_eq(TC1_PRK, prk, 32));
    hkdf_expand(prk, 32, TC1_INFO, sizeof(TC1_INFO), okm, 42);
    ASSERT_TRUE("case 1 expand -> OKM", buf_eq(TC1_OKM, okm, 42));

    // case 2: 80-byte salt/IKM/info, L = 82 — long-key HMAC paths
    uint8_t ikm2[80], salt2[80], info2[80];
    for (int i = 0; i < 80; i++) {
        ikm2[i] = (uint8_t)i;
        salt2[i] = (uint8_t)(0x60 + i);
        info2[i] = (uint8_t)(0xb0 + i);
    }
    hkdf_extract(salt2, sizeof(salt2), ikm2, sizeof(ikm2), prk);
    ASSERT_TRUE("case 2 extract -> PRK", buf_eq(TC2_PRK, prk, 32));
    hkdf_expand(prk, 32, info2, sizeof(info2), okm, 82);
    ASSERT_TRUE("case 2 expand -> OKM", buf_eq(TC2_OKM, okm, 82));

    // case 3: zero-length salt AND info, L = 42 — RFC's absent-salt path
    hkdf_extract(NULL, 0, TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("case 3 extract (salt = 32 zeros) -> PRK",
                buf_eq(TC3_PRK, prk, 32));
    hkdf_expand(prk, 32, NULL, 0, okm, 42);
    ASSERT_TRUE("case 3 expand (empty info) -> OKM",
                buf_eq(TC3_OKM, okm, 42));

    // The C reference must reproduce the same vectors
    ref_hkdf_extract(TC1_SALT, sizeof(TC1_SALT), TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("reference agrees on case 1 PRK", buf_eq(TC1_PRK, prk, 32));
    ref_hkdf_expand(prk, 32, TC1_INFO, sizeof(TC1_INFO), okm, 42);
    ASSERT_TRUE("reference agrees on case 1 OKM", buf_eq(TC1_OKM, okm, 42));
}

// The asm reads inputs with byte loads (alignment-agnostic) but sweep
// every start offset inside a 16-byte block for salt, ikm, info,
// label, context, and the output buffers.
static void test_hkdf_alignment(void) {
    TEST_SUITE("hkdf buffer alignment (offsets 0-15)");
    static uint8_t sb[48 + 16], ib[64 + 16];
    static uint8_t lb[32 + 16], cb[40 + 16], ob[128 + 16];
    static uint8_t prk[32], want[64];
    static uint8_t info[600], label[32], ctx[40];
    int ok = 1;

    for (int i = 0; i < 600; i++)
        info[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 32; i++) {
        label[i] = (uint8_t)('a' + i % 26);
        prk[i] = (uint8_t)(i * 3 + 5);
    }
    for (int i = 0; i < 40; i++)
        ctx[i] = (uint8_t)(i * 11 + 2);

    // extract: salt/ikm/prk offsets
    ref_hkdf_extract(label, 32, info, 64, want);
    for (int so = 0; so <= 15 && ok; so++) {
        for (int io = 0; io <= 15 && ok; io++) {
            for (int oo = 0; oo <= 15 && ok; oo++) {
                memcpy(sb + so, label, 32);
                memcpy(ib + io, info, 64);
                hkdf_extract(sb + so, 32, ib + io, 64, ob + oo);
                if (!buf_eq(want, ob + oo, 32)) {
                    ok = 0;
                    _FAIL("extract salt_off %d ikm_off %d out_off %d",
                          so, io, oo);
                }
            }
        }
    }
    ASSERT_EQ("extract: all 4096 offset combos match reference", 1, ok);

    // expand: prk/info/okm offsets
    ref_hkdf_expand(prk, 32, info, 64, want, 64);
    ok = 1;
    for (int po = 0; po <= 15 && ok; po++) {
        for (int io = 0; io <= 15 && ok; io++) {
            for (int oo = 0; oo <= 15 && ok; oo++) {
                memcpy(sb + po, prk, 32);
                memcpy(ib + io, info, 64);
                hkdf_expand(sb + po, 32, ib + io, 64, ob + oo, 64);
                if (!buf_eq(want, ob + oo, 64)) {
                    ok = 0;
                    _FAIL("expand prk_off %d info_off %d out_off %d",
                          po, io, oo);
                }
            }
        }
    }
    ASSERT_EQ("expand: all 4096 offset combos match reference", 1, ok);

    // expand-label: label/context/out offsets (secret stays aligned)
    ref_hkdf_expand_label(prk, label, 20, ctx, 40, want, 48);
    ok = 1;
    for (int lo = 0; lo <= 15 && ok; lo++) {
        for (int co = 0; co <= 15 && ok; co++) {
            for (int oo = 0; oo <= 15 && ok; oo++) {
                memcpy(lb + lo, label, 20);
                memcpy(cb + co, ctx, 40);
                hkdf_expand_label(prk, lb + lo, 20, cb + co, 40,
                                  ob + oo, 48);
                if (!buf_eq(want, ob + oo, 48)) {
                    ok = 0;
                    _FAIL("label_off %d ctx_off %d out_off %d", lo, co, oo);
                }
            }
        }
    }
    ASSERT_EQ("expand-label: all 4096 offset combos match reference", 1, ok);
}

// The outputs are only written after every input is fully consumed, so
// an output buffer aliasing an input must be safe. Guard that property.
static void test_hkdf_inplace(void) {
    TEST_SUITE("hkdf in-place (aliased) outputs");
    static uint8_t buf[128];
    uint8_t want[64];

    for (int i = 0; i < 128; i++)
        buf[i] = (uint8_t)(i * 3 + 1);

    // expand: okm overwrites the info buffer (info is snapshotted
    // before the first block, so multi-block outputs are safe too)
    ref_hkdf_expand(buf, 32, buf + 40, 60, want, 60);
    hkdf_expand(buf, 32, buf + 40, 60, buf + 40, 60);
    ASSERT_TRUE("expand okm == info buffer", buf_eq(want, buf + 40, 60));

    // expand: single-block okm overwrites the prk buffer — safe, since
    // hmac_sha256 reads its key fully before writing the digest and a
    // 32-octet output needs only one block
    ref_hkdf_expand(buf, 32, buf + 40, 60, want, 32);
    hkdf_expand(buf, 32, buf + 40, 60, buf, 32);
    ASSERT_TRUE("expand okm == prk buffer (single block)",
                buf_eq(want, buf, 32));

    // expand-label: out overwrites the context buffer
    ref_hkdf_expand_label(buf, buf + 40, 10, buf + 60, 40, want, 48);
    hkdf_expand_label(buf, buf + 40, 10, buf + 60, 40, buf + 60, 48);
    ASSERT_TRUE("expand-label out == context buffer", buf_eq(want, buf + 60, 48));

    // extract: prk overwrites the ikm buffer
    ref_hkdf_extract(buf, 32, buf + 40, 60, want);
    hkdf_extract(buf, 32, buf + 40, 60, buf + 40);
    ASSERT_TRUE("extract prk == ikm buffer", buf_eq(want, buf + 40, 32));
}

int main(void) {
    test_hkdf_rfc5869();
    test_hkdf_alignment();
    test_hkdf_inplace();
    test_summary();
    return 0;
}
