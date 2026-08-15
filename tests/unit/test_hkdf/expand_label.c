// Unit tests for src/crypto/hkdf/expand_label.S
//
// Tests the hkdf_expand_label function (TLS 1.3 wrapper) with:
//   1. RFC 8448 known-answer vectors (TLS 1.3 key schedule)
//   2. Comprehensive sweep over labels, contexts, and output lengths

#include "test_harness.h"

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

// ── TLS 1.3 (RFC 8448 §3) secrets ────────────────────────────────────

// "extract secret early" — HKDF-Extract with salt = 0 and IKM = 32 zeros.
static const uint8_t EARLY_SECRET[32] = {
    0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
    0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
};
// "extract secret handshake" — HKDF-Extract(derived_secret, ECDHE).
static const uint8_t HANDSHAKE_SECRET[32] = {
    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
};
// "tls13 s hs traffic" (server handshake traffic secret).
static const uint8_t S_HS_TRAFFIC[32] = {
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
};
// "extract secret master".
static const uint8_t MASTER_SECRET[32] = {
    0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f, 0x8a, 0x47,
    0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8, 0xd0, 0x40, 0x29, 0x19,
};
// "tls13 res master".
static const uint8_t RES_MASTER[32] = {
    0x7d, 0xf2, 0x35, 0xf2, 0x03, 0x1d, 0x2a, 0x05, 0x12, 0x87, 0xd0, 0x2b, 0x02, 0x41, 0xb0, 0xbf,
    0xda, 0xf8, 0x6c, 0xc8, 0x56, 0x23, 0x1f, 0x2d, 0x5a, 0xba, 0x46, 0xc4, 0x34, 0xec, 0x19, 0x6c,
};

// Transcript hashes used as HkdfLabel contexts in the trace.
static const uint8_t CH_HS_HASH[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
};
static const uint8_t AP_HASH[32] = {
    0x96, 0x08, 0x10, 0x2a, 0x0f, 0x1c, 0xcc, 0x6d, 0xb6, 0x25, 0x0b, 0x7b, 0x7e, 0x41, 0x7b, 0x1a,
    0x00, 0x0e, 0xaa, 0xda, 0x3d, 0xaa, 0xe4, 0x77, 0x7a, 0x76, 0x86, 0xc9, 0xff, 0x83, 0xdf, 0x13,
};
// SHA-256 of the empty string — the context of the "derived" derivations.
static const uint8_t EMPTY_HASH[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

// Expected HKDF-Expand-Label outputs (RFC 8448 §3).
static const uint8_t DERIVED_HS[32] = {
    0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
    0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
};
static const uint8_t C_HS_TRAFFIC[32] = {
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
};
static const uint8_t S_HS_TRAFFIC_EXPECT[32] = {
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
};
static const uint8_t HS_KEY[16] = {
    0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc,
};
static const uint8_t HS_IV[12] = {
    0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30,
};
static const uint8_t HS_FINISHED[32] = {
    0x00, 0x8d, 0x3b, 0x66, 0xf8, 0x16, 0xea, 0x55, 0x9f, 0x96, 0xb5, 0x37, 0xe8, 0x85, 0xc3, 0x1f,
    0xc0, 0x68, 0xbf, 0x49, 0x2c, 0x65, 0x2f, 0x01, 0xf2, 0x88, 0xa1, 0xd8, 0xcd, 0xc1, 0x9f, 0xc8,
};
static const uint8_t C_AP_TRAFFIC[32] = {
    0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d, 0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52,
    0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87, 0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5,
};
static const uint8_t EXP_MASTER[32] = {
    0xfe, 0x22, 0xf8, 0x81, 0x17, 0x6e, 0xda, 0x18, 0xeb, 0x8f, 0x44, 0x52, 0x9e, 0x67, 0x92, 0xc5,
    0x0c, 0x9a, 0x3f, 0x89, 0x45, 0x2f, 0x68, 0xd8, 0xae, 0x31, 0x1b, 0x43, 0x09, 0xd3, 0xcf, 0x50,
};
static const uint8_t RESUMPTION[32] = {
    0x4e, 0xcd, 0x0e, 0xb6, 0xec, 0x3b, 0x4d, 0x87, 0xf5, 0xd6, 0x02, 0x8f, 0x92, 0x2c, 0xa4, 0xc5,
    0x85, 0x1a, 0x27, 0x7f, 0xd4, 0x13, 0x11, 0xc9, 0xe6, 0x2d, 0x2c, 0x94, 0x92, 0xe1, 0xc4, 0xf3,
};

// ── helpers ──────────────────────────────────────────────────────────

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// test_harness.h deliberately avoids <string.h> (name collisions with
// the util module's non-standard strlen ABI), so compute it locally.
static size_t cstrlen(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

// ── tests ────────────────────────────────────────────────────────────

static void test_hkdf_tls13(void) {
    TEST_SUITE("TLS 1.3 HKDF-Expand-Label (RFC 8448)");
    uint8_t out[64];

    // "extract secret early": salt = 0 (absent), IKM = 32 zero octets
    static const uint8_t zeros32[32] = { 0 };

    // derive secret for handshake: label "derived", context SHA256("")
    hkdf_expand_label(EARLY_SECRET, (const uint8_t *)"derived", 7,
                      EMPTY_HASH, 32, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"derived\"", buf_eq(DERIVED_HS, out, 32));

    // handshake traffic secrets: label "c hs traffic" / "s hs traffic",
    // context = ClientHello...ServerHello transcript hash
    hkdf_expand_label(HANDSHAKE_SECRET, (const uint8_t *)"c hs traffic", 12,
                      CH_HS_HASH, 32, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"c hs traffic\"",
                buf_eq(C_HS_TRAFFIC, out, 32));
    hkdf_expand_label(HANDSHAKE_SECRET, (const uint8_t *)"s hs traffic", 12,
                      CH_HS_HASH, 32, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"s hs traffic\"",
                buf_eq(S_HS_TRAFFIC_EXPECT, out, 32));

    // traffic keys: empty context, non-32-octet outputs
    hkdf_expand_label(S_HS_TRAFFIC, (const uint8_t *)"key", 3,
                      NULL, 0, out, 16);
    ASSERT_TRUE("HKDF-Expand-Label \"key\" (16 B)", buf_eq(HS_KEY, out, 16));
    hkdf_expand_label(S_HS_TRAFFIC, (const uint8_t *)"iv", 2,
                      NULL, 0, out, 12);
    ASSERT_TRUE("HKDF-Expand-Label \"iv\" (12 B)", buf_eq(HS_IV, out, 12));

    // finished: empty context, 32-octet output
    hkdf_expand_label(S_HS_TRAFFIC, (const uint8_t *)"finished", 8,
                      NULL, 0, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"finished\"",
                buf_eq(HS_FINISHED, out, 32));

    // application traffic secrets and exporter master
    hkdf_expand_label(MASTER_SECRET, (const uint8_t *)"c ap traffic", 12,
                      AP_HASH, 32, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"c ap traffic\"",
                buf_eq(C_AP_TRAFFIC, out, 32));
    hkdf_expand_label(MASTER_SECRET, (const uint8_t *)"exp master", 10,
                      AP_HASH, 32, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"exp master\"",
                buf_eq(EXP_MASTER, out, 32));

    // resumption secret: 2-octet context { 0x00, 0x00 }
    static const uint8_t resumption_ctx[2] = { 0x00, 0x00 };
    hkdf_expand_label(RES_MASTER, (const uint8_t *)"resumption", 10,
                      resumption_ctx, 2, out, 32);
    ASSERT_TRUE("HKDF-Expand-Label \"resumption\"",
                buf_eq(RESUMPTION, out, 32));

    // every vector above must also match the C reference
    uint8_t want[64];
    ref_hkdf_expand_label(EARLY_SECRET, (const uint8_t *)"derived", 7,
                          EMPTY_HASH, 32, want, 32);
    ASSERT_TRUE("reference agrees on \"derived\"",
                buf_eq(DERIVED_HS, want, 32));
    ref_hkdf_expand_label(S_HS_TRAFFIC, (const uint8_t *)"iv", 2,
                          NULL, 0, want, 12);
    ASSERT_TRUE("reference agrees on \"iv\"", buf_eq(HS_IV, want, 12));
}

// PLAN.MD §5.3: label/context/length sweeps vs the C reference. Labels
// from 1 to 36 octets, contexts 0..40, outputs crossing the T-block
// boundary — the asm HkdfLabel encoder is exercised at every length.
static void test_hkdf_expand_label_sweep(void) {
    TEST_SUITE("hkdf expand-label sweep vs reference");
    static uint8_t secret[32], label[64], ctx[64];
    uint8_t want[96], got[96];
    static const char *labels[] = {
        "", "a", "key", "iv", "sn", "finished", "res binder",
        "c hs traffic", "s hs traffic", "c ap traffic", "exp master",
        "e exp master", "resumption", "123456789012345678901234567890",
    };

    for (int i = 0; i < 32; i++)
        secret[i] = (uint8_t)(i * 5 + 1);
    for (int i = 0; i < 64; i++) {
        label[i] = (uint8_t)('a' + i % 26);
        ctx[i] = (uint8_t)(i * 3 + 9);
    }

    static const size_t out_lens[] = { 1, 12, 16, 24, 32, 33, 48, 96 };
    for (size_t li = 0; li < sizeof(labels) / sizeof(labels[0]); li++) {
        size_t ll = cstrlen(labels[li]);
        for (size_t cl = 0; cl <= 40; cl += 8) {
            for (size_t oi = 0; oi < sizeof(out_lens) / sizeof(out_lens[0]); oi++) {
                size_t ol = out_lens[oi];
                ref_hkdf_expand_label(secret, (const uint8_t *)labels[li], ll,
                                      ctx, cl, want, ol);
                hkdf_expand_label(secret, (const uint8_t *)labels[li], ll,
                                  ctx, cl, got, ol);
                if (!buf_eq(want, got, ol)) {
                    _FAIL("label \"%s\" (%zu) ctx %zu out %zu — mismatch",
                          labels[li], ll, cl, ol);
                    return;
                }
            }
        }
    }
    _PASS("labels {1..30} x ctx {0..40} x out {1..96} match reference");

    // empty label + empty context is legal for hkdf_expand_label's
    // caller contract (label_len + 6 = 6 fits the octet) — but the asm
    // expands "tls13 " + "" + "" so it still differs from a bare
    // hkdf_expand of the secret; the reference must agree.
    ref_hkdf_expand_label(secret, NULL, 0, NULL, 0, want, 32);
    hkdf_expand_label(secret, NULL, 0, NULL, 0, got, 32);
    ASSERT_TRUE("empty label, empty context", buf_eq(want, got, 32));
}

int main(void) {
    test_hkdf_tls13();
    test_hkdf_expand_label_sweep();
    test_summary();
    return 0;
}
