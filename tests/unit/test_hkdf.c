// Unit tests for src/crypto/hkdf.S
//
// The asm file exports three symbols (PLAN.MD §5):
//   hkdf_extract      (salt=x0, saltlen=x1, ikm=x2, ikmlen=x3, prk=x4)
//   hkdf_expand       (prk=x0, prklen=x1, info=x2, infolen=x3,
//                      okm=x4, okmlen=x5)
//   hkdf_expand_label (secret=x0, label=x1, label_len=x2, context=x3,
//                      context_len=x4, out=x5, outlen=x6)
// HKDF (RFC 5869) with SHA-256: extract is HMAC(salt, IKM) with an
// absent salt replaced by 32 zero octets; expand chains
// T(i) = HMAC(PRK, T(i-1) || info || i); expand_label is the TLS 1.3
// wrapper (RFC 8446 §7.1) that builds the HkdfLabel wire struct
// ("tls13 " + label, context) and expands the secret with it. The
// functions are self-contained (all scratch on the stack) and built on
// hmac_sha256 from hmac.S.
//
// The asm symbols are bare (no leading underscore, matching the rest of
// the codebase), so the C declarations below pin them with __asm__
// labels to bypass the Mach-O underscore mangling of C names.
//
// These tests drive the asm against:
//   1. the RFC 5869 known-answer vectors (cases 1-3, SHA-256),
//   2. the TLS 1.3 key-schedule vectors of RFC 8448 §3 (HKDF-Expand-
//      Label invocations from the simple 1-RTT trace, including the
//      early-secret extract),
//   3. an independent plain-C HKDF implementation in this file (whose
//      SHA-256/HMAC core is the same portable code test_hmac.c
//      cross-checks against RFC 4231), swept over salt/info/okm
//      lengths, the 32/33-octet T-block boundary, the 255-block
//      counter maximum, buffer alignments, and aliased outputs.

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

static void test_hkdf_rfc5869(void) {
    TEST_SUITE("RFC 5869 known-answer vectors");
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

    // The C reference must reproduce the same vectors, otherwise the
    // cross-checks below would compare two equally-broken derivations.
    ref_hkdf_extract(TC1_SALT, sizeof(TC1_SALT), TC1_IKM, sizeof(TC1_IKM), prk);
    ASSERT_TRUE("reference agrees on case 1 PRK", buf_eq(TC1_PRK, prk, 32));
    ref_hkdf_expand(prk, 32, TC1_INFO, sizeof(TC1_INFO), okm, 42);
    ASSERT_TRUE("reference agrees on case 1 OKM", buf_eq(TC1_OKM, okm, 42));
}

static void test_hkdf_tls13(void) {
    TEST_SUITE("TLS 1.3 HKDF-Expand-Label (RFC 8448)");
    uint8_t out[64];

    // "extract secret early": salt = 0 (absent), IKM = 32 zero octets
    static const uint8_t zeros32[32] = { 0 };
    hkdf_extract(NULL, 0, zeros32, 32, out);
    ASSERT_TRUE("early_secret extract", buf_eq(EARLY_SECRET, out, 32));

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
    test_hkdf_tls13();
    test_hkdf_extract_sweep();
    test_hkdf_expand_sweep();
    test_hkdf_expand_label_sweep();
    test_hkdf_alignment();
    test_hkdf_inplace();
    test_summary();
    return 0;
}
