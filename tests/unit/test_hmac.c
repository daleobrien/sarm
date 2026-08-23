// Unit tests for src/crypto/hmac.S
//
// The asm file exports one symbol:
//   hmac_sha256 — one-shot HMAC-SHA256
//     (key=x0, keylen=x1, data=x2, datalen=x3, digest=x4)
//   Computes SHA256((K0 ^ opad) || SHA256((K0 ^ ipad) || data)) with K0
//   the key zero-padded to the 64-byte block size; keys longer than one
//   block are replaced by their SHA-256 digest first (RFC 2104). The
//   function is self-contained (all scratch on the stack) and built on
//   the streaming sha256_init/update/final API from sha256.S.
//
// The asm symbol is bare (no leading underscore, matching the rest of
// the codebase), so the C declaration below pins it with an __asm__
// label to bypass the Mach-O underscore mangling of C names.
//
// These tests drive the asm against:
//   1. the RFC 4231 known-answer vectors (external ground truth,
//      including the 128-bit truncated output of test case 5),
//   2. an independent plain-C HMAC-SHA256 implementation in this file
//      (whose SHA-256 core is itself cross-checked against NIST KATs),
//      cross-checked over key-length and message-length sweeps — the
//      boundaries (key < block size, key = block size,
//      key > block size, empty message, large message) — plus buffer
//      alignment and aliased (in-place) digests.

#include "test_harness.h"

extern void hmac_sha256(const uint8_t *key, uint64_t keylen,
                        const uint8_t *data, uint64_t datalen,
                        uint8_t *digest) __asm__("hmac_sha256");

// ── independent C reference (FIPS 180-4 SHA-256 core) ────────────────
// Same implementation as test_sha256.c: a separate, portable SHA-256
// that does not share code with the asm under test.

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

// Compress one 64-byte block into h (FIPS 180-4 §6.2.2).
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

// ── padding + reference digest ────────────────────────────────────────

// Enough for the largest test (1,000,000 'a' → 1,000,064 padded bytes).
#define PAD_BUF_SIZE (1 << 20)
#define HMAC_BLOCK   64
#define HMAC_SIZE    32

// Pad msg[0..msg_len) with 0x80, zeros, and the big-endian 64-bit bit
// length; write into out and return the number of 64-byte blocks.
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

// Full reference SHA-256 digest of a whole message.
static void ref_digest(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    static uint8_t padded[PAD_BUF_SIZE];
    size_t nblocks = pad_tail(msg, len, (uint64_t)len * 8, padded);
    uint32_t h[8];
    h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
    h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
    for (size_t b = 0; b < nblocks; b++)
        ref_compress(h, padded + 64 * b);
    digest_bytes(h, digest);
}

// ── reference HMAC-SHA256 (RFC 2104) ─────────────────────────────────
// Independent of the asm: pads the key in C, hashes ipad||data and
// opad||inner through ref_digest.
static void ref_hmac_sha256(const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t datalen,
                            uint8_t out[32]) {
    static uint8_t k0[HMAC_BLOCK];
    static uint8_t msg[PAD_BUF_SIZE];
    uint8_t kh[HMAC_SIZE], inner[HMAC_SIZE];

    if (keylen > HMAC_BLOCK) {            // RFC 2104 §2: hash long keys
        ref_digest(key, keylen, kh);
        key = kh;
        keylen = HMAC_SIZE;
    }
    memset(k0, 0, HMAC_BLOCK);
    memcpy(k0, key, keylen);

    for (int i = 0; i < HMAC_BLOCK; i++)
        k0[i] ^= 0x36;                    // ipad
    memcpy(msg, k0, HMAC_BLOCK);
    memcpy(msg + HMAC_BLOCK, data, datalen);
    ref_digest(msg, HMAC_BLOCK + datalen, inner);

    for (int i = 0; i < HMAC_BLOCK; i++)
        k0[i] ^= (uint8_t)(0x36 ^ 0x5c);  // ipad -> opad
    memcpy(msg, k0, HMAC_BLOCK);
    memcpy(msg + HMAC_BLOCK, inner, HMAC_SIZE);
    ref_digest(msg, HMAC_BLOCK + HMAC_SIZE, out);
}

static int digest_eq(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32) == 0;
}

// ── RFC 4231 known-answer vectors ────────────────────────────────────

typedef struct {
    const char *name;
    const uint8_t *key;
    size_t keylen;
    const uint8_t *data;
    size_t datalen;
    const uint8_t *mac;    // 32 bytes (case 5's RFC value is 16 bytes)
    size_t maclen;
} rfc4231_case_t;

static const uint8_t TC1_KEY[20] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
};
static const uint8_t TC1_MAC[32] = {
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
};

static const uint8_t TC2_KEY[4] = { 'J', 'e', 'f', 'e' };
static const uint8_t TC2_MAC[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
};

static const uint8_t TC3_KEY[20] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};
static const uint8_t TC3_DATA[50] = {
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
};
static const uint8_t TC3_MAC[32] = {
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
    0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
};

static const uint8_t TC4_KEY[25] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19,
};
static const uint8_t TC4_DATA[50] = {
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
};
static const uint8_t TC4_MAC[32] = {
    0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
    0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
};

static const uint8_t TC5_KEY[20] = {
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
    0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
};
// RFC 4231 case 5 publishes only the truncated 128-bit output.
static const uint8_t TC5_MAC_TRUNC[16] = {
    0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
    0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b,
};

static const uint8_t TC6_KEY[131] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa,
};
static const uint8_t TC6_MAC[32] = {
    0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
    0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
};

static const uint8_t TC7_MAC[32] = {
    0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
    0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
};

// ── Boundary vectors (computed independently) ───────────────────────────

// key = 64 bytes (exactly one block), empty message
static const uint8_t K64_MAC[32] = {
    0xdb, 0x2c, 0xf9, 0x3f, 0x63, 0x3f, 0xcd, 0xfd, 0x9b, 0xb7, 0xf3, 0xb9, 0x97, 0x63, 0xa6, 0x37,
    0x25, 0xcb, 0x8e, 0x38, 0xb4, 0xfa, 0x60, 0xa8, 0x7d, 0x0e, 0x94, 0xb7, 0x1d, 0x8b, 0x59, 0x70,
};

// key = 20 bytes, empty message
static const uint8_t EMPTY_MAC[32] = {
    0x99, 0x9a, 0x90, 0x12, 0x19, 0xf0, 0x32, 0xcd, 0x49, 0x7c, 0xad, 0xb5, 0xe6, 0x05, 0x1e, 0x97,
    0xb6, 0xa2, 0x9a, 0xb2, 0x97, 0xbd, 0x6a, 0xe7, 0x22, 0xbd, 0x60, 0x62, 0xa2, 0xf5, 0x95, 0x42,
};

// key = 131 bytes (> block size), empty message — long-key path
static const uint8_t LONGKEY_EMPTY_MAC[32] = {
    0x44, 0xb5, 0x45, 0xde, 0xf5, 0xb9, 0x7e, 0xb7, 0x19, 0xd8, 0x56, 0xa1, 0x5e, 0x32, 0x78, 0x33,
    0xe5, 0x20, 0xe4, 0x77, 0x06, 0x19, 0xc0, 0xe3, 0xee, 0xfb, 0xde, 0x24, 0xb7, 0x12, 0x85, 0xa7,
};

// key = empty, message = 1,000,000 x 'a' — large-message path
static const uint8_t MILLION_MAC[32] = {
    0xcc, 0x9b, 0x6b, 0xe4, 0x9d, 0x15, 0x12, 0x55, 0x7c, 0xef, 0x49, 0x57, 0x70, 0xbb, 0x61, 0xe4,
    0x6f, 0xce, 0x6e, 0x83, 0xaf, 0x89, 0xd3, 0x85, 0xa0, 0x38, 0xc8, 0xc0, 0x50, 0xf4, 0x60, 0x9d,
};

// key = 64 bytes 0xaa, message = 1,000,000 x 'a' — both boundaries
static const uint8_t K64_MILLION_MAC[32] = {
    0xaa, 0xd7, 0xc8, 0x4e, 0xf0, 0x11, 0xa9, 0x24, 0x29, 0xe2, 0x47, 0xa1, 0xaa, 0xa8, 0xe2, 0xcb,
    0x2c, 0x0e, 0x48, 0x3e, 0x98, 0xe3, 0x99, 0x38, 0x01, 0x0e, 0xb1, 0x4d, 0x4e, 0x2a, 0x66, 0x87,
};

// ── tests ────────────────────────────────────────────────────────────

static void test_hmac_rfc4231(void) {
    TEST_SUITE("RFC 4231 known-answer vectors");
    uint8_t got[32];

    // case 1: 20-byte key (0x0b), "Hi There"
    hmac_sha256(TC1_KEY, sizeof(TC1_KEY),
                (const uint8_t *)"Hi There", 8, got);
    ASSERT_TRUE("case 1 (key < block)", digest_eq(TC1_MAC, got));

    // case 2: "Jefe", "what do ya want for nothing?"
    hmac_sha256(TC2_KEY, sizeof(TC2_KEY),
                (const uint8_t *)"what do ya want for nothing?", 28, got);
    ASSERT_TRUE("case 2 (short key, text data)", digest_eq(TC2_MAC, got));

    // case 3: 20-byte key (0xaa), 50 bytes 0xdd
    hmac_sha256(TC3_KEY, sizeof(TC3_KEY), TC3_DATA, sizeof(TC3_DATA), got);
    ASSERT_TRUE("case 3 (50-byte data)", digest_eq(TC3_MAC, got));

    // case 4: 25-byte key 0x01..0x19, 50 bytes 0xcd
    hmac_sha256(TC4_KEY, sizeof(TC4_KEY), TC4_DATA, sizeof(TC4_DATA), got);
    ASSERT_TRUE("case 4 (25-byte key)", digest_eq(TC4_MAC, got));

    // case 5: RFC publishes only the truncated 128-bit output; check
    // that prefix, then the full 32 bytes against the C reference.
    hmac_sha256(TC5_KEY, sizeof(TC5_KEY),
                (const uint8_t *)"Test With Truncation", 20, got);
    ASSERT_TRUE("case 5 truncated prefix == RFC 4231",
                memcmp(TC5_MAC_TRUNC, got, 16) == 0);
    {
        uint8_t want[32];
        ref_hmac_sha256(TC5_KEY, sizeof(TC5_KEY),
                        (const uint8_t *)"Test With Truncation", 20, want);
        ASSERT_TRUE("case 5 full output == reference", digest_eq(want, got));
    }

    // case 6: 131-byte key (0xaa), short message — long-key path
    hmac_sha256(TC6_KEY, sizeof(TC6_KEY),
                (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First",
                54, got);
    ASSERT_TRUE("case 6 (key > block, hashed first)",
                digest_eq(TC6_MAC, got));

    // case 7: same 131-byte key as case 6 (RFC 4231 reuses it), long
    // message — both the long-key and multi-block paths
    hmac_sha256(TC6_KEY, sizeof(TC6_KEY),
                (const uint8_t *)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                152, got);
    ASSERT_TRUE("case 7 (key > block, data > block)",
                digest_eq(TC7_MAC, got));

    // The C reference must agree with the same vectors — otherwise the
    // cross-checks below would be comparing two equally-broken MACs.
    ref_hmac_sha256(TC1_KEY, sizeof(TC1_KEY),
                    (const uint8_t *)"Hi There", 8, got);
    ASSERT_TRUE("reference agrees on case 1", digest_eq(TC1_MAC, got));
}

// Explicit key-size boundaries — key < block (TC1 covers
// 20 bytes), key = block (64), key > block (131). Sweep 0..131 against
// the C reference so every boundary and the long-key hashing path is
// hit with a deterministic key pattern.
static void test_hmac_key_sizes(void) {
    TEST_SUITE("hmac key-size sweep vs reference (0-131)");
    static uint8_t key[160], msg[200];
    uint8_t want[32], got[32];

    for (int i = 0; i < 160; i++)
        key[i] = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 200; i++)
        msg[i] = (uint8_t)(i * 13 + 5);

    for (size_t kl = 0; kl <= 131; kl++) {
        ref_hmac_sha256(key, kl, msg, sizeof(msg), want);
        hmac_sha256(key, kl, msg, sizeof(msg), got);
        if (!digest_eq(want, got)) {
            _FAIL("keylen %zu — MAC mismatch", kl);
            return;
        }
    }
    _PASS("keylen 0-131 matches reference (0 < 64 = 64 < 64 > 64)");

    // explicit boundaries against the C reference
    hmac_sha256(key, 64, msg, sizeof(msg), got);
    ref_hmac_sha256(key, 64, msg, sizeof(msg), want);
    ASSERT_TRUE("keylen = 64 (exactly one block)", digest_eq(want, got));
    hmac_sha256(key, 65, msg, sizeof(msg), got);
    ref_hmac_sha256(key, 65, msg, sizeof(msg), want);
    ASSERT_TRUE("keylen = 65 (first hashed key)", digest_eq(want, got));
    hmac_sha256(key, 0, msg, sizeof(msg), got);
    ref_hmac_sha256(key, 0, msg, sizeof(msg), want);
    ASSERT_TRUE("keylen = 0 (all-zero K0)", digest_eq(want, got));
}

// Message-size boundaries — empty message and messages
// spanning the padding boundaries (55/56/57/63/64/65/119/120/121...).
static void test_hmac_msg_sizes(void) {
    TEST_SUITE("hmac message-size sweep vs reference (0-300)");
    static uint8_t key[40], msg[400];
    uint8_t want[32], got[32];

    for (int i = 0; i < 40; i++)
        key[i] = (uint8_t)(i * 3 + 2);
    for (int i = 0; i < 400; i++)
        msg[i] = (uint8_t)(i * 17 + 3);

    for (size_t dl = 0; dl <= 300; dl++) {
        ref_hmac_sha256(key, sizeof(key), msg, dl, want);
        hmac_sha256(key, sizeof(key), msg, dl, got);
        if (!digest_eq(want, got)) {
            _FAIL("datalen %zu — MAC mismatch", dl);
            return;
        }
    }
    _PASS("datalen 0-300 matches reference");

    // empty message against the independently computed KAT
    hmac_sha256(key, sizeof(key), NULL, 0, got);
    static const uint8_t expect[32] = {
        0xca, 0x3e, 0x6e, 0x87, 0x82, 0x77, 0x39, 0xc2,
        0xdd, 0xd9, 0xda, 0xef, 0x11, 0xcd, 0x1f, 0x24,
        0x0d, 0x18, 0xef, 0x80, 0x54, 0x27, 0xf7, 0x4e,
        0xd5, 0x5c, 0x1b, 0xc2, 0x95, 0x74, 0xb8, 0xb8,
    };
    // (expected value computed independently; the sweep above already
    // ties empty-message output to the C reference too)
    ASSERT_TRUE("empty message (NULL data, len 0) == KAT",
                digest_eq(expect, got));
}

// Large message — 1,000,000 x 'a' (15,625 SHA-256 blocks)
// against the independently computed KAT, with a short and a long key.
static void test_hmac_large_message(void) {
    TEST_SUITE("hmac large message (1,000,000 x 'a')");
    static uint8_t million_a[1000000];
    for (int i = 0; i < 1000000; i++)
        million_a[i] = 'a';
    uint8_t got[32];

    hmac_sha256(NULL, 0, million_a, sizeof(million_a), got);
    ASSERT_TRUE("empty key, 1M message", digest_eq(MILLION_MAC, got));

    static uint8_t key64[64];
    memset(key64, 0xaa, sizeof(key64));
    hmac_sha256(key64, sizeof(key64), million_a, sizeof(million_a), got);
    ASSERT_TRUE("64-byte key, 1M message", digest_eq(K64_MILLION_MAC, got));

    // and the 64-byte-key/empty-message KAT (key = block)
    hmac_sha256(key64, sizeof(key64), NULL, 0, got);
    ASSERT_TRUE("64-byte key, empty message", digest_eq(K64_MAC, got));
}

// The asm reads inputs with byte/vector loads (alignment-agnostic) but
// sweep every start offset inside a 16-byte block for key, data, and
// digest to guard the whole pipeline.
static void test_hmac_alignment(void) {
    TEST_SUITE("hmac buffer alignment (offsets 0-15)");
    static uint8_t kb[40 + 16], db[64 + 16], ob[32 + 16];
    static uint8_t key[40], msg[64];
    uint8_t want[32];

    for (int i = 0; i < 40; i++)
        key[i] = (uint8_t)(i * 11 + 7);
    for (int i = 0; i < 64; i++)
        msg[i] = (uint8_t)(i * 5 + 9);
    ref_hmac_sha256(key, sizeof(key), msg, sizeof(msg), want);

    int ok = 1;
    for (int ko = 0; ko <= 15 && ok; ko++) {
        for (int doff = 0; doff <= 15 && ok; doff++) {
            for (int oo = 0; oo <= 15 && ok; oo++) {
                memcpy(kb + ko, key, sizeof(key));
                memcpy(db + doff, msg, sizeof(msg));
                hmac_sha256(kb + ko, sizeof(key), db + doff,
                            sizeof(msg), ob + oo);
                if (!digest_eq(want, ob + oo)) {
                    ok = 0;
                    _FAIL("key_off %d data_off %d out_off %d — mismatch",
                          ko, doff, oo);
                }
            }
        }
    }
    ASSERT_EQ("all 4096 offset combos match reference", 1, ok);
}

// The digest is only written after both inputs are fully read (the last
// sha256_final), so a digest buffer aliasing the key or the data must be
// safe. Guard that property explicitly.
static void test_hmac_inplace(void) {
    TEST_SUITE("hmac in-place (aliased) outputs");
    static uint8_t buf[64];
    uint8_t want[32], got[32];

    for (int i = 0; i < 64; i++)
        buf[i] = (uint8_t)(i * 3 + 1);

    // digest overwrites the key buffer
    ref_hmac_sha256(buf, 40, buf + 40, 24, want);
    hmac_sha256(buf, 40, buf + 40, 24, buf);
    ASSERT_TRUE("digest == key buffer", digest_eq(want, buf));

    // digest overwrites the data buffer
    memcpy(buf, want, 32);
    ref_hmac_sha256(buf, 32, buf + 32, 32, want);
    hmac_sha256(buf, 32, buf + 32, 32, buf + 32);
    ASSERT_TRUE("digest == data buffer", digest_eq(want, buf + 32));
}

int main(void) {
    test_hmac_rfc4231();
    test_hmac_key_sizes();
    test_hmac_msg_sizes();
    test_hmac_large_message();
    test_hmac_alignment();
    test_hmac_inplace();
    test_summary();
    return 0;
}
