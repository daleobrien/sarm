// Unit tests for src/crypto/sha256/final.S
//
// Tests for SHA-256 finalization, padding, and known-answer verification.

#include "test_harness.h"

extern void sha256(uint32_t state[8], const void *data,
                   uint64_t nblocks) __asm__("sha256");
extern const uint32_t sha256_h256[8] __asm__("sha256_h256");
extern void sha256_init(void *ctx) __asm__("sha256_init");
extern void sha256_update(void *ctx, const void *data,
                          uint64_t len) __asm__("sha256_update");
extern void sha256_final(void *ctx, void *digest) __asm__("sha256_final");

// The context layout contract, mirrored from src/defs.S (SHA256_CTX_*).
#define SHA256_CTX_STATE   0
#define SHA256_CTX_BITLEN  32
#define SHA256_CTX_BUF     40
#define SHA256_CTX_BUFLEN  104
#define SHA256_CTX_SIZE    112

// ── independent C reference (FIPS 180-4) ─────────────────────────────

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

// Serialize the state as the 32 big-endian digest bytes.
static void digest_bytes(const uint32_t h[8], uint8_t out[32]) {
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(h[i]);
    }
}

// Pad the tail of a message: msg[0..msg_len) followed by 0x80, zeros,
// and the total message length (in bits) as a big-endian 64-bit word.
// Writes into out and returns the number of 64-byte blocks produced.
#define PAD_BUF_SIZE (1 << 20)

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

// Full asm digest of a whole message: pad in C, then call the
// compression function once with all blocks.
static void asm_digest(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    static uint8_t padded[PAD_BUF_SIZE];
    size_t nblocks = pad_tail(msg, len, (uint64_t)len * 8, padded);
    uint32_t h[8];
    memcpy(h, sha256_h256, sizeof(h));
    sha256(h, padded, nblocks);
    digest_bytes(h, digest);
}

// Same, but through the plain-C reference.
static void ref_digest(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    static uint8_t padded[PAD_BUF_SIZE];
    size_t nblocks = pad_tail(msg, len, (uint64_t)len * 8, padded);
    uint32_t h[8];
    memcpy(h, sha256_h256, sizeof(h));
    for (size_t b = 0; b < nblocks; b++)
        ref_compress(h, padded + 64 * b);
    digest_bytes(h, digest);
}

static int digest_eq(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32) == 0;
}

// ── known-answer vectors (FIPS 180-4 / NIST) ─────────────────────────

static const uint8_t KAT_EMPTY[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static const uint8_t KAT_ABC[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static const uint8_t KAT_FOX[32] = {
    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94,
    0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
    0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
    0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92,
};

// 56 bytes — one full message block plus a padding block.
static const uint8_t KAT_56[32] = {
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
    0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
    0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
};

// 1,000,000 x 'a' — 15,625 blocks.
static const uint8_t KAT_MILLION_A[32] = {
    0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
    0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
    0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
    0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0,
};

// ── streaming API helpers ────────────────────────────────────────────

// Stream msg[0..len) through the asm streaming API, feeding it in
// chunks that cycle through the given pattern. A zero-length message
// still runs final (→ the empty-string digest).
static void stream_digest(const uint8_t *msg, size_t len,
                          const size_t *chunks, int nchunks,
                          uint8_t digest[32]) {
    static uint8_t ctx[SHA256_CTX_SIZE];
    sha256_init(ctx);
    size_t off = 0;
    for (int i = 0; off < len; i++) {
        size_t n = chunks[i % nchunks];
        if (n > len - off)
            n = len - off;
        sha256_update(ctx, msg + off, n);
        off += n;
    }
    sha256_final(ctx, digest);
}

// ── tests ────────────────────────────────────────────────────────────

static void test_sha256_known_vectors(void) {
    TEST_SUITE("sha256 known-answer vectors");
    uint8_t d[32];

    asm_digest((const uint8_t *)"", 0, d);
    ASSERT_TRUE("empty string", digest_eq(KAT_EMPTY, d));

    asm_digest((const uint8_t *)"abc", 3, d);
    ASSERT_TRUE("\"abc\"", digest_eq(KAT_ABC, d));

    asm_digest((const uint8_t *)"The quick brown fox jumps over the lazy dog",
               43, d);
    ASSERT_TRUE("quick brown fox", digest_eq(KAT_FOX, d));

    static const char msg56[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    asm_digest((const uint8_t *)msg56, sizeof(msg56) - 1, d);
    ASSERT_TRUE("56-byte NIST vector (2 blocks)", digest_eq(KAT_56, d));

    // The C reference must agree with the same vectors — otherwise the
    // cross-checks below would be comparing two equally-broken hashes.
    ref_digest((const uint8_t *)"abc", 3, d);
    ASSERT_TRUE("reference agrees on \"abc\"", digest_eq(KAT_ABC, d));

    static uint8_t million_a[1000000];
    for (int i = 0; i < 1000000; i++)
        million_a[i] = 'a';
    asm_digest(million_a, sizeof(million_a), d);
    ASSERT_TRUE("1,000,000 x 'a' (15,625 blocks)", digest_eq(KAT_MILLION_A, d));
}

// Sweep every length 0..300 with several byte patterns, comparing the
// asm digest against the C reference. Hits every padding/block boundary
// (55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, ...).
static void test_sha256_length_sweep(void) {
    TEST_SUITE("sha256 length sweep vs reference (0-300)");
    static uint8_t buf[400];
    uint8_t asm_d[32], ref_d[32];

    for (int i = 0; i < 400; i++)
        buf[i] = (uint8_t)i;                          // incrementing
    for (size_t len = 0; len <= 300; len++) {
        asm_digest(buf, len, asm_d);
        ref_digest(buf, len, ref_d);
        if (!digest_eq(asm_d, ref_d)) {
            _FAIL("incrementing, len %zu — digest mismatch", len);
            return;
        }
    }
    _PASS("incrementing bytes, len 0-300");

    memset(buf, 0xFF, sizeof(buf));                   // all 0xFF
    for (size_t len = 0; len <= 300; len++) {
        asm_digest(buf, len, asm_d);
        ref_digest(buf, len, ref_d);
        if (!digest_eq(asm_d, ref_d)) {
            _FAIL("all-0xFF, len %zu — digest mismatch", len);
            return;
        }
    }
    _PASS("all-0xFF bytes, len 0-300");

    for (int i = 0; i < 400; i++)
        buf[i] = (uint8_t)("0123456789abcdef"[i % 16]);  // repeating ASCII
    for (size_t len = 0; len <= 300; len++) {
        asm_digest(buf, len, asm_d);
        ref_digest(buf, len, ref_d);
        if (!digest_eq(asm_d, ref_d)) {
            _FAIL("repeating ASCII, len %zu — digest mismatch", len);
            return;
        }
    }
    _PASS("repeating ASCII, len 0-300");
}

// A context must be reusable: final, then init again, then hash the
// same message again — identical digests.
static void test_sha256_streaming_reuse(void) {
    TEST_SUITE("context reuse after final");
    static uint8_t ctx[SHA256_CTX_SIZE];
    static uint8_t msg[200];
    for (int i = 0; i < 200; i++)
        msg[i] = (uint8_t)(i * 3 + 2);
    uint8_t d1[32], d2[32], want[32];
    ref_digest(msg, sizeof(msg), want);

    sha256_init(ctx);
    sha256_update(ctx, msg, sizeof(msg));
    sha256_final(ctx, d1);
    ASSERT_TRUE("first use matches reference", digest_eq(want, d1));

    sha256_init(ctx);
    sha256_update(ctx, msg, sizeof(msg));
    sha256_final(ctx, d2);
    ASSERT_TRUE("second use after re-init matches reference",
                digest_eq(want, d2));
}

// The NIST 1,000,000 x 'a' vector, streamed in odd-sized chunks —
// exercises the multi-block update loop over 15,625 blocks.
static void test_sha256_streaming_million(void) {
    TEST_SUITE("streaming 1,000,000 x 'a'");
    static uint8_t million_a[1000000];
    for (int i = 0; i < 1000000; i++)
        million_a[i] = 'a';
    uint8_t got[32];
    static const size_t pats[][2] = {
        { 333, 333 },        // 333-byte chunks (1M = 333*3003 + 1)
        { 4096, 7 },         // big chunks with a small tail pattern
        { 64, 1 },           // exact blocks plus singles
    };
    for (size_t pi = 0; pi < sizeof(pats) / sizeof(pats[0]); pi++) {
        stream_digest(million_a, sizeof(million_a), pats[pi], 2, got);
        char label[48];
        snprintf(label, sizeof(label), "chunk pattern %zu", pi);
        ASSERT_TRUE(label, digest_eq(KAT_MILLION_A, got));
    }
}

int main(void) {
    test_sha256_known_vectors();
    test_sha256_length_sweep();
    test_sha256_streaming_reuse();
    test_sha256_streaming_million();
    test_summary();
    return 0;
}
