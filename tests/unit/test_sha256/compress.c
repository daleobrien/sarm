// Unit tests for src/crypto/sha256/compress.S
//
// Tests for SHA-256 compression function block processing.

#include "test_harness.h"

extern void sha256(uint32_t state[8], const void *data,
                   uint64_t nblocks) __asm__("sha256");
extern const uint32_t sha256_h256[8] __asm__("sha256_h256");

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

// ── tests ────────────────────────────────────────────────────────────

// The compression function takes an explicit block count: a 2-block
// padded message processed in a single call must equal the reference,
// and must equal the same blocks fed one call at a time (state carried
// in place between calls).
static void test_sha256_block_count(void) {
    TEST_SUITE("sha256 nblocks & state-in-place");
    static uint8_t msg[300];
    for (int i = 0; i < 300; i++)
        msg[i] = (uint8_t)(i * 7 + 3);

    static uint8_t padded[PAD_BUF_SIZE];
    uint8_t ref_d[32], got[32];
    uint32_t h[8];

    // 65 bytes → exactly 2 blocks; 129 bytes → exactly 3 blocks.
    static const size_t lens[] = { 57, 64, 65, 120, 128, 129, 200 };
    for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        size_t len = lens[li];
        size_t nb = pad_tail(msg, len, (uint64_t)len * 8, padded);
        if (nb < 2)
            continue;

        ref_digest(msg, len, ref_d);

        // one call, all blocks
        memcpy(h, sha256_h256, sizeof(h));
        sha256(h, padded, nb);
        digest_bytes(h, got);
        if (!digest_eq(ref_d, got)) {
            _FAIL("len %zu, nblocks %zu in one call", len, nb);
            continue;
        }
        _PASS("multi-block single call matches reference");

        // same blocks, one call per block (streaming, state in place)
        memcpy(h, sha256_h256, sizeof(h));
        for (size_t b = 0; b < nb; b++)
            sha256(h, padded + 64 * b, 1);
        digest_bytes(h, got);
        if (!digest_eq(ref_d, got)) {
            _FAIL("len %zu, block-by-block calls (nblocks %zu)", len, nb);
            continue;
        }
        _PASS("block-by-block calls match reference");

        // nblocks = 0 must be a no-op (early return, no state store)
        memcpy(h, sha256_h256, sizeof(h));
        uint32_t save[8];
        memcpy(save, h, sizeof(h));
        sha256(h, padded, 0);
        if (memcmp(save, h, sizeof(h)) != 0)
            _FAIL("len %zu — nblocks=0 changed the state", len);
        else
            _PASS("nblocks=0 leaves state untouched");
    }
}

int main(void) {
    test_sha256_block_count();
    test_summary();
    return 0;
}
