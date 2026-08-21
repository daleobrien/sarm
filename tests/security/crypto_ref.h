// sarm security tests — independent C reference implementations
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/crypto_ref.h — slow, obvious, test-only
//   reference implementations of the primitives src/crypto/ implements
//   in hand-written ARM64 assembly (docs/SECURITY.md, Steps 3 and 5)
//
// Description: "No crash and reference output matches" is the pass
//   condition Step 3 asks for at every boundary length. That needs a
//   second implementation which is not the one under test — otherwise
//   the assertion is that the assembly agrees with itself, which it
//   always will.
//
//   Everything here is written for obviousness, not speed: no tables
//   beyond the ones the specification itself defines, no SIMD, no
//   vectorised tails, no clever length handling. Byte at a time, block
//   at a time, straight out of the standard. That is the point — the
//   whole class of bug this catches is "the fast path handles a partial
//   tail differently from the slow path", and a reference that shares
//   the same trick shares the same bug.
//
//   Every function here is checked against published test vectors
//   (FIPS 180-4, FIPS 197, RFC 4231, RFC 5869, SP 800-38D) by the
//   ref_selfcheck suite each test binary runs *before* it compares
//   anything to the assembly. A reference that has drifted must fail
//   loudly rather than quietly validate a broken implementation.
//
//   Sources:
//     SHA-256      FIPS 180-4 §6.2
//     HMAC         RFC 2104 / FIPS 198-1
//     HKDF         RFC 5869 §2.2-2.3
//     HkdfLabel    RFC 8446 §7.1
//     AES-128      FIPS 197 §5.1
//     GHASH / GCM  NIST SP 800-38D §6.3-§6.4, §7.1
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_CRYPTO_REF_H
#define SARM_CRYPTO_REF_H

#include <stddef.h>
#include <stdint.h>

// ── SHA-256 (FIPS 180-4) ────────────────────────────────────────────

static uint32_t ref_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t REF_K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

// One compression round set over a single 64-byte block, straight from
// FIPS 180-4 §6.2.2. Exported because Step 3 drives the assembly
// `sha256` (which is the raw block function, not the streaming API)
// directly at block-count boundaries.
static void ref_sha256_compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
               ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = ref_rotr(w[i - 15], 7) ^ ref_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = ref_rotr(w[i - 2], 17) ^ ref_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; i++) {
        const uint32_t S1 = ref_rotr(e, 6) ^ ref_rotr(e, 11) ^ ref_rotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + REF_K256[i] + w[i];
        const uint32_t S0 = ref_rotr(a, 2) ^ ref_rotr(a, 13) ^ ref_rotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static const uint32_t REF_SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

#define REF_SHA256_MAX_MSG 65536

static void ref_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    static uint8_t padded[REF_SHA256_MAX_MSG + 128];
    uint32_t h[8];
    for (int i = 0; i < 8; i++)
        h[i] = REF_SHA256_IV[i];

    for (size_t i = 0; i < len; i++)
        padded[i] = msg[i];
    size_t n = len;
    padded[n++] = 0x80;
    while (n % 64 != 56)
        padded[n++] = 0x00;
    const uint64_t bits = (uint64_t)len * 8;
    for (int i = 7; i >= 0; i--)
        padded[n++] = (uint8_t)(bits >> (8 * i));

    for (size_t off = 0; off < n; off += 64)
        ref_sha256_compress(h, padded + off);

    for (int i = 0; i < 8; i++) {
        out[4 * i]     = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
}

// ── HMAC-SHA256 (RFC 2104) ──────────────────────────────────────────

#define REF_HMAC_BLOCK 64

static void ref_hmac_sha256(const uint8_t *key, size_t keylen,
                            const uint8_t *data, size_t datalen,
                            uint8_t out[32])
{
    uint8_t k[REF_HMAC_BLOCK] = {0};
    if (keylen > REF_HMAC_BLOCK) {
        ref_sha256(key, keylen, k);          // §2: keys longer than the
                                             // block are hashed first
    } else {
        for (size_t i = 0; i < keylen; i++)
            k[i] = key[i];
    }

    static uint8_t inner[REF_HMAC_BLOCK + REF_SHA256_MAX_MSG];
    uint8_t outer[REF_HMAC_BLOCK + 32];

    for (int i = 0; i < REF_HMAC_BLOCK; i++)
        inner[i] = (uint8_t)(k[i] ^ 0x36);
    for (size_t i = 0; i < datalen; i++)
        inner[REF_HMAC_BLOCK + i] = data[i];

    uint8_t inner_digest[32];
    ref_sha256(inner, REF_HMAC_BLOCK + datalen, inner_digest);

    for (int i = 0; i < REF_HMAC_BLOCK; i++)
        outer[i] = (uint8_t)(k[i] ^ 0x5c);
    for (int i = 0; i < 32; i++)
        outer[REF_HMAC_BLOCK + i] = inner_digest[i];

    ref_sha256(outer, REF_HMAC_BLOCK + 32, out);
}

// ── HKDF (RFC 5869) ─────────────────────────────────────────────────

static void ref_hkdf_extract(const uint8_t *salt, size_t saltlen,
                             const uint8_t *ikm, size_t ikmlen,
                             uint8_t prk[32])
{
    const uint8_t zeros[32] = {0};
    if (saltlen == 0) {
        salt = zeros;            // §2.2: absent salt is HashLen zeros
        saltlen = 32;
    }
    ref_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

// okmlen may be up to 255 * 32 = 8160 (§2.3).
static void ref_hkdf_expand(const uint8_t *prk, size_t prklen,
                            const uint8_t *info, size_t infolen,
                            uint8_t *okm, size_t okmlen)
{
    uint8_t t[32];
    size_t tlen = 0;
    size_t done = 0;
    uint8_t counter = 1;

    static uint8_t block[32 + 4096 + 1];

    while (done < okmlen) {
        size_t n = 0;
        for (size_t i = 0; i < tlen; i++)
            block[n++] = t[i];
        for (size_t i = 0; i < infolen; i++)
            block[n++] = info[i];
        block[n++] = counter;

        ref_hmac_sha256(prk, prklen, block, n, t);
        tlen = 32;

        const size_t take = (okmlen - done < 32) ? (okmlen - done) : 32;
        for (size_t i = 0; i < take; i++)
            okm[done + i] = t[i];
        done += take;
        counter++;
    }
}

// RFC 8446 §7.1 HKDF-Expand-Label: the HkdfLabel struct is
//   uint16 length; opaque label<7..255> = "tls13 " + label;
//   opaque context<0..255>;
static void ref_hkdf_expand_label(const uint8_t secret[32],
                                  const char *label, size_t label_len,
                                  const uint8_t *context, size_t context_len,
                                  uint8_t *out, size_t outlen)
{
    static uint8_t info[2 + 1 + 6 + 255 + 1 + 255];
    size_t n = 0;

    info[n++] = (uint8_t)(outlen >> 8);
    info[n++] = (uint8_t)outlen;
    info[n++] = (uint8_t)(6 + label_len);
    const char *prefix = "tls13 ";
    for (int i = 0; i < 6; i++)
        info[n++] = (uint8_t)prefix[i];
    for (size_t i = 0; i < label_len; i++)
        info[n++] = (uint8_t)label[i];
    info[n++] = (uint8_t)context_len;
    for (size_t i = 0; i < context_len; i++)
        info[n++] = context[i];

    ref_hkdf_expand(secret, 32, info, n, out, outlen);
}

// ── AES-128 (FIPS 197) ──────────────────────────────────────────────

static const uint8_t REF_SBOX[256] = {
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

static uint8_t ref_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

// 176-byte round key schedule (11 round keys of 16 bytes)
static void ref_aes128_key_expand(const uint8_t key[16], uint8_t rk[176])
{
    for (int i = 0; i < 16; i++)
        rk[i] = key[i];

    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t t[4] = { rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1] };
        if (i % 16 == 0) {
            const uint8_t tmp = t[0];
            t[0] = (uint8_t)(REF_SBOX[t[1]] ^ rcon);
            t[1] = REF_SBOX[t[2]];
            t[2] = REF_SBOX[t[3]];
            t[3] = REF_SBOX[tmp];
            rcon = ref_xtime(rcon);
        }
        for (int j = 0; j < 4; j++)
            rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ t[j]);
    }
}

static void ref_aes128_encrypt(const uint8_t pt[16], const uint8_t rk[176],
                               uint8_t ct[16])
{
    uint8_t s[16];
    for (int i = 0; i < 16; i++)
        s[i] = (uint8_t)(pt[i] ^ rk[i]);

    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++)                 // SubBytes
            s[i] = REF_SBOX[s[i]];

        uint8_t t[16];                               // ShiftRows
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                t[4 * c + r] = s[4 * ((c + r) % 4) + r];
        for (int i = 0; i < 16; i++)
            s[i] = t[i];

        if (round != 10) {                           // MixColumns
            for (int c = 0; c < 4; c++) {
                uint8_t *col = s + 4 * c;
                const uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = (uint8_t)(ref_xtime(a0) ^ (ref_xtime(a1) ^ a1) ^ a2 ^ a3);
                col[1] = (uint8_t)(a0 ^ ref_xtime(a1) ^ (ref_xtime(a2) ^ a2) ^ a3);
                col[2] = (uint8_t)(a0 ^ a1 ^ ref_xtime(a2) ^ (ref_xtime(a3) ^ a3));
                col[3] = (uint8_t)((ref_xtime(a0) ^ a0) ^ a1 ^ a2 ^ ref_xtime(a3));
            }
        }

        for (int i = 0; i < 16; i++)                 // AddRoundKey
            s[i] = (uint8_t)(s[i] ^ rk[16 * round + i]);
    }

    for (int i = 0; i < 16; i++)
        ct[i] = s[i];
}

// ── GHASH and AES-128-GCM (SP 800-38D) ──────────────────────────────

// The bitwise GF(2^128) multiply from §6.3, with no Karatsuba, no
// PMULL and no deferred reduction — deliberately the least clever
// implementation that is still correct.
static void ref_gf_mult(const uint8_t x[16], const uint8_t y[16], uint8_t z[16])
{
    uint8_t v[16], out[16] = {0};
    for (int i = 0; i < 16; i++)
        v[i] = y[i];

    for (int i = 0; i < 128; i++) {
        const int byte = i / 8;
        const int bit  = 7 - (i % 8);
        if ((x[byte] >> bit) & 1)
            for (int j = 0; j < 16; j++)
                out[j] ^= v[j];

        const int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xe1;       // R = 11100001 || 0^120
    }

    for (int i = 0; i < 16; i++)
        z[i] = out[i];
}

static void ref_ghash_absorb(uint8_t y[16], const uint8_t h[16],
                             const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        uint8_t block[16] = {0};
        const size_t take = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < take; i++)
            block[i] = data[off + i];        // partial blocks are
                                             // zero-padded (§6.4)
        for (int i = 0; i < 16; i++)
            y[i] ^= block[i];
        uint8_t tmp[16];
        ref_gf_mult(y, h, tmp);
        for (int i = 0; i < 16; i++)
            y[i] = tmp[i];
        off += take;
    }
}

static void ref_ghash(const uint8_t h[16],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t out[16])
{
    uint8_t y[16] = {0};
    ref_ghash_absorb(y, h, aad, aad_len);
    ref_ghash_absorb(y, h, ct, ct_len);

    uint8_t lenblock[16] = {0};
    const uint64_t abits = (uint64_t)aad_len * 8;
    const uint64_t cbits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) {
        lenblock[i]     = (uint8_t)(abits >> (8 * (7 - i)));
        lenblock[8 + i] = (uint8_t)(cbits >> (8 * (7 - i)));
    }
    for (int i = 0; i < 16; i++)
        y[i] ^= lenblock[i];
    ref_gf_mult(y, h, out);
}

// AES-128-GCM with a 12-byte IV (the only case sarm uses, and the only
// case where J0 = IV || 0^31 || 1 — §7.1).
static void ref_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[16])
{
    uint8_t rk[176];
    ref_aes128_key_expand(key, rk);

    uint8_t h[16];
    const uint8_t zero[16] = {0};
    ref_aes128_encrypt(zero, rk, h);

    uint8_t j0[16] = {0};
    for (int i = 0; i < 12; i++)
        j0[i] = iv[i];
    j0[15] = 1;

    uint8_t counter[16];
    for (int i = 0; i < 16; i++)
        counter[i] = j0[i];

    for (size_t off = 0; off < pt_len; off += 16) {
        for (int i = 15; i >= 12; i--)          // inc32
            if (++counter[i] != 0)
                break;
        uint8_t ks[16];
        ref_aes128_encrypt(counter, rk, ks);
        const size_t take = (pt_len - off < 16) ? (pt_len - off) : 16;
        for (size_t i = 0; i < take; i++)
            ct[off + i] = (uint8_t)(pt[off + i] ^ ks[i]);
    }

    uint8_t s[16];
    ref_ghash(h, aad, aad_len, ct, pt_len, s);

    uint8_t ej0[16];
    ref_aes128_encrypt(j0, rk, ej0);
    for (int i = 0; i < 16; i++)
        tag[i] = (uint8_t)(s[i] ^ ej0[i]);
}

// Returns 1 if the tag verifies (and pt is written), 0 otherwise.
static int ref_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[16], uint8_t *pt)
{
    uint8_t rk[176];
    ref_aes128_key_expand(key, rk);

    uint8_t h[16];
    const uint8_t zero[16] = {0};
    ref_aes128_encrypt(zero, rk, h);

    uint8_t j0[16] = {0};
    for (int i = 0; i < 12; i++)
        j0[i] = iv[i];
    j0[15] = 1;

    uint8_t s[16], ej0[16], expected[16];
    ref_ghash(h, aad, aad_len, ct, ct_len, s);
    ref_aes128_encrypt(j0, rk, ej0);
    for (int i = 0; i < 16; i++)
        expected[i] = (uint8_t)(s[i] ^ ej0[i]);

    int diff = 0;
    for (int i = 0; i < 16; i++)
        diff |= expected[i] ^ tag[i];
    if (diff != 0)
        return 0;

    uint8_t counter[16];
    for (int i = 0; i < 16; i++)
        counter[i] = j0[i];
    for (size_t off = 0; off < ct_len; off += 16) {
        for (int i = 15; i >= 12; i--)
            if (++counter[i] != 0)
                break;
        uint8_t ks[16];
        ref_aes128_encrypt(counter, rk, ks);
        const size_t take = (ct_len - off < 16) ? (ct_len - off) : 16;
        for (size_t i = 0; i < take; i++)
            pt[off + i] = (uint8_t)(ct[off + i] ^ ks[i]);
    }
    return 1;
}

#endif // SARM_CRYPTO_REF_H
