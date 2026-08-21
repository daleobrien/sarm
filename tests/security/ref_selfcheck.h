// sarm security tests — pinning the C references to published vectors
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/ref_selfcheck.h — the standards vectors the
//   reference implementations must reproduce before they are allowed
//   to judge anything
//
// Description: every suite from Step 3 onward decides pass or fail by
//   comparing assembly against the C references in crypto_ref.h. That
//   comparison is worth exactly as much as the reference is, so the
//   reference is checked first, against vectors published by someone
//   who has never seen this codebase: FIPS 180-4 for SHA-256, RFC 4231
//   for HMAC, RFC 5869 for HKDF, FIPS 197 for AES, and the
//   McGrew-Viega vectors carried into SP 800-38D for GCM.
//
//   Run these at the top of main(), before any sweep. A reference that
//   has drifted turns a green suite into a lie, and this is the only
//   thing standing between the two.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_REF_SELFCHECK_H
#define SARM_REF_SELFCHECK_H

#include "crypto_ref.h"
#include "../unit/test_harness.h"

#include <stdint.h>
#include <stddef.h>

// Byte comparison, kept local so this header stands alone.
static int refchk_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    int d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

// ── reference self-checks ───────────────────────────────────────────
// Run these FIRST in every suite. "The assembly matches the reference"
// is worth nothing if the reference has drifted, so the reference is
// pinned to published vectors before it is used to judge anything.

static void ref_selfcheck_sha256(void)
{
    TEST_SUITE("reference self-check — SHA-256 (FIPS 180-4)");

    // FIPS 180-4 / the two canonical vectors
    static const uint8_t empty[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,
        0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
    };
    static const uint8_t abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,
        0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };

    uint8_t got[32];
    ref_sha256((const uint8_t *)"", 0, got);
    ASSERT_TRUE("SHA-256(\"\")", refchk_eq(got, empty, 32));
    ref_sha256((const uint8_t *)"abc", 3, got);
    ASSERT_TRUE("SHA-256(\"abc\")", refchk_eq(got, abc, 32));
}

static void ref_selfcheck_hmac_hkdf(void)
{
    TEST_SUITE("reference self-check — HMAC (RFC 4231) / HKDF (RFC 5869)");

    uint8_t got[64];

    // RFC 4231 test case 1
    {
        uint8_t key[20];
        for (int i = 0; i < 20; i++) key[i] = 0x0b;
        static const uint8_t want[32] = {
            0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,
            0xaf,0x0b,0xf1,0x2b,0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
            0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7,
        };
        ref_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, got);
        ASSERT_TRUE("HMAC-SHA256 RFC 4231 case 1", refchk_eq(got, want, 32));
    }

    // RFC 4231 test case 3 — a key longer than the 64-byte block, which
    // is the branch the assembly hashes the key on
    {
        uint8_t key[131];
        for (int i = 0; i < 131; i++) key[i] = 0xaa;
        static const uint8_t want[32] = {
            0x60,0xe4,0x31,0x59,0x1e,0xe0,0xb6,0x7f,0x0d,0x8a,0x26,0xaa,
            0xcb,0xf5,0xb7,0x7f,0x8e,0x0b,0xc6,0x21,0x37,0x28,0xc5,0x14,
            0x05,0x46,0x04,0x0f,0x0e,0xe3,0x7f,0x54,
        };
        const char *msg = "Test Using Larger Than Block-Size Key - Hash "
                          "Key First";
        size_t msglen = 0;
        while (msg[msglen]) msglen++;
        ref_hmac_sha256(key, 131, (const uint8_t *)msg, msglen, got);
        ASSERT_TRUE("HMAC-SHA256 RFC 4231 case 4 (key > block)",
                    refchk_eq(got, want, 32));
    }

    // RFC 5869 test case 1
    {
        uint8_t ikm[22], salt[13], info[10];
        for (int i = 0; i < 22; i++) ikm[i] = 0x0b;
        for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);

        static const uint8_t want_prk[32] = {
            0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,0x3f,0x0d,
            0xc4,0x7b,0xba,0x63,0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
            0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5,
        };
        static const uint8_t want_okm[42] = {
            0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,
            0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
            0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,
            0xd5,0xb8,0x87,0x18,0x58,0x65,
        };

        uint8_t prk[32], okm[42];
        ref_hkdf_extract(salt, 13, ikm, 22, prk);
        ASSERT_TRUE("HKDF-Extract RFC 5869 case 1", refchk_eq(prk, want_prk, 32));
        ref_hkdf_expand(prk, 32, info, 10, okm, 42);
        ASSERT_TRUE("HKDF-Expand RFC 5869 case 1", refchk_eq(okm, want_okm, 42));
    }
}

static void ref_selfcheck_aes_gcm(void)
{
    TEST_SUITE("reference self-check — AES-128 (FIPS 197) / GCM (SP 800-38D)");

    // FIPS 197 Appendix C.1
    {
        uint8_t key[16], pt[16], rk[176], ct[16];
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(0x00 + i * 0x11);
        static const uint8_t want[16] = {
            0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a,
        };
        ref_aes128_key_expand(key, rk);
        ref_aes128_encrypt(pt, rk, ct);
        ASSERT_TRUE("AES-128 FIPS 197 C.1", refchk_eq(ct, want, 16));
    }

    // SP 800-38D / McGrew-Viega test case 1: all-zero key and IV, no
    // plaintext, no AAD — the tag is E_K(J0) alone, so it pins J0
    // construction and the empty-input GHASH path at once.
    {
        const uint8_t key[16] = {0}, iv[12] = {0};
        uint8_t tag[16];
        static const uint8_t want[16] = {
            0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
            0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a,
        };
        ref_gcm_encrypt(key, iv, NULL, 0, NULL, 0, NULL, tag);
        ASSERT_TRUE("AES-128-GCM test case 1 (empty)", refchk_eq(tag, want, 16));
    }

    // test case 2: one all-zero plaintext block
    {
        const uint8_t key[16] = {0}, iv[12] = {0}, pt[16] = {0};
        uint8_t ct[16], tag[16];
        static const uint8_t want_ct[16] = {
            0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
            0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
        };
        static const uint8_t want_tag[16] = {
            0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
            0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf,
        };
        ref_gcm_encrypt(key, iv, NULL, 0, pt, 16, ct, tag);
        ASSERT_TRUE("AES-128-GCM test case 2 ciphertext",
                    refchk_eq(ct, want_ct, 16));
        ASSERT_TRUE("AES-128-GCM test case 2 tag",
                    refchk_eq(tag, want_tag, 16));
    }
}

#endif // SARM_REF_SELFCHECK_H
