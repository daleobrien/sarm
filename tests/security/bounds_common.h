// sarm security tests — shared scaffolding for the boundary suites
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/bounds_common.h — the pattern every
//   test_bounds_*.c suite follows (docs/SECURITY.md, Step 3)
//
// Description: Step 3 asks one question of every assembly routine, at
//   every interesting length:
//
//     0, 1, block-1, block, block+1, large, maximum supported
//     -> no crash, and reference output matches
//
//   Both halves are answered by one run here. Each case allocates
//   guarded buffers (guard_pages.h) for every pointer the routine
//   touches, sized to *exactly* what the caller declared, then runs the
//   call inside a forked child:
//
//     * touch a byte outside a declared buffer  -> SIGSEGV/SIGBUS,
//       reported as an out-of-bounds failure naming the case
//     * produce output the C reference disagrees with -> the child
//       exits BOUNDS_MISMATCH
//     * otherwise -> pass
//
//   The fork is what makes the suite survivable. An out-of-bounds
//   access in-process would take the whole binary down on the first
//   bad case and hide every case after it; here each case is isolated,
//   so one run reports every length that fails, which is the difference
//   between "GHASH is broken somewhere" and "GHASH is broken at 17, 33
//   and 49 bytes, i.e. one past each 16-byte block".
//
//   Both guard sides are exercised. A routine can be flush against the
//   trailing guard (an over-read past the end traps) or the leading one
//   (a pointer walked backwards traps), never both at once, so every
//   case runs twice.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_BOUNDS_COMMON_H
#define SARM_BOUNDS_COMMON_H

#include "guard_pages.h"
#include "crypto_ref.h"
#include "../unit/test_harness.h"

#include <stdint.h>
#include <stddef.h>

// ── child verdicts ──────────────────────────────────────────────────
// Returned by a probe function through guard_probe_status. 77 is
// reserved (GUARD_CHILD_FAULTED).
#define BOUNDS_PASS      0
#define BOUNDS_MISMATCH  1
#define BOUNDS_BADSETUP  2   // the test itself could not set the case up

// ── the boundary corpus ─────────────────────────────────────────────
// docs/SECURITY.md §3.3: "0 1 2 15 16 17 31 32 33 63 64 65 127 128 129
// — especially useful because your crypto and networking code will
// probably have block boundaries at 16, 32, or 64 bytes." Plus the
// large and maximum-supported cases Step 3 names.

// every block boundary and its neighbours, for byte-length arguments
#define BOUNDS_LENGTHS \
    0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, \
    255, 256, 257, 1023, 1024, 1025

// a shorter list, for arguments that are swept against another swept
// argument (the cross product would otherwise be thousands of forks)
#define BOUNDS_LENGTHS_SHORT \
    0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65

static const size_t bounds_lengths[] = { BOUNDS_LENGTHS };
static const size_t bounds_lengths_short[] = { BOUNDS_LENGTHS_SHORT };

#define BOUNDS_N(arr) (sizeof(arr) / sizeof((arr)[0]))

// ── guarded buffer helpers ──────────────────────────────────────────

// Deterministic, position-dependent filler. Position-dependent matters:
// a routine that copies the wrong 16 bytes produces obviously wrong
// output rather than accidentally-correct output, which a constant fill
// would hide.
static void bounds_pattern(uint8_t *p, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t)(seed + i * 31u + (i >> 3));
}

// Allocate a guarded buffer of exactly `len` bytes and fill it with the
// pattern. Returns 0 on success.
static int bounds_in(struct guarded_buffer *gb, size_t len,
                     enum guard_side side, uint8_t seed)
{
    if (guard_alloc_side(gb, len, side) != 0)
        return -1;
    bounds_pattern(gb->data, len, seed);
    return 0;
}

// Allocate a guarded output buffer of exactly `len` bytes, poisoned.
// 0xA5 rather than 0: a routine that writes nothing at all leaves
// recognisable poison instead of plausible zeros.
static int bounds_out(struct guarded_buffer *gb, size_t len,
                      enum guard_side side)
{
    if (guard_alloc_side(gb, len, side) != 0)
        return -1;
    guard_fill(gb, 0xA5);
    return 0;
}

static int bounds_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    int diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// ── the case runner ─────────────────────────────────────────────────

static const char *bounds_side_name(enum guard_side side)
{
    return side == GUARD_OVERRUN ? "overrun-guarded" : "underrun-guarded";
}

// Run one case and record a single assertion for it.
static void bounds_case(const char *label, void (*fn)(void *), void *ctx)
{
    int verdict = 0;
    const int r = guard_probe_status(fn, ctx, &verdict);

    if (r == GUARD_PROBE_FAULT) {
        _FAIL("%s — OUT OF BOUNDS: touched memory outside its declared "
              "buffers", label);
        return;
    }
    if (r == GUARD_PROBE_TIMEOUT) {
        _FAIL("%s — DID NOT TERMINATE within %d seconds", label,
              GUARD_PROBE_SECS);
        return;
    }
    if (r != GUARD_PROBE_OK) {
        _FAIL("%s — probe error (fork/waitpid failed)", label);
        return;
    }
    switch (verdict) {
    case BOUNDS_PASS:
        _PASS(label);
        break;
    case BOUNDS_MISMATCH:
        _FAIL("%s — output differs from the reference implementation", label);
        break;
    case BOUNDS_BADSETUP:
        _FAIL("%s — could not set the case up (allocation failed)", label);
        break;
    default:
        _FAIL("%s — child exited %d (unexpected)", label, verdict);
        break;
    }
}

// ── raising the harness timeout ─────────────────────────────────────
// test_harness.h arms alarm(5) at load time so a hung test can never
// block `make test` forever. These suites fork hundreds of children and
// run a deliberately slow bitwise reference, so they re-arm it longer.
// Still bounded — a hang must still be caught, just not a slow pass.
extern unsigned int alarm(unsigned int seconds);
static void bounds_extend_timeout(void) { alarm(120); }

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
    ASSERT_TRUE("SHA-256(\"\")", bounds_eq(got, empty, 32));
    ref_sha256((const uint8_t *)"abc", 3, got);
    ASSERT_TRUE("SHA-256(\"abc\")", bounds_eq(got, abc, 32));
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
        ASSERT_TRUE("HMAC-SHA256 RFC 4231 case 1", bounds_eq(got, want, 32));
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
                    bounds_eq(got, want, 32));
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
        ASSERT_TRUE("HKDF-Extract RFC 5869 case 1", bounds_eq(prk, want_prk, 32));
        ref_hkdf_expand(prk, 32, info, 10, okm, 42);
        ASSERT_TRUE("HKDF-Expand RFC 5869 case 1", bounds_eq(okm, want_okm, 42));
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
        ASSERT_TRUE("AES-128 FIPS 197 C.1", bounds_eq(ct, want, 16));
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
        ASSERT_TRUE("AES-128-GCM test case 1 (empty)", bounds_eq(tag, want, 16));
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
                    bounds_eq(ct, want_ct, 16));
        ASSERT_TRUE("AES-128-GCM test case 2 tag",
                    bounds_eq(tag, want_tag, 16));
    }
}

#endif // SARM_BOUNDS_COMMON_H
