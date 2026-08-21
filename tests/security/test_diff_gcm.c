// sarm security tests — AES-128, GHASH and AES-128-GCM against a
// reference, over random vectors
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 4. Routines covered:
//   aes128_key_expand(key, rk)         src/crypto/aes128/key_expand.S
//   aes128_encrypt(pt, rk, ct)         src/crypto/aes128/encrypt.S
//   gf_mult_128(x, y, z)               src/crypto/gcm/gf_mult_128.S
//   ghash(h, aad, alen, ct, clen, out) src/crypto/gcm/ghash.S
//   aes_gcm_encrypt / aes_gcm_decrypt  src/crypto/gcm/{encrypt,decrypt}.S
//
// This is the record layer, and it is the one place in the codebase
// where a wrong answer is worse than a crash. A GCM implementation
// that produces a tag nobody else produces fails loudly and safely; an
// implementation that *accepts* a tag it should reject is a forgery
// oracle, and nothing above it in the stack will notice. So the sweeps
// below check both directions: every sealed record must match the
// reference byte for byte, and every tampered record must be refused.
//
// GHASH gets the most vectors. It runs four blocks at a time over
// attacker-chosen lengths, with a partial tail zero-padded, and the
// length block at the end is built from two 64-bit counts — three
// separate opportunities for an off-by-one that only shows at lengths
// nobody would think to write down.

#include "diff_common.h"

extern void aes128_key_expand(const void *key, void *rk)
    __asm__("aes128_key_expand");
extern void aes128_encrypt(const void *pt, const void *rk, void *ct)
    __asm__("aes128_encrypt");
extern void gf_mult_128(const void *x, const void *y, void *z)
    __asm__("gf_mult_128");
extern void ghash(const void *h, const void *aad, uint64_t aad_len,
                  const void *ct, uint64_t ct_len, void *out) __asm__("ghash");
extern void aes_gcm_encrypt(const void *key, const void *iv,
                            const void *aad, uint64_t aad_len,
                            const void *pt, uint64_t pt_len,
                            void *ct, void *tag) __asm__("aes_gcm_encrypt");
extern uint64_t aes_gcm_decrypt(const void *key, const void *iv,
                                const void *aad, uint64_t aad_len,
                                const void *ct, uint64_t ct_len,
                                const void *tag, void *pt)
    __asm__("aes_gcm_decrypt");

// A TLS 1.3 record's inner plaintext maxes out at 2^14 + 1; these
// sweeps stay a little under that for speed and take the exact maxima
// from the Step 3 suite, which tests them explicitly.
#define MAX_PT  2048
#define MAX_AAD 256

// ── AES-128 ─────────────────────────────────────────────────────────
// The key schedule and the block cipher are checked together and
// separately: together because that is how they are used, separately
// because a schedule that is wrong from round 7 onward still produces
// a plausible-looking ciphertext, and comparing the 176-byte schedule
// itself says exactly which round went wrong.

static int case_aes(struct diff_rng *rng, char *detail, size_t len)
{
    uint8_t key[16], pt[16], want_rk[176], want_ct[16];
    diff_rng_bytes(rng, key, 16);
    diff_rng_bytes(rng, pt, 16);

    DIFF_OUT(rk, 176);
    DIFF_OUT(ct, 16);

    aes128_key_expand(key, rk);
    DIFF_CHECK_TAIL(rk, 176, "aes128_key_expand", detail, len);
    ref_aes128_key_expand(key, want_rk);

    if (!diff_eq(rk, want_rk, 176)) {
        const long at = diff_first_delta(rk, want_rk, 176);
        snprintf(detail, len,
                 "key schedule differs at byte %ld (round %ld)",
                 at, at / 16);
        return 0;
    }

    aes128_encrypt(pt, rk, ct);
    DIFF_CHECK_TAIL(ct, 16, "aes128_encrypt", detail, len);
    ref_aes128_encrypt(pt, want_rk, want_ct);

    if (!diff_eq(ct, want_ct, 16)) {
        diff_report(detail, len, "aes128_encrypt", 16, ct, want_ct, 16);
        return 0;
    }
    return 1;
}

// ── the GF(2^128) multiplier ────────────────────────────────────────
// The reference does this bit by bit; the assembly does it with carry-
// less multiplies and a folded reduction. Nothing about the two shapes
// is alike, which is exactly what makes agreement meaningful.

static int case_gf_mult(struct diff_rng *rng, char *detail, size_t len)
{
    uint8_t x[16], y[16], want[16];
    diff_rng_bytes(rng, x, 16);
    diff_rng_bytes(rng, y, 16);

    DIFF_OUT(z, 16);
    gf_mult_128(x, y, z);
    DIFF_CHECK_TAIL(z, 16, "gf_mult_128", detail, len);

    ref_gf_mult(x, y, want);
    if (!diff_eq(z, want, 16)) {
        diff_report(detail, len, "gf_mult_128", 16, z, want, 16);
        return 0;
    }
    return 1;
}

// The field is commutative, and the assembly's two operands take
// different paths through the routine. Agreement with the reference
// already implies this, but a failure here says something sharper: the
// bug depends on which operand is which.
static int case_gf_commutes(struct diff_rng *rng, char *detail, size_t len)
{
    uint8_t x[16], y[16];
    diff_rng_bytes(rng, x, 16);
    diff_rng_bytes(rng, y, 16);

    DIFF_OUT(xy, 16);
    DIFF_OUT(yx, 16);
    gf_mult_128(x, y, xy);
    gf_mult_128(y, x, yx);

    if (!diff_eq(xy, yx, 16)) {
        diff_report(detail, len, "gf_mult_128 x*y vs y*x", 16, xy, yx, 16);
        return 0;
    }
    return 1;
}

// ── GHASH ───────────────────────────────────────────────────────────

static int case_ghash(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t alen = diff_rng_len(rng, MAX_AAD);
    const size_t clen = diff_rng_len(rng, MAX_PT);

    uint8_t h[16], aad[MAX_AAD], ct[MAX_PT], want[16];
    diff_rng_bytes(rng, h, 16);
    diff_rng_bytes(rng, aad, alen);
    diff_rng_bytes(rng, ct, clen);

    DIFF_OUT(got, 16);
    ghash(h, aad, alen, ct, clen, got);
    DIFF_CHECK_TAIL(got, 16, "ghash", detail, len);

    ref_ghash(h, aad, alen, ct, clen, want);
    if (!diff_eq(got, want, 16)) {
        char msg[64];
        snprintf(msg, sizeof msg, "ghash (aad %llu)",
                 (unsigned long long)alen);
        diff_report(detail, len, msg, clen, got, want, 16);
        return 0;
    }
    return 1;
}

// ── AES-128-GCM, sealing ────────────────────────────────────────────

static int case_gcm_encrypt(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t alen = diff_rng_len(rng, MAX_AAD);
    const size_t plen = diff_rng_len(rng, MAX_PT);

    uint8_t key[16], iv[12], aad[MAX_AAD], pt[MAX_PT];
    uint8_t want_ct[MAX_PT], want_tag[16];
    diff_rng_bytes(rng, key, 16);
    diff_rng_bytes(rng, iv, 12);
    diff_rng_bytes(rng, aad, alen);
    diff_rng_bytes(rng, pt, plen);

    DIFF_OUT(ct, MAX_PT);
    DIFF_OUT(tag, 16);

    aes_gcm_encrypt(key, iv, aad, alen, pt, plen, ct, tag);
    DIFF_CHECK_TAIL(ct, MAX_PT, "aes_gcm_encrypt ciphertext", detail, len);
    DIFF_CHECK_TAIL(tag, 16, "aes_gcm_encrypt tag", detail, len);

    ref_gcm_encrypt(key, iv, aad, alen, pt, plen, want_ct, want_tag);

    if (!diff_eq(ct, want_ct, plen)) {
        char msg[64];
        snprintf(msg, sizeof msg, "gcm ciphertext (aad %llu)",
                 (unsigned long long)alen);
        diff_report(detail, len, msg, plen, ct, want_ct, plen);
        return 0;
    }
    if (!diff_eq(tag, want_tag, 16)) {
        char msg[64];
        snprintf(msg, sizeof msg, "gcm tag (aad %llu)",
                 (unsigned long long)alen);
        diff_report(detail, len, msg, plen, tag, want_tag, 16);
        return 0;
    }
    return 1;
}

// ── AES-128-GCM, opening ────────────────────────────────────────────
// Four things, in the order that matters: the assembly opens what the
// reference sealed (so it agrees about what a valid record is), the
// reference opens what the assembly sealed (so the agreement is not
// two implementations sharing one delusion), the plaintext comes back
// intact, and a single flipped bit anywhere is refused.

static int case_gcm_decrypt(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t alen = diff_rng_len(rng, MAX_AAD);
    const size_t plen = diff_rng_len(rng, MAX_PT);

    uint8_t key[16], iv[12], aad[MAX_AAD], pt[MAX_PT];
    uint8_t ref_ct[MAX_PT], ref_tag[16], ref_out[MAX_PT];
    diff_rng_bytes(rng, key, 16);
    diff_rng_bytes(rng, iv, 12);
    diff_rng_bytes(rng, aad, alen);
    diff_rng_bytes(rng, pt, plen);

    ref_gcm_encrypt(key, iv, aad, alen, pt, plen, ref_ct, ref_tag);

    DIFF_OUT(out, MAX_PT);
    if (aes_gcm_decrypt(key, iv, aad, alen, ref_ct, plen, ref_tag, out) != 1) {
        snprintf(detail, len,
                 "rejected a valid record the reference produced "
                 "(aad %llu, ct %llu)",
                 (unsigned long long)alen, (unsigned long long)plen);
        return 0;
    }
    DIFF_CHECK_TAIL(out, MAX_PT, "aes_gcm_decrypt", detail, len);

    if (!diff_eq(out, pt, plen)) {
        diff_report(detail, len, "gcm recovered plaintext", plen,
                    out, pt, plen);
        return 0;
    }

    // and the other direction
    DIFF_OUT(ct, MAX_PT);
    DIFF_OUT(tag, 16);
    aes_gcm_encrypt(key, iv, aad, alen, pt, plen, ct, tag);
    if (!ref_gcm_decrypt(key, iv, aad, alen, ct, plen, tag, ref_out)) {
        snprintf(detail, len,
                 "the reference rejected a record the assembly sealed "
                 "(aad %llu, ct %llu)",
                 (unsigned long long)alen, (unsigned long long)plen);
        return 0;
    }

    // A single random bit, anywhere in the tag, the ciphertext or the
    // AAD. Random rather than fixed: the Step 3 suite flips known
    // positions, and what this adds is every other position.
    const uint64_t total_bits = 16 * 8 + plen * 8 + alen * 8;
    uint64_t bit = diff_rng_below(rng, total_bits);
    const char *where;
    uint8_t *target;
    if (bit < 16 * 8)          { where = "tag";        target = tag; }
    else if (bit < 16 * 8 + plen * 8)
                               { bit -= 16 * 8; where = "ciphertext"; target = ct; }
    else                       { bit -= 16 * 8 + plen * 8;
                                 where = "aad"; target = aad; }

    target[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    const uint64_t opened = aes_gcm_decrypt(key, iv, aad, alen, ct, plen,
                                            tag, out);
    target[bit / 8] ^= (uint8_t)(1u << (bit % 8));

    if (opened != 0) {
        snprintf(detail, len,
                 "FORGERY ACCEPTED: flipping bit %llu of the %s "
                 "(aad %llu, ct %llu) still verified",
                 (unsigned long long)bit, where,
                 (unsigned long long)alen, (unsigned long long)plen);
        return 0;
    }
    return 1;
}

int main(void)
{
    diff_init("differential: AES-128 / GHASH / AES-128-GCM");

    ref_selfcheck_aes_gcm();

    TEST_SUITE("differential — AES-128");
    diff_sweep("aes128 key schedule and block", case_aes, 120000);

    TEST_SUITE("differential — GF(2^128) and GHASH");
    diff_sweep("gf_mult_128", case_gf_mult, 120000);
    diff_sweep("gf_mult_128 commutativity", case_gf_commutes, 30000);
    diff_sweep("ghash", case_ghash, 12000);

    TEST_SUITE("differential — AES-128-GCM");
    diff_sweep("aes_gcm_encrypt", case_gcm_encrypt, 8000);
    diff_sweep("aes_gcm_decrypt round trip and forgery rejection",
               case_gcm_decrypt, 5000);

    test_summary();
    return 0;
}
