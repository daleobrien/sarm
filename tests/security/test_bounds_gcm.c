// sarm security tests — AES-128, GHASH and AES-128-GCM at their
// length boundaries
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 3. Routines covered:
//   aes128_key_expand(key, rk)         src/crypto/aes128/key_expand.S
//   aes128_encrypt(pt, rk, ct)         src/crypto/aes128/encrypt.S
//   gf_mult_128(x, y, z)               src/crypto/gcm/gf_mult_128.S
//   ghash(h, aad, alen, ct, clen, out) src/crypto/gcm/ghash.S
//   aes_gcm_encrypt(...)               src/crypto/gcm/encrypt.S
//   aes_gcm_decrypt(...)               src/crypto/gcm/decrypt.S
//
// This is the record layer's crypto: every byte the server sends or
// receives over TLS passes through aes_gcm_encrypt/decrypt, at whatever
// length the peer chose. The block size is 16 and GHASH reduces four
// blocks at a time, so the lengths that matter are the neighbours of
// every multiple of 16 *and* of 64 — a 4-block-at-a-time loop with a
// mishandled tail shows up at 17, 33, 49, 65 and nowhere else.
//
// The AAD is attacker-influenced too: in TLS 1.3 it is the 5-byte
// record header, but the routine takes any length, and Step 4's
// differential testing will lean on the same boundaries.

#include "bounds_common.h"

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

// ── the fixed-size primitives ───────────────────────────────────────
// No length argument at all, so the boundary question becomes: does it
// stay inside the fixed sizes its header declares? A guarded buffer of
// exactly 16 (or 176) bytes answers that — a routine that reads a
// 32-byte vector where 16 were promised traps.

struct fixed_case { enum guard_side side; };

static void probe_key_expand(void *ctx)
{
    const struct fixed_case *c = (const struct fixed_case *)ctx;

    struct guarded_buffer key, rk;
    if (bounds_in(&key, 16, c->side, 0x31) != 0 ||
        bounds_out(&rk, 176, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    aes128_key_expand(key.data, rk.data);

    uint8_t want[176];
    ref_aes128_key_expand(key.data, want);

    _exit(bounds_eq(rk.data, want, 176) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void probe_encrypt_block(void *ctx)
{
    const struct fixed_case *c = (const struct fixed_case *)ctx;

    struct guarded_buffer key, pt, rk, ct;
    if (bounds_in(&key, 16, c->side, 0x31) != 0 ||
        bounds_in(&pt, 16, c->side, 0x77) != 0 ||
        bounds_out(&rk, 176, c->side) != 0 ||
        bounds_out(&ct, 16, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    aes128_key_expand(key.data, rk.data);
    aes128_encrypt(pt.data, rk.data, ct.data);

    uint8_t want_rk[176], want[16];
    ref_aes128_key_expand(key.data, want_rk);
    ref_aes128_encrypt(pt.data, want_rk, want);

    _exit(bounds_eq(ct.data, want, 16) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void probe_gf_mult(void *ctx)
{
    const struct fixed_case *c = (const struct fixed_case *)ctx;

    struct guarded_buffer x, y, z;
    if (bounds_in(&x, 16, c->side, 0x05) != 0 ||
        bounds_in(&y, 16, c->side, 0xb3) != 0 ||
        bounds_out(&z, 16, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    gf_mult_128(x.data, y.data, z.data);

    uint8_t want[16];
    ref_gf_mult(x.data, y.data, want);

    _exit(bounds_eq(z.data, want, 16) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_fixed(void)
{
    TEST_SUITE("fixed-size primitives — exactly-sized guarded buffers");

    for (int s = 0; s < 2; s++) {
        const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
        struct fixed_case c = { side };
        char label[96];

        snprintf(label, sizeof(label), "aes128_key_expand (16 -> 176), %s",
                 bounds_side_name(side));
        bounds_case(label, probe_key_expand, &c);

        snprintf(label, sizeof(label), "aes128_encrypt (16, 176 -> 16), %s",
                 bounds_side_name(side));
        bounds_case(label, probe_encrypt_block, &c);

        snprintf(label, sizeof(label), "gf_mult_128 (16, 16 -> 16), %s",
                 bounds_side_name(side));
        bounds_case(label, probe_gf_mult, &c);
    }
}

// ── ghash ───────────────────────────────────────────────────────────

struct ghash_case {
    size_t aad_len;
    size_t ct_len;
    enum guard_side side;
};

static void probe_ghash(void *ctx)
{
    const struct ghash_case *c = (const struct ghash_case *)ctx;

    struct guarded_buffer h, aad, ct, out;
    if (bounds_in(&h, 16, c->side, 0x9d) != 0 ||
        bounds_in(&aad, c->aad_len, c->side, 0x24) != 0 ||
        bounds_in(&ct, c->ct_len, c->side, 0x68) != 0 ||
        bounds_out(&out, 16, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    ghash(h.data, aad.data, c->aad_len, ct.data, c->ct_len, out.data);

    uint8_t want[16];
    ref_ghash(h.data, aad.data, c->aad_len, ct.data, c->ct_len, want);

    _exit(bounds_eq(out.data, want, 16) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_ghash_lengths(void)
{
    TEST_SUITE("ghash — ciphertext lengths (16-byte blocks, 4 per reduction)");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct ghash_case c = { 13, bounds_lengths[i], side };
            char label[96];
            snprintf(label, sizeof(label), "ct %4zu bytes, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_ghash, &c);
        }
    }

    // Every length in the first four blocks, one at a time. A tail
    // handled by a separate code path from the 4-block body will be
    // wrong (or out of bounds) at exactly one of these, and a sparse
    // sweep can walk straight past it.
    TEST_SUITE("ghash — every length 0..64 (the 4-block reduction window)");
    for (size_t n = 0; n <= 64; n++) {
        struct ghash_case c = { 0, n, GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "ct %2zu bytes, no aad", n);
        bounds_case(label, probe_ghash, &c);
    }
}

static void test_ghash_aad(void)
{
    TEST_SUITE("ghash — AAD x ciphertext lengths");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths_short); i++) {
        for (size_t j = 0; j < BOUNDS_N(bounds_lengths_short); j++) {
            struct ghash_case c = {
                bounds_lengths_short[i], bounds_lengths_short[j], GUARD_OVERRUN
            };
            char label[96];
            snprintf(label, sizeof(label), "aad %3zu / ct %3zu",
                     bounds_lengths_short[i], bounds_lengths_short[j]);
            bounds_case(label, probe_ghash, &c);
        }
    }
}

// ── aes_gcm_encrypt / aes_gcm_decrypt ───────────────────────────────

struct gcm_case {
    size_t aad_len;
    size_t pt_len;
    enum guard_side side;
};

static void probe_gcm_seal(void *ctx)
{
    const struct gcm_case *c = (const struct gcm_case *)ctx;

    struct guarded_buffer key, iv, aad, pt, ct, tag;
    if (bounds_in(&key, 16, c->side, 0x3c) != 0 ||
        bounds_in(&iv, 12, c->side, 0x5e) != 0 ||
        bounds_in(&aad, c->aad_len, c->side, 0x24) != 0 ||
        bounds_in(&pt, c->pt_len, c->side, 0x68) != 0 ||
        bounds_out(&ct, c->pt_len, c->side) != 0 ||
        bounds_out(&tag, 16, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    aes_gcm_encrypt(key.data, iv.data, aad.data, c->aad_len,
                    pt.data, c->pt_len, ct.data, tag.data);

    static uint8_t want_ct[4096];
    uint8_t want_tag[16];
    if (c->pt_len > sizeof(want_ct))
        _exit(BOUNDS_BADSETUP);
    ref_gcm_encrypt(key.data, iv.data, aad.data, c->aad_len,
                    pt.data, c->pt_len, want_ct, want_tag);

    if (!bounds_eq(ct.data, want_ct, c->pt_len))
        _exit(BOUNDS_MISMATCH);
    if (!bounds_eq(tag.data, want_tag, 16))
        _exit(BOUNDS_MISMATCH);
    _exit(BOUNDS_PASS);
}

// Seal with the assembly, open with the assembly, and check the
// plaintext comes back — then flip one ciphertext bit and check it does
// not. A tag check that passes at some lengths and not others is a
// forgery oracle, so the tamper case is swept at the same boundaries as
// the clean one.
static void probe_gcm_open(void *ctx)
{
    const struct gcm_case *c = (const struct gcm_case *)ctx;

    struct guarded_buffer key, iv, aad, pt, ct, tag, out;
    if (bounds_in(&key, 16, c->side, 0x3c) != 0 ||
        bounds_in(&iv, 12, c->side, 0x5e) != 0 ||
        bounds_in(&aad, c->aad_len, c->side, 0x24) != 0 ||
        bounds_in(&pt, c->pt_len, c->side, 0x68) != 0 ||
        bounds_out(&ct, c->pt_len, c->side) != 0 ||
        bounds_out(&tag, 16, c->side) != 0 ||
        bounds_out(&out, c->pt_len, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    aes_gcm_encrypt(key.data, iv.data, aad.data, c->aad_len,
                    pt.data, c->pt_len, ct.data, tag.data);

    if (aes_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                        ct.data, c->pt_len, tag.data, out.data) != 1)
        _exit(BOUNDS_MISMATCH);            // a good tag must verify
    if (!bounds_eq(out.data, pt.data, c->pt_len))
        _exit(BOUNDS_MISMATCH);            // and give the plaintext back

    // the reference must also open what the assembly sealed
    static uint8_t ref_out[4096];
    if (c->pt_len > sizeof(ref_out))
        _exit(BOUNDS_BADSETUP);
    if (ref_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                        ct.data, c->pt_len, tag.data, ref_out) != 1)
        _exit(BOUNDS_MISMATCH);

    // tamper: flip the low bit of the last tag byte
    tag.data[15] ^= 0x01;
    if (aes_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                        ct.data, c->pt_len, tag.data, out.data) != 0)
        _exit(BOUNDS_MISMATCH);            // a bad tag must not verify
    tag.data[15] ^= 0x01;

    // tamper: flip a ciphertext bit (only meaningful when there is one)
    if (c->pt_len > 0) {
        ct.data[c->pt_len - 1] ^= 0x80;
        if (aes_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                            ct.data, c->pt_len, tag.data, out.data) != 0)
            _exit(BOUNDS_MISMATCH);
        ct.data[c->pt_len - 1] ^= 0x80;
    }

    // tamper: flip an AAD bit
    if (c->aad_len > 0) {
        aad.data[0] ^= 0x01;
        if (aes_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                            ct.data, c->pt_len, tag.data, out.data) != 0)
            _exit(BOUNDS_MISMATCH);
        aad.data[0] ^= 0x01;
    }

    _exit(BOUNDS_PASS);
}

static void test_gcm(void)
{
    TEST_SUITE("aes_gcm_encrypt — plaintext lengths vs the reference");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct gcm_case c = { 5, bounds_lengths[i], side };
            char label[96];
            snprintf(label, sizeof(label), "pt %4zu bytes, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_gcm_seal, &c);
        }
    }

    TEST_SUITE("aes_gcm_encrypt — every plaintext length 0..64");
    for (size_t n = 0; n <= 64; n++) {
        struct gcm_case c = { 5, n, GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "pt %2zu bytes", n);
        bounds_case(label, probe_gcm_seal, &c);
    }

    TEST_SUITE("aes_gcm_encrypt — AAD lengths");
    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        struct gcm_case c = { bounds_lengths[i], 48, GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "aad %4zu bytes", bounds_lengths[i]);
        bounds_case(label, probe_gcm_seal, &c);
    }

    TEST_SUITE("aes_gcm_decrypt — round trip and tamper rejection");
    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct gcm_case c = { 5, bounds_lengths[i], side };
            char label[96];
            snprintf(label, sizeof(label), "ct %4zu bytes, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_gcm_open, &c);
        }
    }

    TEST_SUITE("aes_gcm_decrypt — every ciphertext length 0..64");
    for (size_t n = 0; n <= 64; n++) {
        struct gcm_case c = { 5, n, GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "ct %2zu bytes", n);
        bounds_case(label, probe_gcm_open, &c);
    }
}

// ── the record-layer sizes ──────────────────────────────────────────
// TLS_MAX_PLAINTEXT is 16384 and the record layer adds one inner-type
// octet, so the largest single AEAD operation this server can perform
// is 16385 bytes of plaintext (defs.S, TLS_MAX_AEAD = 2^14 + 1 + 16).
// That is the "maximum supported" case for GCM, and it is the length a
// peer can actually reach from the network.

static void probe_gcm_record_max(void *ctx)
{
    const struct gcm_case *c = (const struct gcm_case *)ctx;

    struct guarded_buffer key, iv, aad, pt, ct, tag, out;
    if (bounds_in(&key, 16, c->side, 0x3c) != 0 ||
        bounds_in(&iv, 12, c->side, 0x5e) != 0 ||
        bounds_in(&aad, c->aad_len, c->side, 0x24) != 0 ||
        bounds_in(&pt, c->pt_len, c->side, 0x68) != 0 ||
        bounds_out(&ct, c->pt_len, c->side) != 0 ||
        bounds_out(&tag, 16, c->side) != 0 ||
        bounds_out(&out, c->pt_len, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    aes_gcm_encrypt(key.data, iv.data, aad.data, c->aad_len,
                    pt.data, c->pt_len, ct.data, tag.data);
    if (aes_gcm_decrypt(key.data, iv.data, aad.data, c->aad_len,
                        ct.data, c->pt_len, tag.data, out.data) != 1)
        _exit(BOUNDS_MISMATCH);
    if (!bounds_eq(out.data, pt.data, c->pt_len))
        _exit(BOUNDS_MISMATCH);

    // The bitwise reference over 16 KiB is slow but not prohibitive,
    // and this is the one length where being sure matters most.
    uint8_t want_tag[16];
    static uint8_t want_ct[16385];
    ref_gcm_encrypt(key.data, iv.data, aad.data, c->aad_len,
                    pt.data, c->pt_len, want_ct, want_tag);
    if (!bounds_eq(ct.data, want_ct, c->pt_len))
        _exit(BOUNDS_MISMATCH);
    if (!bounds_eq(tag.data, want_tag, 16))
        _exit(BOUNDS_MISMATCH);

    _exit(BOUNDS_PASS);
}

static void test_record_sizes(void)
{
    TEST_SUITE("aes_gcm — the record-layer maximum (TLS_MAX_PLAINTEXT)");

    static const size_t lens[] = { 16383, 16384, 16385 };
    for (size_t i = 0; i < BOUNDS_N(lens); i++) {
        struct gcm_case c = { 5, lens[i], GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "%zu-byte record, seal + open + verify",
                 lens[i]);
        bounds_case(label, probe_gcm_record_max, &c);
    }
}

int main(void)
{
    bounds_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  bounds: AES-128 / GHASH / AES-128-GCM    ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    ref_selfcheck_aes_gcm();

    test_fixed();
    test_ghash_lengths();
    test_ghash_aad();
    test_gcm();
    test_record_sizes();

    test_summary();
    return 0;
}
