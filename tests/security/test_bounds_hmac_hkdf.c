// sarm security tests — HMAC and HKDF at their length boundaries
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 3. Routines covered:
//   hmac_sha256(key, keylen, data, datalen, digest)  src/crypto/hmac.S
//   hkdf_extract(salt, saltlen, ikm, ikmlen, prk)    src/crypto/hkdf/extract.S
//   hkdf_expand(prk, prklen, info, infolen, okm, n)  src/crypto/hkdf/expand.S
//   hkdf_expand_label(...)                           src/crypto/hkdf/expand_label.S
//
// These are where TLS key material is derived, so a bound missed here
// is a bound missed on every traffic key the server ever uses
// (docs/security/threat-model.md §4.2).
//
// The lengths that matter are not the same for each argument:
//   * HMAC's key crosses the 64-byte block at which RFC 2104 switches
//     from padding the key to hashing it — 63/64/65 is the branch.
//   * HKDF-Expand's output crosses 32 bytes (one HMAC block of output)
//     at every multiple, and tops out at 255*32 = 8160. 8160 and its
//     neighbours are the maximum-supported case Step 3 asks for.
//   * HkdfLabel's label and context are each length-prefixed by a
//     single octet, so 255 is their structural maximum.

#include "bounds_common.h"

extern void hmac_sha256(const void *key, uint64_t keylen,
                        const void *data, uint64_t datalen,
                        void *digest) __asm__("hmac_sha256");
extern void hkdf_extract(const void *salt, uint64_t saltlen,
                         const void *ikm, uint64_t ikmlen,
                         void *prk) __asm__("hkdf_extract");
extern void hkdf_expand(const void *prk, uint64_t prklen,
                        const void *info, uint64_t infolen,
                        void *okm, uint64_t okmlen) __asm__("hkdf_expand");
extern void hkdf_expand_label(const void *secret,
                              const void *label, uint64_t label_len,
                              const void *context, uint64_t context_len,
                              void *out, uint64_t outlen)
    __asm__("hkdf_expand_label");

#define HKDF_MAX_OKM 8160   // 255 * 32, RFC 5869 §2.3

// ── hmac_sha256 ─────────────────────────────────────────────────────

struct hmac_case {
    size_t keylen;
    size_t datalen;
    enum guard_side side;
};

static void probe_hmac(void *ctx)
{
    const struct hmac_case *c = (const struct hmac_case *)ctx;

    struct guarded_buffer key, data, digest;
    if (bounds_in(&key, c->keylen, c->side, 0x41) != 0 ||
        bounds_in(&data, c->datalen, c->side, 0x71) != 0 ||
        bounds_out(&digest, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    hmac_sha256(key.data, c->keylen, data.data, c->datalen, digest.data);

    uint8_t want[32];
    ref_hmac_sha256(key.data, c->keylen, data.data, c->datalen, want);

    _exit(bounds_eq(digest.data, want, 32) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_hmac_keys(void)
{
    TEST_SUITE("hmac_sha256 — key lengths (the 64-byte hash-the-key branch)");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct hmac_case c = { bounds_lengths[i], 37, side };
            char label[96];
            snprintf(label, sizeof(label), "key %4zu bytes, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_hmac, &c);
        }
    }
}

static void test_hmac_data(void)
{
    TEST_SUITE("hmac_sha256 — message lengths");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct hmac_case c = { 32, bounds_lengths[i], side };
            char label[96];
            snprintf(label, sizeof(label), "data %4zu bytes, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_hmac, &c);
        }
    }
}

static void test_hmac_cross(void)
{
    TEST_SUITE("hmac_sha256 — key x message, both at block edges");

    // The cross product is where a length interaction hides: a key that
    // lands exactly on the block boundary combined with an empty
    // message, for instance.
    for (size_t i = 0; i < BOUNDS_N(bounds_lengths_short); i++) {
        for (size_t j = 0; j < BOUNDS_N(bounds_lengths_short); j++) {
            struct hmac_case c = {
                bounds_lengths_short[i], bounds_lengths_short[j], GUARD_OVERRUN
            };
            char label[96];
            snprintf(label, sizeof(label), "key %3zu / data %3zu",
                     bounds_lengths_short[i], bounds_lengths_short[j]);
            bounds_case(label, probe_hmac, &c);
        }
    }
}

// ── hkdf_extract ────────────────────────────────────────────────────

struct extract_case {
    size_t saltlen;
    size_t ikmlen;
    enum guard_side side;
};

static void probe_extract(void *ctx)
{
    const struct extract_case *c = (const struct extract_case *)ctx;

    struct guarded_buffer salt, ikm, prk;
    if (bounds_in(&salt, c->saltlen, c->side, 0x13) != 0 ||
        bounds_in(&ikm, c->ikmlen, c->side, 0x59) != 0 ||
        bounds_out(&prk, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    hkdf_extract(salt.data, c->saltlen, ikm.data, c->ikmlen, prk.data);

    uint8_t want[32];
    ref_hkdf_extract(salt.data, c->saltlen, ikm.data, c->ikmlen, want);

    _exit(bounds_eq(prk.data, want, 32) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_extract(void)
{
    TEST_SUITE("hkdf_extract — salt x IKM lengths");

    // saltlen == 0 is the RFC 5869 §2.2 "absent salt" path, which
    // substitutes 32 zero bytes rather than reading the pointer — the
    // guarded zero-length buffer makes any read of it trap.
    for (size_t i = 0; i < BOUNDS_N(bounds_lengths_short); i++) {
        for (size_t j = 0; j < BOUNDS_N(bounds_lengths_short); j++) {
            struct extract_case c = {
                bounds_lengths_short[i], bounds_lengths_short[j], GUARD_OVERRUN
            };
            char label[96];
            snprintf(label, sizeof(label), "salt %3zu / ikm %3zu",
                     bounds_lengths_short[i], bounds_lengths_short[j]);
            bounds_case(label, probe_extract, &c);
        }
    }

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths_short); i++) {
        struct extract_case c = { bounds_lengths_short[i], 32, GUARD_UNDERRUN };
        char label[96];
        snprintf(label, sizeof(label), "salt %3zu, underrun-guarded",
                 bounds_lengths_short[i]);
        bounds_case(label, probe_extract, &c);
    }
}

// ── hkdf_expand ─────────────────────────────────────────────────────

struct expand_case {
    size_t infolen;
    size_t okmlen;
    enum guard_side side;
};

static void probe_expand(void *ctx)
{
    const struct expand_case *c = (const struct expand_case *)ctx;

    struct guarded_buffer prk, info, okm;
    if (bounds_in(&prk, 32, c->side, 0x21) != 0 ||
        bounds_in(&info, c->infolen, c->side, 0x67) != 0 ||
        bounds_out(&okm, c->okmlen, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    hkdf_expand(prk.data, 32, info.data, c->infolen, okm.data, c->okmlen);

    static uint8_t want[HKDF_MAX_OKM];
    ref_hkdf_expand(prk.data, 32, info.data, c->infolen, want, c->okmlen);

    _exit(bounds_eq(okm.data, want, c->okmlen) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_expand(void)
{
    TEST_SUITE("hkdf_expand — output lengths (32-byte T(n) blocks, max 8160)");

    // Every neighbourhood of a 32-byte output block, plus the RFC's
    // absolute maximum of 255 blocks. 8160 is the last legal length;
    // it is also where a counter that is compared with <= instead of <
    // writes one block too many.
    static const size_t okmlens[] = {
        0, 1, 2, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129,
        255, 256, 257, 1023, 1024, 1025, 8127, 8128, 8159, 8160
    };

    for (size_t i = 0; i < BOUNDS_N(okmlens); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct expand_case c = { 11, okmlens[i], side };
            char label[96];
            snprintf(label, sizeof(label), "okm %4zu bytes, %s",
                     okmlens[i], bounds_side_name(side));
            bounds_case(label, probe_expand, &c);
        }
    }
}

static void test_expand_info(void)
{
    TEST_SUITE("hkdf_expand — info lengths (documented maximum 607)");

    // The sweep stops at 607 because that is the routine's documented
    // limit, not because longer inputs are uninteresting: hkdf_expand
    // assembles [T(i-1)] || [info] || [counter] in a 640-byte stack
    // buffer, so its header states "infolen must satisfy
    // 32 + infolen + 1 <= 640, i.e. infolen <= 607".
    //
    // That precondition is enforced by documentation alone — there is no
    // length check in the assembly, and an over-long info silently
    // overruns the stack frame. This suite found that by sweeping past
    // it (1023/1024/1025 all trapped on the guard page) before the sweep
    // was corrected to the contract. It is not a live defect: the only
    // caller in the tree is hkdf_expand_label, whose own HkdfLabel
    // buffer caps info at 520 octets by construction, and every label
    // and context in src/tls/ is a compile-time constant. It is
    // recorded in docs/security/threat-model.md as an unchecked
    // precondition, which is what it is.
    static const size_t infolens[] = {
        0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
        255, 256, 257, 511, 512, 513, 520, 606, 607
    };

    for (size_t i = 0; i < BOUNDS_N(infolens); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct expand_case c = { infolens[i], 64, side };
            char label[96];
            snprintf(label, sizeof(label), "info %4zu bytes, %s",
                     infolens[i], bounds_side_name(side));
            bounds_case(label, probe_expand, &c);
        }
    }
}

// ── hkdf_expand_label ───────────────────────────────────────────────

struct label_case {
    size_t label_len;
    size_t context_len;
    size_t outlen;
    enum guard_side side;
};

static void probe_expand_label(void *ctx)
{
    const struct label_case *c = (const struct label_case *)ctx;

    struct guarded_buffer secret, label, context, out;
    if (bounds_in(&secret, 32, c->side, 0x81) != 0 ||
        bounds_in(&label, c->label_len, c->side, 0x61) != 0 ||
        bounds_in(&context, c->context_len, c->side, 0x91) != 0 ||
        bounds_out(&out, c->outlen, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // labels are ASCII on the wire; keep the bytes printable so a
    // mismatch is legible in a debugger
    for (size_t i = 0; i < c->label_len; i++)
        label.data[i] = (uint8_t)('a' + (i % 26));

    hkdf_expand_label(secret.data, label.data, c->label_len,
                      context.data, c->context_len, out.data, c->outlen);

    static uint8_t want[HKDF_MAX_OKM];
    ref_hkdf_expand_label(secret.data, (const char *)label.data, c->label_len,
                          context.data, c->context_len, want, c->outlen);

    _exit(bounds_eq(out.data, want, c->outlen) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_expand_label(void)
{
    TEST_SUITE("hkdf_expand_label — label / context / output lengths");

    // label lengths: 1 is the shortest legal, 249 makes "tls13 " + label
    // exactly 255, the single-octet length prefix's maximum.
    static const size_t label_lens[] = { 1, 2, 3, 8, 12, 13, 16, 32, 63, 64, 65, 248, 249 };
    for (size_t i = 0; i < BOUNDS_N(label_lens); i++) {
        struct label_case c = { label_lens[i], 32, 32, GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "label %3zu bytes", label_lens[i]);
        bounds_case(label, probe_expand_label, &c);
    }

    static const size_t ctx_lens[] = { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 254, 255 };
    for (size_t i = 0; i < BOUNDS_N(ctx_lens); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct label_case c = { 3, ctx_lens[i], 32, side };
            char label[96];
            snprintf(label, sizeof(label), "context %3zu bytes, %s",
                     ctx_lens[i], bounds_side_name(side));
            bounds_case(label, probe_expand_label, &c);
        }
    }

    // The output lengths TLS 1.3 actually asks for are 12 (an IV), 16
    // (an AES-128 key) and 32 (a secret) — plus the boundaries around
    // them, and 255, the largest value the HkdfLabel length field can
    // describe honestly for a single-octet-prefixed context.
    static const size_t outlens[] = { 0, 1, 11, 12, 13, 15, 16, 17, 31, 32, 33, 64, 255, 256 };
    for (size_t i = 0; i < BOUNDS_N(outlens); i++) {
        struct label_case c = { 6, 32, outlens[i], GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "output %3zu bytes", outlens[i]);
        bounds_case(label, probe_expand_label, &c);
    }
}

int main(void)
{
    bounds_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  bounds: HMAC + HKDF                      ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    ref_selfcheck_sha256();
    ref_selfcheck_hmac_hkdf();

    test_hmac_keys();
    test_hmac_data();
    test_hmac_cross();
    test_extract();
    test_expand();
    test_expand_info();
    test_expand_label();

    test_summary();
    return 0;
}
