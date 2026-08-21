// sarm security tests — SHA-256, HMAC and HKDF against a reference,
// over random vectors
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 4. Routines covered:
//   sha256(state, data, nblocks)          src/crypto/sha256/compress.S
//   sha256_init/update/final              src/crypto/sha256/{init,update,final}.S
//   hmac_sha256(...)                      src/crypto/sha256/hmac.S
//   hkdf_extract/expand/expand_label      src/crypto/hkdf/*.S
//
// This is the hash chain the whole handshake rests on: the transcript,
// every traffic secret, the ECDSA message hash, the HMAC in extract.
// A single wrong bit anywhere in it is a handshake that fails against
// every real client, or — far worse — one that succeeds against a
// peer computing the same wrong thing.
//
// The streaming sweep is the one that earns its place here. init /
// update / final buffers a partial block across calls, and the split
// points a real connection produces are whatever the network happened
// to deliver: a record boundary, a partial read, a 3-byte fragment.
// Random splits over random lengths exercise the buffering path in
// combinations no hand-written list would reach, and every one of them
// must equal the one-shot hash of the same bytes.

#include "diff_common.h"

extern void sha256(uint32_t state[8], const void *data, uint64_t nblocks)
    __asm__("sha256");
extern void sha256_init(void *ctx) __asm__("sha256_init");
extern void sha256_update(void *ctx, const void *data, uint64_t len)
    __asm__("sha256_update");
extern void sha256_final(void *ctx, void *digest) __asm__("sha256_final");
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

#define SHA256_CTX_BYTES 112   // SHA256_CTX_SIZE, defs.S
#define MAX_MSG          4096

// ── the raw compression function ────────────────────────────────────
// Random *state* as well as random blocks: the compression function is
// pure, so feeding it a chaining value that never occurs in a real
// hash is a legitimate and much wider test than always starting from
// the IV. A round constant that is wrong in round 57 shows up here
// long before it shows up in a digest.

static int case_compress(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t nblocks = 1 + (size_t)diff_rng_below(rng, 8);
    uint8_t data[8 * 64];
    diff_rng_bytes(rng, data, nblocks * 64);

    uint32_t st_asm[8], st_ref[8];
    for (int i = 0; i < 8; i++) {
        st_asm[i] = (uint32_t)diff_rng_u64(rng);
        st_ref[i] = st_asm[i];
    }

    sha256(st_asm, data, nblocks);
    for (size_t b = 0; b < nblocks; b++)
        ref_sha256_compress(st_ref, data + b * 64);

    if (!diff_eq((const uint8_t *)st_asm, (const uint8_t *)st_ref, 32)) {
        diff_report(detail, len, "sha256 compress", nblocks * 64,
                    (const uint8_t *)st_asm, (const uint8_t *)st_ref, 32);
        return 0;
    }
    return 1;
}

// ── the one-shot digest ─────────────────────────────────────────────

static int case_digest(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t n = diff_rng_len(rng, MAX_MSG);
    uint8_t msg[MAX_MSG];
    diff_rng_bytes(rng, msg, n);

    DIFF_OUT(got, 32);
    uint8_t want[32];

    uint8_t ctx[SHA256_CTX_BYTES];
    sha256_init(ctx);
    sha256_update(ctx, msg, n);
    sha256_final(ctx, got);
    DIFF_CHECK_TAIL(got, 32, "sha256_final", detail, len);

    ref_sha256(msg, n, want);
    if (!diff_eq(got, want, 32)) {
        diff_report(detail, len, "sha256 digest", n, got, want, 32);
        return 0;
    }
    return 1;
}

// ── the streaming path ──────────────────────────────────────────────
// The same bytes, delivered in pieces the way a socket delivers them.

static int case_streaming(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t n = diff_rng_len(rng, MAX_MSG);
    uint8_t msg[MAX_MSG];
    diff_rng_bytes(rng, msg, n);

    uint8_t ctx[SHA256_CTX_BYTES];
    sha256_init(ctx);

    // Up to 12 chunks, each a random slice of what is left — including
    // zero-length chunks, which a partial read really does produce and
    // which must not disturb the buffered remainder.
    size_t off = 0;
    unsigned chunks = 0;
    const unsigned max_chunks = 12;
    while (off < n && chunks < max_chunks - 1) {
        const size_t take = (size_t)diff_rng_below(rng, (n - off) + 1);
        sha256_update(ctx, msg + off, take);
        off += take;
        chunks++;
    }
    sha256_update(ctx, msg + off, n - off);

    DIFF_OUT(got, 32);
    uint8_t want[32];
    sha256_final(ctx, got);
    DIFF_CHECK_TAIL(got, 32, "sha256_final", detail, len);

    ref_sha256(msg, n, want);
    if (!diff_eq(got, want, 32)) {
        snprintf(detail, len,
                 "streaming digest of %llu bytes in %u chunks differs from "
                 "the one-shot reference",
                 (unsigned long long)n, chunks + 1);
        return 0;
    }
    return 1;
}

// ── HMAC ────────────────────────────────────────────────────────────
// Key lengths straddle the 64-byte block on purpose: at 65 bytes the
// key is hashed first, and that branch is a favourite home for
// off-by-ones.

static int case_hmac(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t klen = diff_rng_len(rng, 200);
    const size_t dlen = diff_rng_len(rng, 2048);
    uint8_t key[200], data[2048];
    diff_rng_bytes(rng, key, klen);
    diff_rng_bytes(rng, data, dlen);

    DIFF_OUT(got, 32);
    uint8_t want[32];

    hmac_sha256(key, klen, data, dlen, got);
    DIFF_CHECK_TAIL(got, 32, "hmac_sha256", detail, len);

    ref_hmac_sha256(key, klen, data, dlen, want);
    if (!diff_eq(got, want, 32)) {
        char msg[64];
        snprintf(msg, sizeof msg, "hmac (key %llu)",
                 (unsigned long long)klen);
        diff_report(detail, len, msg, dlen, got, want, 32);
        return 0;
    }
    return 1;
}

// ── HKDF ────────────────────────────────────────────────────────────

static int case_hkdf_extract(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t slen = diff_rng_len(rng, 128);
    const size_t ilen = diff_rng_len(rng, 256);
    uint8_t salt[128], ikm[256];
    diff_rng_bytes(rng, salt, slen);
    diff_rng_bytes(rng, ikm, ilen);

    DIFF_OUT(got, 32);
    uint8_t want[32];

    hkdf_extract(salt, slen, ikm, ilen, got);
    DIFF_CHECK_TAIL(got, 32, "hkdf_extract", detail, len);

    ref_hkdf_extract(salt, slen, ikm, ilen, want);
    if (!diff_eq(got, want, 32)) {
        char msg[64];
        snprintf(msg, sizeof msg, "hkdf_extract (salt %llu)",
                 (unsigned long long)slen);
        diff_report(detail, len, msg, ilen, got, want, 32);
        return 0;
    }
    return 1;
}

// okm lengths cross the 32-byte T(i) boundary repeatedly; infolen stays
// within the 607 the routine's header declares (see
// docs/security/threat-model.md §9, where the missing check on that
// bound is recorded for Step 5).
#define MAX_INFO 607
#define MAX_OKM  1024

static int case_hkdf_expand(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t prklen = 32;
    const size_t ilen = diff_rng_len(rng, MAX_INFO);
    const size_t olen = 1 + (size_t)diff_rng_below(rng, MAX_OKM);

    uint8_t prk[32], info[MAX_INFO];
    diff_rng_bytes(rng, prk, prklen);
    diff_rng_bytes(rng, info, ilen);

    DIFF_OUT(got, MAX_OKM);
    uint8_t want[MAX_OKM];

    hkdf_expand(prk, prklen, info, ilen, got, olen);
    DIFF_CHECK_TAIL(got, MAX_OKM, "hkdf_expand", detail, len);

    ref_hkdf_expand(prk, prklen, info, ilen, want, olen);
    if (!diff_eq(got, want, olen)) {
        char msg[64];
        snprintf(msg, sizeof msg, "hkdf_expand (info %llu, okm %llu)",
                 (unsigned long long)ilen, (unsigned long long)olen);
        diff_report(detail, len, msg, ilen, got, want, olen);
        return 0;
    }
    return 1;
}

// The TLS 1.3 wrapper: HkdfLabel is a length-prefixed structure, so
// this sweep is as much about the encoding as about the KDF.
#define MAX_LABEL   249
#define MAX_CONTEXT 255
#define MAX_LOUT    512

static int case_expand_label(struct diff_rng *rng, char *detail, size_t len)
{
    const size_t llen = diff_rng_len(rng, MAX_LABEL);
    const size_t clen = diff_rng_len(rng, MAX_CONTEXT);
    const size_t olen = 1 + (size_t)diff_rng_below(rng, MAX_LOUT);

    uint8_t secret[32], context[MAX_CONTEXT];
    char label[MAX_LABEL];
    diff_rng_bytes(rng, secret, 32);
    diff_rng_bytes(rng, (uint8_t *)label, llen);
    diff_rng_bytes(rng, context, clen);

    DIFF_OUT(got, MAX_LOUT);
    uint8_t want[MAX_LOUT];

    hkdf_expand_label(secret, label, llen, context, clen, got, olen);
    DIFF_CHECK_TAIL(got, MAX_LOUT, "hkdf_expand_label", detail, len);

    ref_hkdf_expand_label(secret, label, llen, context, clen, want, olen);
    if (!diff_eq(got, want, olen)) {
        char msg[80];
        snprintf(msg, sizeof msg,
                 "hkdf_expand_label (label %llu, context %llu, out %llu)",
                 (unsigned long long)llen, (unsigned long long)clen,
                 (unsigned long long)olen);
        diff_report(detail, len, msg, llen, got, want, olen);
        return 0;
    }
    return 1;
}

int main(void)
{
    diff_init("differential: SHA-256 / HMAC / HKDF");

    // The reference is pinned to published vectors before it is used to
    // judge anything — see bounds_common.h for why that ordering
    // matters. Duplicated here rather than shared so each suite is
    // self-contained when run on its own.
    ref_selfcheck_sha256();
    ref_selfcheck_hmac_hkdf();

    TEST_SUITE("differential — SHA-256");
    diff_sweep("sha256 compression function", case_compress, 40000);
    diff_sweep("sha256 one-shot digest", case_digest, 12000);
    diff_sweep("sha256 streaming vs one-shot", case_streaming, 12000);

    TEST_SUITE("differential — HMAC-SHA256");
    diff_sweep("hmac_sha256", case_hmac, 12000);

    TEST_SUITE("differential — HKDF");
    diff_sweep("hkdf_extract", case_hkdf_extract, 12000);
    diff_sweep("hkdf_expand", case_hkdf_expand, 3000);
    diff_sweep("hkdf_expand_label", case_expand_label, 4000);

    test_summary();
    return 0;
}
