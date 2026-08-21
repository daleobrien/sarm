// sarm security tests — SHA-256 and the CSPRNG at their length boundaries
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// docs/SECURITY.md, Step 3: every assembly routine, at 0, 1, block-1,
// block, block+1, large and maximum-supported lengths — no crash, and
// reference output matches.
//
// Routines covered here:
//   sha256(state, data, nblocks)      src/crypto/sha256/compress.S
//   sha256_init/update/final(ctx,..)  src/crypto/sha256/{init,update,final}.S
//   crypto_random_bytes(buf, len)     src/crypto/random.S
//
// The block size is 64 bytes and the streaming context buffers a
// partial block, so the interesting lengths are the ones either side of
// every multiple of 64 — and, for update, the ones either side of a
// buffer boundary reached in two calls rather than one.

#include "bounds_common.h"

// The assembly labels carry no leading underscore, so a plain extern
// (which Mach-O would mangle to _sha256) could not name them — hence
// the explicit __asm__ names, the same convention tests/unit uses.
extern void sha256(uint32_t state[8], const void *data, uint64_t nblocks)
    __asm__("sha256");
extern void sha256_init(void *ctx) __asm__("sha256_init");
extern void sha256_update(void *ctx, const void *data, uint64_t len)
    __asm__("sha256_update");
extern void sha256_final(void *ctx, void *digest) __asm__("sha256_final");
extern uint64_t crypto_random_bytes(void *buf, uint64_t len)
    __asm__("crypto_random_bytes");

#define SHA256_CTX_BYTES 112   // SHA256_CTX_SIZE, defs.S

// ── sha256: the raw block function ──────────────────────────────────

struct compress_case {
    size_t nblocks;
    enum guard_side side;
};

static void probe_compress(void *ctx)
{
    const struct compress_case *c = (const struct compress_case *)ctx;

    struct guarded_buffer in, state;
    if (bounds_in(&in, c->nblocks * 64, c->side, 0x11) != 0 ||
        bounds_out(&state, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    // the state is an input too — seed both copies identically
    uint32_t want[8];
    for (int i = 0; i < 8; i++)
        want[i] = REF_SHA256_IV[i];
    for (int i = 0; i < 8; i++)
        ((uint32_t *)state.data)[i] = REF_SHA256_IV[i];

    sha256((uint32_t *)state.data, in.data, c->nblocks);

    for (size_t b = 0; b < c->nblocks; b++)
        ref_sha256_compress(want, in.data + 64 * b);

    const int ok = bounds_eq((const uint8_t *)state.data,
                             (const uint8_t *)want, 32);
    _exit(ok ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_compress(void)
{
    TEST_SUITE("sha256 — block counts (compress.S)");

    // 0 blocks is documented as a no-op that returns early; 1024 blocks
    // (64 KiB) is the large case. Everything between brackets the
    // 4-block-at-a-time structure the ARMv8 SHA extension encourages.
    static const size_t block_counts[] = {
        0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 255, 1024
    };

    for (size_t i = 0; i < BOUNDS_N(block_counts); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct compress_case c = { block_counts[i], side };
            char label[96];
            snprintf(label, sizeof(label), "%4zu block(s), %s",
                     block_counts[i], bounds_side_name(side));
            bounds_case(label, probe_compress, &c);
        }
    }
}

// ── sha256_init / update / final: the streaming API ─────────────────

struct stream_case {
    size_t len;
    size_t split;          // 0 = one update call, else two
    enum guard_side side;
};

static void probe_stream(void *ctx)
{
    const struct stream_case *c = (const struct stream_case *)ctx;

    struct guarded_buffer in, sctx, digest;
    if (bounds_in(&in, c->len, c->side, 0x33) != 0 ||
        bounds_out(&sctx, SHA256_CTX_BYTES, c->side) != 0 ||
        bounds_out(&digest, 32, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    sha256_init(sctx.data);
    if (c->split == 0) {
        sha256_update(sctx.data, in.data, c->len);
    } else {
        sha256_update(sctx.data, in.data, c->split);
        sha256_update(sctx.data, in.data + c->split, c->len - c->split);
    }
    sha256_final(sctx.data, digest.data);

    uint8_t want[32];
    ref_sha256(in.data, c->len, want);

    _exit(bounds_eq(digest.data, want, 32) ? BOUNDS_PASS : BOUNDS_MISMATCH);
}

static void test_stream(void)
{
    TEST_SUITE("sha256_init/update/final — message lengths");

    for (size_t i = 0; i < BOUNDS_N(bounds_lengths); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct stream_case c = { bounds_lengths[i], 0, side };
            char label[96];
            snprintf(label, sizeof(label), "%4zu byte message, %s",
                     bounds_lengths[i], bounds_side_name(side));
            bounds_case(label, probe_stream, &c);
        }
    }

    // The maximum this suite's reference can pad (65536 bytes) stands in
    // for "large": the assembly's own limit is 2^61 bytes, which no test
    // can reach. What matters here is that a length far past any
    // internal buffer still lands on the same digest.
    {
        struct stream_case c = { REF_SHA256_MAX_MSG, 0, GUARD_OVERRUN };
        bounds_case("65536 byte message (large), overrun-guarded",
                    probe_stream, &c);
    }
}

static void test_stream_splits(void)
{
    TEST_SUITE("sha256_update — split across two calls at block edges");

    // The bug this is shaped to find: an update that flushes the
    // context's partial-block buffer differently depending on where the
    // caller's chunk boundary falls. Same message, same digest, no
    // matter how it is fed.
    static const size_t splits[][2] = {
        { 64, 1 }, { 64, 32 }, { 64, 63 },
        { 65, 1 }, { 65, 64 },
        { 128, 63 }, { 128, 64 }, { 128, 65 },
        { 129, 1 }, { 129, 128 },
        { 200, 100 }, { 256, 255 },
    };

    for (size_t i = 0; i < BOUNDS_N(splits); i++) {
        struct stream_case c = { splits[i][0], splits[i][1], GUARD_OVERRUN };
        char label[96];
        snprintf(label, sizeof(label), "%4zu bytes fed as %zu + %zu",
                 splits[i][0], splits[i][1], splits[i][0] - splits[i][1]);
        bounds_case(label, probe_stream, &c);
    }
}

// ── crypto_random_bytes ─────────────────────────────────────────────
// No reference output is possible — the whole point is that it is
// unpredictable. What Step 3 can check is the bound: getentropy caps a
// call at 256 bytes and the assembly loops to cover more, so 255/256/257
// are exactly where a loop that writes one chunk too many would show up.

struct rng_case {
    size_t len;
    enum guard_side side;
};

static void probe_rng(void *ctx)
{
    const struct rng_case *c = (const struct rng_case *)ctx;

    struct guarded_buffer out;
    if (bounds_out(&out, c->len, c->side) != 0)
        _exit(BOUNDS_BADSETUP);

    if (crypto_random_bytes(out.data, c->len) != 0)
        _exit(BOUNDS_MISMATCH);   // fail-closed: a failure is reported,
                                  // never silently substituted

    // A filled buffer must not still be poison. One byte could legally
    // be 0xA5; a whole buffer of it means nothing was written.
    if (c->len >= 8) {
        int all_poison = 1;
        for (size_t i = 0; i < c->len; i++)
            if (out.data[i] != 0xA5) { all_poison = 0; break; }
        if (all_poison)
            _exit(BOUNDS_MISMATCH);
    }
    _exit(BOUNDS_PASS);
}

static void test_rng(void)
{
    TEST_SUITE("crypto_random_bytes — fill lengths (256-byte chunk limit)");

    static const size_t lens[] = {
        0, 1, 15, 16, 31, 32, 33, 63, 64, 255, 256, 257, 511, 512, 513, 4096
    };

    for (size_t i = 0; i < BOUNDS_N(lens); i++) {
        for (int s = 0; s < 2; s++) {
            const enum guard_side side = s ? GUARD_UNDERRUN : GUARD_OVERRUN;
            struct rng_case c = { lens[i], side };
            char label[96];
            snprintf(label, sizeof(label), "%4zu bytes, %s",
                     lens[i], bounds_side_name(side));
            bounds_case(label, probe_rng, &c);
        }
    }
}

int main(void)
{
    bounds_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  bounds: SHA-256 + CSPRNG                 ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    ref_selfcheck_sha256();
    test_compress();
    test_stream();
    test_stream_splits();
    test_rng();

    test_summary();
    return 0;
}
