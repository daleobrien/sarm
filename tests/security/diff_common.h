// sarm security tests — shared scaffolding for the differential suites
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/diff_common.h — random-vector differential
//   testing of the crypto assembly (docs/SECURITY.md, Step 4)
//
// Description: Step 3 asked "does it survive the edges, and does it
//   match at the edges we thought to name?" Step 4 asks the question
//   the named edges cannot: does it match *everywhere*? Every routine
//   is run against the independent C references (crypto_ref.h,
//   refbn.h) over thousands of random inputs at random lengths, and
//   the two answers must be identical byte for byte.
//
//   This is where a bug that lives at some length nobody wrote down
//   gets caught. A carry that only propagates when limb 2 is exactly
//   0xffffffffffffffff, a GHASH tail that mishandles 13 bytes but not
//   12 or 14, a key schedule whose round constant is wrong only in
//   round 9 — none of these are at a boundary anyone would list, and
//   all of them are found by enough random vectors.
//
// Reproducibility: every vector is derived from a single 64-bit seed,
//   so a failure is replayable rather than a ghost. The suite prints
//   its seed on every run and takes an override:
//
//     SARM_DIFF_SEED=0x1234 ./_obj/test_diff_gcm
//
//   Each routine gets its own stream, derived from (seed, routine
//   name, iteration), so adding a case to one routine does not shift
//   every other routine's vectors and turn one regression into a
//   hundred unrelated diffs.
//
//   Iteration counts scale with SARM_DIFF_ITERS (default 1):
//
//     SARM_DIFF_ITERS=100 make -C tests/security
//
//   The default is sized to keep `make test` quick; the multiplier is
//   what Step 14's continuous fuzzing turns up. Counts differ per
//   routine by design — the reference reduces modulo a 256-bit prime
//   one bit at a time, so field operations get thousands of vectors
//   and a full scalar multiplication gets a handful. The field
//   operations are where carry bugs live, so that is the right way
//   round.
//
// Not guarded: these suites do not use guard_pages.h. Step 3 already
//   proved each routine stays inside its declared buffers, one forked
//   probe per case; forking a million times to re-prove it would cost
//   the vector count that is the entire point of this step. What
//   remains here is a cheap standing check — every output buffer
//   carries a poison tail that must come back untouched — which
//   catches a gross overwrite without a syscall per vector.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_DIFF_COMMON_H
#define SARM_DIFF_COMMON_H

#include "crypto_ref.h"
#include "ref_selfcheck.h"
#include "refbn.h"
#include "../unit/test_harness.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Declared by hand rather than via <stdlib.h>, for the reason
// test_harness.h gives: that header declares atoi, which collides with
// the assembly symbol of the same name.
extern char *getenv(const char *name);

// ── the random stream ───────────────────────────────────────────────
// splitmix64 to spread a seed into state, xoshiro256** to generate.
// Both are small, well-mixed, and — the property that matters here —
// exactly reproducible from the seed on any machine, which is what
// makes a failed vector something you can put in a bug report.

struct diff_rng { uint64_t s[4]; };

static uint64_t diff_splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static void diff_rng_seed(struct diff_rng *r, uint64_t seed)
{
    uint64_t x = seed ? seed : 0x243f6a8885a308d3ull;
    for (int i = 0; i < 4; i++) r->s[i] = diff_splitmix64(&x);
}

static uint64_t diff_rng_u64(struct diff_rng *r)
{
    const uint64_t s1 = r->s[1];
    uint64_t result = s1 * 5;
    result = ((result << 7) | (result >> 57)) * 9;

    const uint64_t t = s1 << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= s1;
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = (r->s[3] << 45) | (r->s[3] >> 19);
    return result;
}

// Uniform enough for testing; the modulo bias at these bounds is far
// below anything that would change which code paths get exercised.
static uint64_t diff_rng_below(struct diff_rng *r, uint64_t bound)
{
    return bound ? diff_rng_u64(r) % bound : 0;
}

static void diff_rng_bytes(struct diff_rng *r, uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i + 8 <= n) {
        const uint64_t x = diff_rng_u64(r);
        for (int b = 0; b < 8; b++) p[i + (size_t)b] = (uint8_t)(x >> (8 * b));
        i += 8;
    }
    if (i < n) {
        uint64_t x = diff_rng_u64(r);
        while (i < n) { p[i++] = (uint8_t)x; x >>= 8; }
    }
}

// A length biased towards the small and the boundary-adjacent. Uniform
// lengths over a wide range would spend nearly every vector in the
// "many full blocks, short tail" case and almost none on the tails and
// the empty input, which is where the bugs are.
static size_t diff_rng_len(struct diff_rng *r, size_t max)
{
    if (max == 0) return 0;
    switch (diff_rng_u64(r) & 3u) {
    case 0:  return (size_t)diff_rng_below(r, max < 8 ? max + 1 : 9);
    case 1: {                       // straddling a 16- or 64-byte block
        const size_t blk = (diff_rng_u64(r) & 1u) ? 16u : 64u;
        const size_t mul = (size_t)diff_rng_below(r, (max / blk) + 1);
        const size_t off = (size_t)diff_rng_below(r, 3);   // -1, 0, +1
        size_t n = mul * blk + off;
        if (n > 0) n -= 1;
        return n > max ? max : n;
    }
    default: return (size_t)diff_rng_below(r, max + 1);
    }
}

// ── configuration ───────────────────────────────────────────────────

static uint64_t diff_parse_u64(const char *s, uint64_t fallback)
{
    if (!s || !*s) return fallback;
    uint64_t v = 0, base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
    if (!*s) return fallback;
    for (; *s; s++) {
        uint64_t d;
        if (*s >= '0' && *s <= '9')      d = (uint64_t)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') d = (uint64_t)(*s - 'a' + 10);
        else if (*s >= 'A' && *s <= 'F') d = (uint64_t)(*s - 'A' + 10);
        else return fallback;
        if (d >= base) return fallback;
        v = v * base + d;
    }
    return v;
}

static uint64_t diff_base_seed = 0;
static uint64_t diff_scale_factor = 1;

// Scale a routine's base iteration count by SARM_DIFF_ITERS.
static uint64_t diff_iters(uint64_t base)
{
    const uint64_t n = base * diff_scale_factor;
    return n ? n : 1;
}

static void diff_init(const char *suite)
{
    // A fixed default, not the clock: a suite that tests different
    // vectors on every run is a suite that fails on someone else's
    // machine and passes on yours. Sweeping the space is Step 14's
    // job, and it does it by varying the seed explicitly.
    diff_base_seed = diff_parse_u64(getenv("SARM_DIFF_SEED"),
                                    0x5341524d5f444946ull);  // "SARM_DIF"
    diff_scale_factor = diff_parse_u64(getenv("SARM_DIFF_ITERS"), 1);
    if (diff_scale_factor == 0) diff_scale_factor = 1;

    printf("\n%s: seed=0x%016llx iters=x%llu"
           "  (override with SARM_DIFF_SEED / SARM_DIFF_ITERS)\n",
           suite, (unsigned long long)diff_base_seed,
           (unsigned long long)diff_scale_factor);

    // test_harness.h arms alarm(5) at load time. The references here
    // are slow on purpose, so raise it — but keep it finite, because a
    // routine that never returns is exactly the sort of thing Step 3
    // found and this suite must not hang on.
    alarm(600);
}

// ── the sweep ───────────────────────────────────────────────────────
// One assertion per routine, not one per vector: five thousand passing
// lines say nothing that one line saying "5000 vectors, all matched"
// does not. A failure prints the seed and iteration that produced it,
// which is enough to replay that single vector on its own.

// Returns 1 if the assembly matched the reference. On a mismatch, fills
// `detail` with what differed.
typedef int (*diff_case_fn)(struct diff_rng *rng, char *detail, size_t len);

static uint64_t diff_label_hash(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (; *s; s++) {
        h ^= (uint64_t)(unsigned char)*s;
        h *= 0x100000001b3ull;
    }
    return h;
}

static void diff_sweep(const char *label, diff_case_fn fn, uint64_t base_iters)
{
    const uint64_t iters = diff_iters(base_iters);
    const uint64_t lh = diff_label_hash(label);

    char first_detail[512];
    first_detail[0] = '\0';
    uint64_t failures = 0, first_iter = 0, first_seed = 0;

    for (uint64_t i = 0; i < iters; i++) {
        // Per-(routine, iteration) seed. Independent streams mean
        // adding a vector to one routine does not renumber another's.
        uint64_t mix = diff_base_seed ^ lh ^ (i * 0x9e3779b97f4a7c15ull);
        const uint64_t seed = diff_splitmix64(&mix);

        struct diff_rng rng;
        diff_rng_seed(&rng, seed);

        char detail[512];
        detail[0] = '\0';
        if (!fn(&rng, detail, sizeof detail)) {
            if (failures == 0) {
                first_iter = i;
                first_seed = seed;
                for (size_t k = 0; k < sizeof first_detail; k++) {
                    first_detail[k] = detail[k];
                    if (!detail[k]) break;
                }
                first_detail[sizeof first_detail - 1] = '\0';
            }
            failures++;
        }
    }

    if (failures == 0) {
        char msg[256];
        snprintf(msg, sizeof msg, "%s — %llu random vectors matched",
                 label, (unsigned long long)iters);
        _PASS(msg);
        return;
    }

    _FAIL("%s — %llu of %llu random vectors DIFFER from the reference;\n"
          "      first at iteration %llu (vector seed 0x%016llx): %s\n"
          "      replay: SARM_DIFF_SEED=0x%016llx",
          label, (unsigned long long)failures, (unsigned long long)iters,
          (unsigned long long)first_iter, (unsigned long long)first_seed,
          first_detail, (unsigned long long)diff_base_seed);
}

// ── comparison helpers ──────────────────────────────────────────────

static int diff_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    int d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

// Index of the first differing byte, or -1.
static long diff_first_delta(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) return (long)i;
    return -1;
}

static void diff_hex(char *out, size_t outlen, const uint8_t *p, size_t n)
{
    static const char h[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 3 < outlen; i++) {
        out[o++] = h[p[i] >> 4];
        out[o++] = h[p[i] & 15];
    }
    if (o < outlen) out[o] = '\0';
    else if (outlen) out[outlen - 1] = '\0';
}

// Standard mismatch message: where it diverged, and both values there.
static void diff_report(char *detail, size_t len, const char *what,
                        size_t inlen, const uint8_t *got, const uint8_t *want,
                        size_t n)
{
    const long at = diff_first_delta(got, want, n);
    char g[64], w[64];
    const size_t show = n > 16 ? 16 : n;
    diff_hex(g, sizeof g, got, show);
    diff_hex(w, sizeof w, want, show);
    snprintf(detail, len,
             "%s, input length %llu: first difference at byte %ld; "
             "got %s… want %s…",
             what, (unsigned long long)inlen, at, g, w);
}

// ── poison tails ────────────────────────────────────────────────────
// Not a guard page (see the header comment) — just a cheap standing
// check that a routine wrote where it said it would.

#define DIFF_TAIL 32

static void diff_poison(uint8_t *buf, size_t total)
{
    for (size_t i = 0; i < total; i++) buf[i] = 0x5A;
}

static int diff_tail_intact(const uint8_t *buf, size_t used)
{
    for (size_t i = 0; i < DIFF_TAIL; i++)
        if (buf[used + i] != 0x5A) return 0;
    return 1;
}

// Declare an output buffer of `n` usable bytes followed by a poison
// tail, poisoned in full.
#define DIFF_OUT(name, n) \
    uint8_t name[(n) + DIFF_TAIL]; diff_poison(name, (n) + DIFF_TAIL)

// Check the tail and, if it was clobbered, say so.
#define DIFF_CHECK_TAIL(name, n, what, detail, len) \
    do { \
        if (!diff_tail_intact((name), (n))) { \
            snprintf((detail), (len), \
                     "%s wrote past the end of its %llu-byte output buffer", \
                     (what), (unsigned long long)(size_t)(n)); \
            return 0; \
        } \
    } while (0)

#endif // SARM_DIFF_COMMON_H
