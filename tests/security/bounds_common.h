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
#include "ref_selfcheck.h"
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

#endif // SARM_BOUNDS_COMMON_H
