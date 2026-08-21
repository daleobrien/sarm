// sarm security tests — shared scaffolding for the integer-overflow suites
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/overflow_common.h — the pattern every
//   test_overflow_*.c suite follows (docs/SECURITY.md, Step 5)
//
// Description: Step 5 asks for one thing that Steps 3 and 4 do not:
//
//     "Every security-sensitive length calculation should have a test
//      specifically targeting integer wraparound."
//     "Test: integer-overflow corpus is rejected."
//
//   Rejected, note — not merely survived. A parser that reads past a
//   buffer and then notices is a parser that has already read past the
//   buffer, and on a server whose static buffers sit next to the
//   private scalar (threat-model.md §9.3) the read is the vulnerability
//   even when the answer is thrown away. So every case here asserts
//   two things at once:
//
//     * the routine returns its error, rather than accepting the
//       oversized value or looping forever, and
//     * it does so without touching a byte outside the input it was
//       given.
//
//   The second is what the guard page is for. The corpus item is
//   copied into a buffer placed flush against a PROT_NONE page, so
//   `end` is a real hardware boundary and not a number the test hopes
//   the parser is comparing against. A parser that reads one byte past
//   the block takes SIGSEGV on that instruction and the case is
//   reported as OUT OF BOUNDS, whatever it would eventually have
//   returned.
//
//   Each case runs in a forked child (guard_probe_status), so a suite
//   run reports every failing case rather than dying on the first —
//   the same shape as the Step 3 bounds suites, and for the same
//   reason.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_OVERFLOW_COMMON_H
#define SARM_OVERFLOW_COMMON_H

#include "guard_pages.h"
#include "../unit/test_harness.h"

#include <stdint.h>
#include <stddef.h>

// ── child verdicts ──────────────────────────────────────────────────
// 77 is reserved (GUARD_CHILD_FAULTED).
#define OV_REJECTED  0   // the routine returned its error — what we want
#define OV_ACCEPTED  1   // the routine accepted the value
#define OV_WRONG     2   // it rejected, but something else is off
#define OV_BADSETUP  3   // the test could not set the case up

// The verdict a case expects. Most of the corpus expects OV_REJECTED;
// a few cases pin behaviour that must stay *accepted* (the largest
// legal value, the boundary one below the limit) so the suite cannot
// pass by rejecting everything.
struct ov_expect {
    int         want;
    const char *label;
};

static void ov_case(const char *label, int want,
                    void (*fn)(void *), void *ctx)
{
    int verdict = 0;
    const int r = guard_probe_status(fn, ctx, &verdict);

    if (r == GUARD_PROBE_FAULT) {
        _FAIL("%s — OUT OF BOUNDS: read or wrote outside the block it was "
              "given", label);
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
    if (verdict == OV_BADSETUP) {
        _FAIL("%s — could not set the case up (allocation failed)", label);
        return;
    }
    if (verdict == OV_WRONG) {
        _FAIL("%s — rejected, but not in the way the case expects", label);
        return;
    }
    if (verdict == want) {
        _PASS(label);
        return;
    }
    if (want == OV_REJECTED)
        _FAIL("%s — ACCEPTED: the overflowing value was not rejected", label);
    else
        _FAIL("%s — REJECTED: a legal value was refused", label);
}

// ── guarded input placement ─────────────────────────────────────────
// Copy `len` bytes to a buffer whose last byte is the last byte of a
// page, with PROT_NONE immediately after. Returns NULL on failure.
static uint8_t *ov_place(struct guarded_buffer *gb, const uint8_t *src,
                         size_t len)
{
    if (guard_alloc_side(gb, len, GUARD_OVERRUN) != 0)
        return NULL;
    for (size_t i = 0; i < len; i++)
        gb->data[i] = src[i];
    return gb->data;
}

// test_harness.h arms alarm(5) at load time. These suites fork a child
// per case and one case is a deliberate non-termination probe, so they
// re-arm it longer — still bounded, so a hang is still caught.
extern unsigned int alarm(unsigned int seconds);
static void ov_extend_timeout(void) { alarm(120); }

#endif // SARM_OVERFLOW_COMMON_H
