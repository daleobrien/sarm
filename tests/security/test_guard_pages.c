// sarm security tests — the guard-page helper's own self-test
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// docs/SECURITY.md, Step 2:
//   "Test: deliberately broken test function reliably faults on:
//    read before, read after, write before, write after."
//
// Every later security test trusts this helper to notice an
// out-of-bounds access in hand-written assembly. A guard page that is
// silently not there — wrong page size, payload not flush against the
// guard, mprotect quietly failing — would make every one of those tests
// pass by doing nothing, which is the worst failure mode a test suite
// can have. So the four deliberately broken functions below exist to
// prove the detector fires, on both sides, for both reads and writes,
// before anything real is measured against it.
//
// The positive controls matter just as much: the last in-bounds byte
// and the first in-bounds byte must NOT fault. A helper that mapped
// everything PROT_NONE would pass all four fault tests and be useless.
// ─────────────────────────────────────────────────────────────────────

#include "guard_pages.h"
#include "../unit/test_harness.h"

#include <stdint.h>

// ── the deliberately broken functions ───────────────────────────────
// volatile everywhere: these functions exist to touch memory and
// nothing else, and without it the compiler is entitled to delete the
// read (its result is unused) and turn the whole test green.

static void probe_read_after(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t sink = gb->data[gb->size];      // one past the end
    (void)sink;
}

static void probe_write_after(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[gb->size] = 0x5a; // one past the end
}

static void probe_read_before(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t sink = gb->data[-1];            // one before the start
    (void)sink;
}

static void probe_write_before(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[-1] = 0x5a;       // one before the start
}

// ── the in-bounds controls ──────────────────────────────────────────

static void probe_read_last(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t sink = gb->data[gb->size - 1];
    (void)sink;
}

static void probe_write_last(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[gb->size - 1] = 0x5a;
}

static void probe_read_first(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t sink = gb->data[0];
    (void)sink;
}

static void probe_write_first(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[0] = 0x5a;
}

// probes for guard_alloc_shifted's slack region: the last slack byte is
// still writable, the byte after it is not.
static void probe_write_last_slack(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[gb->size + 7] = 0x5a;
}

static void probe_write_past_slack(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    ((volatile uint8_t *)gb->data)[gb->size + 8] = 0x5a;
}

// a zero-length payload: any dereference at all must trap
static void probe_read_zero(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t sink = gb->data[0];
    (void)sink;
}

// the whole payload, walked — proves nothing inside the bounds traps
static void probe_walk_all(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    volatile uint8_t *p = (volatile uint8_t *)gb->data;
    for (size_t i = 0; i < gb->size; i++)
        p[i] = (uint8_t)i;
    for (size_t i = 0; i < gb->size; i++)
        if (p[i] != (uint8_t)i)
            _exit(3);   // a distinct code: not a fault, a wrong result
}

// after guard_free the mapping is gone, so even data[0] must trap
static void probe_after_free(void *ctx)
{
    struct guarded_buffer *gb = (struct guarded_buffer *)ctx;
    uint8_t *stale = gb->data;
    volatile uint8_t sink = stale[0];
    (void)sink;
}

// ── assertion helpers ───────────────────────────────────────────────

static void assert_faults(const char *label, void (*fn)(void *),
                          struct guarded_buffer *gb)
{
    const int r = guard_probe(fn, gb);
    if (r == GUARD_PROBE_FAULT)
        _PASS(label);
    else if (r == GUARD_PROBE_OK)
        _FAIL("%s — no fault: the guard page is not there", label);
    else
        _FAIL("%s — probe error (fork/waitpid, or the child died "
              "unexpectedly)", label);
}

static void assert_no_fault(const char *label, void (*fn)(void *),
                            struct guarded_buffer *gb)
{
    const int r = guard_probe(fn, gb);
    if (r == GUARD_PROBE_OK)
        _PASS(label);
    else if (r == GUARD_PROBE_FAULT)
        _FAIL("%s — faulted inside the payload: the usable region is "
              "mapped wrong", label);
    else
        _FAIL("%s — probe error (fork/waitpid, or the child died "
              "unexpectedly)", label);
}

// ── suites ──────────────────────────────────────────────────────────

// a function that touches no memory at all — the probe's own control
static void probe_nothing(void *ctx) { (void)ctx; }

int main(void)
{
    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  guard-page helper self-test              ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    struct guarded_buffer gb;

    // ── the probe mechanism ─────────────────────────────────────────
    TEST_SUITE("guard_probe — mechanism");
    {
        struct guarded_buffer none = {0};
        ASSERT_EQ("a function that touches nothing reports OK",
                  GUARD_PROBE_OK, guard_probe(probe_nothing, &none));
    }

    ASSERT_TRUE("page size is a non-zero power of two",
                guard_page_size() != 0 &&
                (guard_page_size() & (guard_page_size() - 1)) == 0);

    // ── GUARD_OVERRUN: the four required cases, plus controls ───────
    TEST_SUITE("GUARD_OVERRUN — payload flush against the trailing guard");

    ASSERT_EQ("guard_alloc(4096) succeeds", 0, guard_alloc(&gb, 4096));
    ASSERT_EQ("payload ends exactly on a page boundary", 0,
              (uint64_t)((uintptr_t)(gb.data + gb.size) % guard_page_size()));
    guard_fill(&gb, 0xA5);

    assert_no_fault("read  data[size-1] (last in-bounds byte)", probe_read_last, &gb);
    assert_no_fault("write data[size-1] (last in-bounds byte)", probe_write_last, &gb);
    assert_faults  ("read  data[size]   (one past the end)",    probe_read_after, &gb);
    assert_faults  ("write data[size]   (one past the end)",    probe_write_after, &gb);
    assert_no_fault("walk and verify every payload byte",       probe_walk_all, &gb);

    guard_free(&gb);
    ASSERT_TRUE("guard_free zeroes the descriptor",
                gb.mapping == NULL && gb.data == NULL && gb.size == 0);

    // ── GUARD_UNDERRUN: the mirror image ────────────────────────────
    TEST_SUITE("GUARD_UNDERRUN — payload flush against the leading guard");

    ASSERT_EQ("guard_alloc_side(4096, UNDERRUN) succeeds", 0,
              guard_alloc_side(&gb, 4096, GUARD_UNDERRUN));
    ASSERT_EQ("payload starts exactly on a page boundary", 0,
              (uint64_t)((uintptr_t)gb.data % guard_page_size()));
    guard_fill(&gb, 0xA5);

    assert_no_fault("read  data[0]  (first in-bounds byte)", probe_read_first, &gb);
    assert_no_fault("write data[0]  (first in-bounds byte)", probe_write_first, &gb);
    assert_faults  ("read  data[-1] (one before the start)", probe_read_before, &gb);
    assert_faults  ("write data[-1] (one before the start)", probe_write_before, &gb);

    guard_free(&gb);

    // ── a size that is not a page multiple stays flush ──────────────
    // The case a hard-coded page size or a rounded-up payload would
    // quietly get wrong: 100 bytes must still end ON the guard, not
    // page_size bytes short of it.
    TEST_SUITE("non-page-multiple sizes stay flush against the guard");

    static const size_t sizes[] = {
        1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 4095, 4097
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        const size_t n = sizes[i];
        char label[96];
        if (guard_alloc(&gb, n) != 0) {
            _FAIL("guard_alloc(%zu) failed", n);
            continue;
        }
        guard_fill(&gb, 0xA5);

        snprintf(label, sizeof(label), "size %-4zu: data[size-1] readable", n);
        assert_no_fault(label, probe_read_last, &gb);
        snprintf(label, sizeof(label), "size %-4zu: data[size] traps", n);
        assert_faults(label, probe_write_after, &gb);

        guard_free(&gb);
    }

    // ── zero-length payloads ────────────────────────────────────────
    TEST_SUITE("zero-length payload — every dereference traps");

    ASSERT_EQ("guard_alloc(0) succeeds", 0, guard_alloc(&gb, 0));
    ASSERT_NOT_NULL("data is a valid, comparable pointer", gb.data);
    ASSERT_EQ("size is 0", 0, (int64_t)gb.size);
    assert_faults("read data[0] traps", probe_read_zero, &gb);
    guard_free(&gb);

    // ── shifted allocations (alignment sweeps) ──────────────────────
    TEST_SUITE("guard_alloc_shifted — slack between payload and guard");

    ASSERT_EQ("guard_alloc_shifted(100, OVERRUN, 8) succeeds", 0,
              guard_alloc_shifted(&gb, 100, GUARD_OVERRUN, 8));
    guard_fill(&gb, 0xA5);
    assert_no_fault("last slack byte data[size+7] is writable",
                    probe_write_last_slack, &gb);
    assert_faults("data[size+8] traps — slack ends at the guard",
                  probe_write_past_slack, &gb);
    guard_free(&gb);

    // Alignment sweep: the reason shifting exists. A routine that
    // quietly assumes 16-byte alignment must be callable at every
    // alignment its ABI permits (docs/SECURITY.md §12).
    for (size_t align = 1; align <= 64; align <<= 1) {
        char label[96];
        // shift so that (page_end - shift - size) % align == 0
        const size_t size = 96;
        const size_t page = guard_page_size();
        const size_t shift = ((page - size) % align + align) % align;
        if (guard_alloc_shifted(&gb, size, GUARD_OVERRUN, shift) != 0) {
            _FAIL("guard_alloc_shifted(96, OVERRUN, %zu) failed", shift);
            continue;
        }
        snprintf(label, sizeof(label),
                 "payload can be placed %2zu-byte aligned", align);
        ASSERT_EQ(label, 0, (uint64_t)((uintptr_t)gb.data % align));
        guard_free(&gb);
    }

    // ── freed mappings really are gone ──────────────────────────────
    TEST_SUITE("guard_free — the mapping is actually unmapped");
    {
        struct guarded_buffer freed;
        ASSERT_EQ("guard_alloc(256) succeeds", 0, guard_alloc(&freed, 256));
        struct guarded_buffer stale = freed;   // keep the old data pointer
        guard_free(&freed);
        assert_faults("a stale pointer into a freed buffer traps",
                      probe_after_free, &stale);
    }

    test_summary();
    return 0;
}
