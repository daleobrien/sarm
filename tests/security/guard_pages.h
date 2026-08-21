// sarm security test helpers — guarded (guard-page) buffer allocation
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/guard_pages.h — guarded buffers for testing
//   hand-written assembly against its declared bounds
//   (docs/SECURITY.md, Step 2)
//
// Description: sarm allocates nothing at runtime — every buffer is a
//   fixed-size .bss/.data global (docs/security/threat-model.md §5).
//   That removes every heap bug class, and with it every heap
//   red zone: there is no allocator to notice that an assembly routine
//   wrote one byte past the end of `filename_buf`, because the byte
//   after `filename_buf` is just another global. ASan cannot instrument
//   hand-written .S either.
//
//   A guarded buffer restores the missing detector by construction. The
//   payload is placed flush against a PROT_NONE page, so the *first*
//   out-of-bounds access traps in hardware:
//
//       [ PROT_NONE ][ ...slack... | payload ][ PROT_NONE ]
//                                  ^data      ^data + size
//                                             = first guard byte
//
//   No instrumentation, no allocator, no false positives: either the
//   routine stayed inside the bounds its header comment declares, or
//   the process takes SIGSEGV/SIGBUS on the exact instruction that
//   left them.
//
//   Which end is flush is the caller's choice, because a page boundary
//   can only be exact on one side at a time:
//     GUARD_OVERRUN  — payload ends at the guard: data[size] traps.
//                      The default; catches writes/reads past the end.
//     GUARD_UNDERRUN — payload starts at the guard: data[-1] traps.
//                      Catches a pointer walked backwards, or a
//                      negative index from a wrapped length.
//   Test both sides to cover both, exactly as docs/SECURITY.md §4 asks
//   ("read before, read after, write before, write after").
//
//   guard_probe() runs a function that is *expected* to trap in a
//   forked child and reports whether it did, so a test can assert the
//   detector itself works — and so Step 3's boundary tests can assert
//   a negative control faults without taking the test binary down.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_GUARD_PAGES_H
#define SARM_GUARD_PAGES_H

#include <stddef.h>
#include <stdint.h>

// Which end of the payload sits flush against a guard page. A payload
// that is not a whole number of pages cannot be flush at both ends;
// pick the end whose overflow direction is under test.
enum guard_side {
    GUARD_OVERRUN  = 0,  // data + size == first guard byte
    GUARD_UNDERRUN = 1,  // data - 1    == last guard byte
};

// A guarded allocation. `mapping`/`mapping_size` describe the whole
// mmap (guards included) and belong to guard_free; `data`/`size`
// describe the payload and are what the code under test is handed.
struct guarded_buffer {
    void    *mapping;
    size_t   mapping_size;
    uint8_t *data;
    size_t   size;
};

// Allocate `size` payload bytes flush against a trailing guard page:
// data[size] traps. Equivalent to
// guard_alloc_shifted(gb, size, GUARD_OVERRUN, 0).
// Returns 0 on success, -1 on failure (gb is zeroed on failure).
int guard_alloc(struct guarded_buffer *gb, size_t size);

// As guard_alloc, choosing which end is flush against its guard page.
int guard_alloc_side(struct guarded_buffer *gb, size_t size,
                     enum guard_side side);

// As guard_alloc_side, with `shift` bytes of accessible slack inserted
// between the payload and the guard it would otherwise touch. Two uses:
//
//   * Alignment sweeps. With GUARD_OVERRUN the payload's start
//     alignment is fixed by its size (start == page_end - size), so a
//     routine can only be offered a 1/2/4/.../64-byte-aligned pointer
//     by shifting it. Detection is then exact to within `shift` bytes
//     instead of one byte — deliberately weaker, and the reason shift
//     defaults to 0.
//   * Deliberate over-read margins, when a routine is *documented* to
//     read up to N bytes past its length (vector tails, for instance)
//     and the test is checking it does not exceed N.
//
// Returns 0 on success, -1 on failure.
int guard_alloc_shifted(struct guarded_buffer *gb, size_t size,
                        enum guard_side side, size_t shift);

// Unmap everything, including the guards, and zero *gb. Safe on an
// already-freed or zeroed buffer.
void guard_free(struct guarded_buffer *gb);

// Fill the payload with `byte`. Use a recognisable poison (0xA5) so a
// routine that reads uninitialised payload bytes produces obviously
// wrong output rather than plausible zeros.
void guard_fill(const struct guarded_buffer *gb, uint8_t byte);

// The page size the guards are built from (cached sysconf(_SC_PAGESIZE);
// 16 KiB on Apple silicon, 4 KiB on most Linux/arm64).
size_t guard_page_size(void);

// ── fault probes ────────────────────────────────────────────────────
// guard_probe() result codes.
enum {
    GUARD_PROBE_OK    = 0,   // fn returned normally, no fault
    GUARD_PROBE_FAULT = 1,   // fn took SIGSEGV/SIGBUS — the guard fired
    GUARD_PROBE_ERROR = -1,  // fork/waitpid failed, or the child died
                             //   some other way (a test bug, not a result)
};

// Run fn(ctx) in a forked child and report whether it faulted. The
// child installs SIGSEGV/SIGBUS handlers that _exit immediately, so an
// expected fault costs no crash report and produces no core file, and
// the parent — the test binary — survives to make an assertion about
// it.
//
// The child inherits the parent's memory, so allocate the guarded
// buffer before calling and pass it through ctx.
int guard_probe(void (*fn)(void *ctx), void *ctx);

#endif // SARM_GUARD_PAGES_H
