// sarm security test helpers — guarded (guard-page) buffer allocation
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// See guard_pages.h for what a guarded buffer is and why sarm needs one.
// This file is the implementation; it is test-only code and links no
// part of the server.

#include "guard_pages.h"

#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

extern unsigned int alarm(unsigned int seconds);

// ─────────────────────────────────────────────────────────────────────
// guard_page_size — sysconf(_SC_PAGESIZE), cached.
//
// Every offset below is computed from this rather than from a constant:
// Apple silicon pages are 16 KiB, most Linux/arm64 builds use 4 KiB, and
// a hard-coded 4096 would silently stop being flush against the guard
// on macOS — the payload would end 12 KiB short of the trap, and every
// overflow test would quietly pass.
// ─────────────────────────────────────────────────────────────────────
size_t guard_page_size(void)
{
    static size_t cached = 0;
    if (cached == 0)
        cached = (size_t)sysconf(_SC_PAGESIZE);
    return cached;
}

static size_t round_up_pages(size_t n, size_t page)
{
    return (n + page - 1) / page * page;
}

// ─────────────────────────────────────────────────────────────────────
// guard_alloc_shifted — the one real allocator; the others wrap it.
//
// Layout:
//
//     mapping ──► [ guard ][ usable pages ][ guard ]
//                          ^region
//
//   GUARD_OVERRUN:   region + usable - shift - size == data
//                    so data + size + shift is the first guard byte.
//   GUARD_UNDERRUN:  region + shift == data
//                    so data - shift - 1 is the last guard byte.
//
// The whole span is mapped PROT_NONE first and only the middle is then
// mprotect'ed to RW. Mapping the guards separately would leave a window
// where another thread's mmap could land between them; one mapping
// cannot be interleaved, and it also makes guard_free a single munmap.
//
// size == 0 is legal and useful: with GUARD_OVERRUN the payload pointer
// lands exactly on the first guard byte, so it is a valid, comparable,
// non-NULL pointer that traps on *any* dereference — precisely the
// probe a zero-length call should be handed (Step 3's corpus starts at
// 0). With GUARD_UNDERRUN a zero-size payload only makes data[-1] trap;
// data[0] is ordinary writable slack.
// ─────────────────────────────────────────────────────────────────────
int guard_alloc_shifted(struct guarded_buffer *gb, size_t size,
                        enum guard_side side, size_t shift)
{
    const size_t page = guard_page_size();

    gb->mapping = NULL;
    gb->mapping_size = 0;
    gb->data = NULL;
    gb->size = 0;

    if (size + shift < size)      // overflow in the caller's arithmetic
        return -1;

    size_t usable = round_up_pages(size + shift, page);
    if (usable == 0)
        usable = page;            // size == shift == 0: keep one real page

    const size_t mapping_size = usable + 2 * page;

    void *mapping = mmap(NULL, mapping_size, PROT_NONE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED)
        return -1;

    uint8_t *region = (uint8_t *)mapping + page;
    if (mprotect(region, usable, PROT_READ | PROT_WRITE) != 0) {
        munmap(mapping, mapping_size);
        return -1;
    }

    gb->mapping = mapping;
    gb->mapping_size = mapping_size;
    gb->size = size;
    gb->data = (side == GUARD_OVERRUN)
             ? region + usable - shift - size
             : region + shift;
    return 0;
}

int guard_alloc_side(struct guarded_buffer *gb, size_t size,
                     enum guard_side side)
{
    return guard_alloc_shifted(gb, size, side, 0);
}

int guard_alloc(struct guarded_buffer *gb, size_t size)
{
    return guard_alloc_shifted(gb, size, GUARD_OVERRUN, 0);
}

void guard_free(struct guarded_buffer *gb)
{
    if (gb->mapping != NULL)
        munmap(gb->mapping, gb->mapping_size);
    gb->mapping = NULL;
    gb->mapping_size = 0;
    gb->data = NULL;
    gb->size = 0;
}

void guard_fill(const struct guarded_buffer *gb, uint8_t byte)
{
    for (size_t i = 0; i < gb->size; i++)
        gb->data[i] = byte;
}

// ─────────────────────────────────────────────────────────────────────
// guard_probe — run a function that is expected to fault, in a child.
//
// The handler exists to make an expected fault cheap and quiet: without
// it, macOS routes every one through the crash reporter (slow, and it
// litters ~/Library/Logs/DiagnosticReports) and Linux may write a core
// file. _exit from the handler is async-signal-safe and does not
// re-enter the faulting instruction, which returning from the handler
// would.
//
// Both outcomes are still accepted — the handler's exit code and plain
// death by SIGSEGV/SIGBUS — so the probe reports GUARD_PROBE_FAULT even
// where signal delivery is arranged differently.
// ─────────────────────────────────────────────────────────────────────
// GUARD_CHILD_FAULTED (77) is defined in guard_pages.h — deliberately
// not 0/1/2, so it cannot collide with a verdict a probe function
// returns through guard_probe_status.

#define GUARD_CHILD_TIMEDOUT 78

static void guard_child_fault_handler(int sig)
{
    (void)sig;
    _exit(GUARD_CHILD_FAULTED);
}

static void guard_child_alarm_handler(int sig)
{
    (void)sig;
    _exit(GUARD_CHILD_TIMEDOUT);
}

int guard_probe(void (*fn)(void *ctx), void *ctx)
{
    int exit_code = 0;
    const int r = guard_probe_status(fn, ctx, &exit_code);
    if (r == GUARD_PROBE_OK && exit_code != 0)
        return GUARD_PROBE_ERROR;   // a plain probe has no verdict to
                                    // report; a non-zero exit is a bug
                                    // in the probe function
    return r;
}

int guard_probe_status(void (*fn)(void *ctx), void *ctx, int *exit_code)
{
    fflush(stdout);   // never let the child inherit buffered output it
                      // could duplicate (it _exits, so it never flushes,
                      // but do not rely on that)
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0)
        return GUARD_PROBE_ERROR;

    if (pid == 0) {
        signal(SIGSEGV, guard_child_fault_handler);
        signal(SIGBUS,  guard_child_fault_handler);
        signal(SIGALRM, guard_child_alarm_handler);
        alarm(GUARD_PROBE_SECS);   // the routine under test may not
                                   // terminate; the child must
        fn(ctx);
        _exit(0);     // no fault
    }

    int status = 0;
    for (;;) {
        if (waitpid(pid, &status, 0) >= 0)
            break;
        if (errno == EINTR)
            continue;   // the harness's own SIGALRM timer, most likely
        return GUARD_PROBE_ERROR;
    }

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == GUARD_CHILD_FAULTED)
            return GUARD_PROBE_FAULT;
        if (WEXITSTATUS(status) == GUARD_CHILD_TIMEDOUT)
            return GUARD_PROBE_TIMEOUT;
        *exit_code = WEXITSTATUS(status);
        return GUARD_PROBE_OK;
    }
    if (WIFSIGNALED(status)) {
        const int sig = WTERMSIG(status);
        if (sig == SIGSEGV || sig == SIGBUS)
            return GUARD_PROBE_FAULT;
        if (sig == SIGALRM)
            return GUARD_PROBE_TIMEOUT;
    }
    return GUARD_PROBE_ERROR;
}
