#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: raw_writev_all
//
// Description: Write an iovec array to a file descriptor with a single
//   writev(2), retrying on a partial write until every iovec is fully
//   drained, unconditionally — no transport_mode dispatch. Mirrors
//   raw_write_all (EINTR retried, everything else — including EPIPE —
//   returned as a failure for the caller to treat as a closed
//   connection), generalized to N iovecs: a partial write can land
//   inside any iovec, not just split at a single buffer's boundary, so
//   the caller's iovec array is mutated in place (iov_base/iov_len
//   advanced past whatever this round consumed) before the next
//   writev(2) call.
//
// Input/Arguments:
//   x0 -> file descriptor (same as writev() syscall)
//   x1 -> iovec array (struct iovec { void *iov_base; size_t iov_len; },
//         mutated in place across retries)
//   x2 -> iovec count
//
// Output/Returns:
//   x0 -> total number of bytes written
//   carry clear = success, carry set = error (x0 = errno)
//
// Clobbered Registers:
//   x0-x2, x9-x11, x16 (x25-x28 saved and restored); the caller's
//   iovec array is mutated, not just the registers
//
// Stack Usage:
//   32 bytes: stp x25, x26, [sp, #-32]!; stp x27, x28, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC raw_writev_all
    stp     x25, x26, [sp, #-32]!
    stp     x27, x28, [sp, #16]
    mov     x25, x0             // fd
    mov     x26, x1             // iovec array cursor
    mov     x27, x2             // iovecs remaining
    mov     x28, #0             // total bytes written
.Lrwa_loop:
    // carry = 0, in case we exit with cbz without ever calling writev().
    cmn     xzr, xzr
.Lrwa_skip_empty:
    cbz     x27, .Lrwa_done
    // Drop leading zero-length iovecs. A writev(2) whose whole array is
    // empty returns 0, which consumes nothing and decrements nothing —
    // the retry loop below would spin on it forever. h2_write_body's
    // terminal empty DATA frame passes exactly that (a 9-byte frame
    // header plus a zero-length body), so this is reachable, not
    // theoretical.
    ldr     x9, [x26, #8]
    cbnz    x9, .Lrwa_issue
    add     x26, x26, #16
    sub     x27, x27, #1
    b       .Lrwa_skip_empty
.Lrwa_issue:

    SCWINUM SYS_writev
    mov     x0, x25
    mov     x1, x26
    mov     x2, x27
    SCWISVC
    SCERR
    b.cs    .Lrwa_fail

    add     x28, x28, x0        // accumulate total
    mov     x9, x0              // bytes to walk off the iovec array
.Lrwa_consume:
    cbz     x9, .Lrwa_loop      // fully accounted for — writev again
    ldr     x10, [x26, #8]      // this iovec's iov_len
    cmp     x9, x10
    b.lo    .Lrwa_partial
    // this iovec was fully written — drop it, keep walking
    sub     x9, x9, x10
    add     x26, x26, #16
    sub     x27, x27, #1
    b       .Lrwa_consume
.Lrwa_partial:
    // partially written — advance base/len in place, nothing left to walk
    ldr     x11, [x26]          // iov_base
    add     x11, x11, x9
    str     x11, [x26]
    sub     x10, x10, x9
    str     x10, [x26, #8]
    mov     x9, #0
    b       .Lrwa_consume

.Lrwa_done:
    mov     x0, x28             // return total bytes written

3:
    ldp     x27, x28, [sp, #16]
    ldp     x25, x26, [sp], #32
    ret

.Lrwa_fail:
    cmp     x0, #EINTR
    b.eq    .Lrwa_loop          // interrupted — nothing to adjust, retry as-is

    cmp     xzr, xzr            // set C=1 so we can b.cs (EPIPE included —
                                 // not retried, reported like any other error
                                 // for the caller to treat as a closed
                                 // connection)
    // x0 is already errno
    b       3b
ENDFUNC raw_writev_all
