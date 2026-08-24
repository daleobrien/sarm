#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: raw_write_all
//
// Description: Write content to a file descriptor, retrying partial
//   writes until all nbytes are written, unconditionally — no
//   transport_mode dispatch. Mirrors raw_read_exact: the primitive
//   transport_write's TRANSPORT_PLAIN path tail-calls, and the one
//   transport_write's own TRANSPORT_TLS branch uses to actually put
//   sealed record bytes on the wire (calling transport_write itself
//   from there would just dispatch straight back and recurse).
//   EINTR is retried; EPIPE is treated as a clean exit (client
//   disconnected).
//
// Input/Arguments:
//   x0 -> file descriptor (same as write() syscall)
//   x1 -> buffer
//   x2 -> nbytes
//
// Output/Returns:
//   x0 -> total number of bytes written
//   carry clear = success, carry set = error (x0 = errno)
//
// Clobbered Registers:
//   x0-x2, x16 (x25, x26 saved and restored)
//
// Stack Usage:
//   16 bytes: stp x25, x26, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC raw_write_all
    stp     x25, x26, [sp, #-16]!
    mov     x25, x0             // fd
    mov     x26, #0             // total bytes written
1:
    // carry = 0, in case we exit with cbz without ever calling write().
    cmn     xzr, xzr
    cbz     x2, 2f

    SCWINUM SYS_write
    mov     x0, x25
    // x1 is set by caller
    // x2 is also set by caller
    SCWISVC
    SCERR
    b.cs    .Lraw_write_fail

    sub     x2, x2, x0          // subtract written bytes
    add     x26, x26, x0        // increment total bytes written
    add     x1, x1, x0          // increment pointer
    b       1b

2:
    mov     x0, x26             // return total bytes written

3:
    ldp     x25, x26, [sp], #16
    ret

.Lraw_write_fail:
    cmp     x0, #EINTR
    b.eq    1b
    cb      eq, x0, #EPIPE, 3b  // treat as clean exit (client disconnected)

    cmp     xzr, xzr            // set C=1 so we can b.cs
    // x0 is already errno
    b       3b
ENDFUNC raw_write_all
