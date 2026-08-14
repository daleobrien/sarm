#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_write
//
// Description: The transport write primitive. Writes content to a file
//   descriptor, retrying in case of partial writes until all nbytes are
//   written. EINTR is retried; EPIPE is treated as a clean exit (client
//   disconnected). This is the seam that will eventually route through
//   TLS; for now it issues the raw socket write directly.
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
//   x0, x1, x2, x25, x26 (x25/x26 saved and restored)
//
// Stack Usage:
//   16 bytes: stp x25, x26, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global transport_write
transport_write:
    stp x25, x26, [sp, #-16]!
    mov x25, x0             // fd
    mov x26, #0             // total bytes written
1:
    // carry = 0, in case we exit with cbz without ever calling write().
    cmn xzr, xzr
    cbz x2, 2f

    SCWINUM SYS_write
    mov x0, x25
    // x1 is set by caller
    // x2 is also set by caller
    SCWISVC
    SCERR
    b.cs .Ltransport_write_fail

    sub x2, x2, x0          // subtract written bytes
    add x26, x26, x0        // increment total bytes written
    add x1, x1, x0          // increment pointer
    b 1b

2:
    mov x0, x26             // return total bytes written

3:
    ldp x25, x26, [sp], #16
    ret

.Ltransport_write_fail:
    cmp x0, #EINTR
    b.eq 1b
    cb eq, x0, #EPIPE, 3b   // treat as clean exit (client disconnected)

    cmp xzr, xzr            // set C=1 so we can b.cs
    // x0 is already errno
    b 3b
