#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: write_all
//
// Description: Generic write helper. Writes all nbytes, retrying
//   partial writes. The socket I/O is delegated to transport_write —
//   the transport seam introduced in PLAN.MD §1.2 — so HTTP/2 frame
//   writers never issue a write syscall directly.
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
//   see transport_write
//
// Stack Usage:
//   none (tail-call)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global write_all
write_all:
    b transport_write
