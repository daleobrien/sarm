#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_read_exact
//
// Description: HTTP/2 read primitive. Reads exactly len bytes from the
//   fd into buf. The socket I/O is delegated to transport_read — the
//   transport seam — so the HTTP/2 frame
//   loop never issues a read syscall directly.
//
// Input/Arguments:
//   x0 — fd, x1 — buffer, x2 — length
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 — errno on failure (carry set); 0 on EOF
//
// Clobbered Registers:
//   see transport_read
//
// Stack Usage:
//   none (tail-call)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_read_exact
    b transport_read
ENDFUNC h2_read_exact
