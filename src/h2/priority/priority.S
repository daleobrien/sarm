// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_priority
//
// Description: Handler not yet implemented — acknowledge receipt and
//   do nothing.
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — payload
//   x2 — connection state
//
// Output/Returns:
//   x0 — 0 (success), carry clear
//
// Clobbered Registers:
//   (none)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.text
.align 2
.global h2_handle_priority
h2_handle_priority:
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
