#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_priority / h2_handle_push_promise /
//                h2_handle_continuation
//
// Description: Handlers not yet implemented — acknowledge receipt and
//   do nothing. The three frame types share one body (they are aliases
//   of the same no-op): PRIORITY, PUSH_PROMISE, CONTINUATION.
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

.text
.align 2
.global h2_handle_priority
.global h2_handle_push_promise
.global h2_handle_continuation
h2_handle_priority:
h2_handle_push_promise:
h2_handle_continuation:
.Lh2_handler_ok:
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
