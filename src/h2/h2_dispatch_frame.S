#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_dispatch_frame
//
// Description: Switch on the frame type and tail-call the matching
//   handler. Unknown frame types are ignored, not errors (RFC 9113
//   §5.5), so a future extension can be added without breaking the
//   connection. The dispatch table (h2_frame_handlers) is local to this
//   file; the handlers it references are .global in their own files.
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — payload
//   x2 — connection state
//
// Output/Returns:
//   x0 — handler result: 0 on success, error code on failure
//   carry set on connection error
//
// Clobbered Registers:
//   x3, x9 (handlers clobber their own)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
// frame-type dispatch table, indexed by frame type (§6). The dispatcher
// tail-calls the selected handler, so the handler returns directly to
// the dispatcher's caller with the same x0/x1/x2 arguments.
h2_frame_handlers:
    .quad h2_handle_data
    .quad h2_handle_headers
    .quad h2_handle_priority
    .quad h2_handle_rst_stream
    .quad h2_handle_settings
    .quad h2_handle_push_promise
    .quad h2_handle_ping
    .quad h2_handle_goaway
    .quad h2_handle_window_update
    .quad h2_handle_continuation

.text
.align 2
.global h2_dispatch_frame
h2_dispatch_frame:
    ldr w3, [x0, #H2F_TYPE]
    cmp w3, #H2_FRAME_CONTINUATION
    b.hi .Lh2_unknown_frame

    // remember the dispatched type — debug aid, observable in tests
    str w3, [x2, #H2C_LAST_FRAME_TYPE]

    adr_l x9, h2_frame_handlers
    ldr x9, [x9, w3, uxtw #3]
    br x9

.Lh2_unknown_frame:
    cmn xzr, xzr
    mov x0, #0
    ret
