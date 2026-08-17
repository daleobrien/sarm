#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_data
//
// Description: DATA frames carry request body bytes. Only an existing
//   stream may receive them — an unknown stream is an idle-stream
//   violation (PROTOCOL_ERROR, §5.1); any other invalid state is
//   STREAM_CLOSED. END_STREAM on the frame closes the client's send
//   side. The payload is not consumed yet (receive-side flow control
//   and body handling arrive later; Stage 11 tracks the send-side
//   windows in h2_write_body and h2_handle_window_update).
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — payload
//   x2 — connection state
//
// Output/Returns:
//   x0 — 0 on success, error code on failure; carry set on error
//
// Clobbered Registers:
//   x0-x4, x8-x11, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_data
h2_handle_data:
    str x30, [sp, #-16]!   // save the return address
    mov x10, x0            // hdr
    mov x11, x2            // conn — unused beyond this, kept for symmetry
    ldr w0, [x10, #H2F_STREAM_ID]
    bl h2_stream_find
    cbz x0, .Lh2_data_idle_error
    mov x8, x0             // stream entry
    mov x1, #H2_EVENT_RECV_DATA
    bl h2_stream_event
    b.cs .Lh2_stream_error
    // END_STREAM closes the client's send side → HALF_CLOSED_REMOTE
    ldr w3, [x10, #H2F_FLAGS]
    tst w3, #H2_FLAG_END_STREAM
    b.eq .Lh2_data_ok
    mov x0, x8
    mov x1, #H2_EVENT_RECV_END_STREAM
    bl h2_stream_event
    b.cs .Lh2_stream_error
.Lh2_data_ok:
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
.Lh2_data_idle_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret

// Shared error exit for the stream handlers: every handler saved x30 at
// entry the same way, so pop it back and pass the error through
// (x0 holds the error, carry is set). Duplicated per function file.
.Lh2_stream_error:
    ldr x30, [sp], #16
    ret
