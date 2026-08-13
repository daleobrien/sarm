#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_window_update
//
// Description: Replenish flow-control credit (RFC 9113 §6.9). The
//   payload is one 31-bit increment (big-endian; the reserved top bit
//   is ignored). Stream 0 updates the connection window; a nonzero
//   stream id updates that stream's window. A length other than 4 is a
//   FRAME_SIZE_ERROR; an increment of 0 is a PROTOCOL_ERROR; an update
//   that would push a window past 2^31-1 is a FLOW_CONTROL_ERROR; and
//   an update for a stream that isn't in the table (an idle stream) is
//   a PROTOCOL_ERROR. An update on a CLOSED stream is ignored, not an
//   error — a peer may send WINDOW_UPDATE after END_STREAM (§5.1 closed).
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
//   x0-x6, x9, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_window_update
h2_handle_window_update:
    str x30, [sp, #-16]!   // save the return address — find clobbers x30
    mov x7, #H2_MAX_FLOW_WINDOW   // 2^31 - 1 — the window ceiling (§5.2)
    // exactly 4 payload bytes — one 32-bit increment (§6.9)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #4
    b.ne .Lh2wu_size_error
    // increment — 31-bit big-endian
    ldrb w4, [x1]
    ldrb w5, [x1, #1]
    ldrb w6, [x1, #2]
    ldrb w3, [x1, #3]
    lsl w4, w4, #24
    orr w4, w4, w5, lsl #16
    orr w4, w4, w6, lsl #8
    orr w4, w4, w3
    and w4, w4, #0x7fffffff   // mask off the reserved bit
    cbz w4, .Lh2wu_zero_error
    mov x5, x4               // increment — x4 is reused for the stream id
    ldr w4, [x0, #H2F_STREAM_ID]
    cbnz w4, .Lh2wu_stream
    // ── connection-level — stream 0 → the connection window ──
    ldr x3, [x2, #H2C_WINDOW]
    add x3, x3, x5
    cmp x3, x7
    b.hi .Lh2wu_flow_error
    str x3, [x2, #H2C_WINDOW]
    b .Lh2wu_ok
.Lh2wu_stream:
    mov x0, x4
    bl h2_stream_find
    cbz x0, .Lh2wu_protocol_error  // idle stream — PROTOCOL_ERROR
    ldr x6, [x0, #H2S_STATE]
    cmp x6, #H2_STREAM_CLOSED
    b.eq .Lh2wu_ok                  // closed — ignore, not an error (§5.1)
    ldr x3, [x0, #H2S_WINDOW]
    add x3, x3, x5
    cmp x3, x7
    b.hi .Lh2wu_flow_error
    str x3, [x0, #H2S_WINDOW]
.Lh2wu_ok:
    ldr x30, [sp], #16
    cmn xzr, xzr             // success — carry clear
    mov x0, #0
    ret
.Lh2wu_protocol_error:
    ldr x30, [sp], #16
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2wu_flow_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FLOW_CONTROL_ERROR
    ret
.Lh2wu_size_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret
.Lh2wu_zero_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
