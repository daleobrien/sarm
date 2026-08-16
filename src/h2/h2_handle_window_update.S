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
//   an update for a stream that was never opened (an idle stream) is a
//   PROTOCOL_ERROR. An update on a CLOSED stream is ignored, not an
//   error — a peer may send WINDOW_UPDATE after END_STREAM (§5.1 closed).
//   A stream missing from the table counts as closed when its id is at
//   or below H2C_LAST_STREAM_ID (§5.1.1), since recycling drops the
//   entries of finished streams.
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
    ldr x6, [x2, #H2C_LAST_STREAM_ID]  // high-water mark — find clobbers x2
    mov x0, x4
    bl h2_stream_find
    cbz x0, .Lh2wu_missing
    ldr x6, [x0, #H2S_STATE]
    cmp x6, #H2_STREAM_CLOSED
    b.eq .Lh2wu_ok                  // closed — ignore, not an error (§5.1)
    ldr x3, [x0, #H2S_WINDOW]
    add x3, x3, x5
    cmp x3, x7
    b.hi .Lh2wu_flow_error
    str x3, [x0, #H2S_WINDOW]
    b .Lh2wu_ok
.Lh2wu_missing:
    // Not in the table. The table is finite and CLOSED entries get
    // recycled, so a stream we once served can vanish from it — and an
    // id at or below the connection's high-water mark (§5.1.1) is
    // exactly that: closed, so ignore the update (§5.1). Only an id
    // above the mark was never opened — idle, a PROTOCOL_ERROR (§6.9).
    cmp x4, x6
    b.hi .Lh2wu_protocol_error
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
