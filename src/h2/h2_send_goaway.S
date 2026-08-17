#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_send_goaway
//
// Description: Send a GOAWAY frame and let the caller close the
//   connection. Carries the connection's high-water stream id (read
//   from the passed connection state) and the given error code (RFC
//   9113 §6.8).
//
// Input/Arguments:
//   x0 — fd, x1 — error code, x2 — connection state
//
// Output/Returns:
//   (none — write failures are ignored; the connection is closing anyway)
//
// Clobbered Registers:
//   x1-x4, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!; plus 32 bytes of stack frame
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_send_goaway
h2_send_goaway:
    str x30, [sp, #-16]!
    sub sp, sp, #32
    // payload length = 8
    mov w3, #8
    strb wzr, [sp, #0]
    strb wzr, [sp, #1]
    strb w3, [sp, #2]
    // type = GOAWAY, flags = 0, stream id = 0
    mov w3, #H2_FRAME_GOAWAY
    strb w3, [sp, #3]
    strb wzr, [sp, #4]
    strb wzr, [sp, #5]
    strb wzr, [sp, #6]
    strb wzr, [sp, #7]
    strb wzr, [sp, #8]
    // payload: last client-initiated stream id (4 bytes, big-endian)
    ldr w3, [x2, #H2C_LAST_STREAM_ID]
    lsr w4, w3, #24
    strb w4, [sp, #9]
    lsr w4, w3, #16
    strb w4, [sp, #10]
    lsr w4, w3, #8
    strb w4, [sp, #11]
    strb w3, [sp, #12]
    // payload: error code (4 bytes, big-endian)
    lsr w4, w1, #24
    strb w4, [sp, #13]
    lsr w4, w1, #16
    strb w4, [sp, #14]
    lsr w4, w1, #8
    strb w4, [sp, #15]
    strb w1, [sp, #16]
    mov x1, sp
    mov x2, #17
    bl write_all
    add sp, sp, #32
    ldr x30, [sp], #16
    ret
