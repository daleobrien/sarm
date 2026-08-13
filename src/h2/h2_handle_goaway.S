#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_goaway
//
// Description: A GOAWAY frame begins connection teardown (RFC 9113
//   §6.8): the sender will not open new streams, and the peer should
//   wrap up. It is connection-scoped (a stream id other than 0 is a
//   PROTOCOL_ERROR connection error) and carries at least 8 payload
//   octets — the last client-initiated stream id the sender might
//   process plus an error code; a shorter frame is a FRAME_SIZE_ERROR
//   (debug data may follow the 8). The server records the peer's last
//   stream id and marks the connection as going away — the HEADERS
//   handler then refuses any brand-new stream with REFUSED_STREAM — and
//   answers with its own GOAWAY(NO_ERROR) so the client knows the server
//   will not open streams either. Already-accepted streams run to
//   completion, which is what makes the shutdown graceful.
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
//   x0-x7, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_goaway
h2_handle_goaway:
    str x30, [sp, #-16]!   // save the return address
    // connection-scoped — stream id must be 0 (§6.8)
    ldr w3, [x0, #H2F_STREAM_ID]
    cbnz w3, .Lh2goaway_protocol_error
    // at least the 8 required octets (§6.8)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #8
    b.lo .Lh2goaway_size_error
    // last processed client stream id — 31-bit, big-endian (§6.8)
    ldrb w4, [x1]
    ldrb w5, [x1, #1]
    ldrb w6, [x1, #2]
    ldrb w7, [x1, #3]
    lsl w4, w4, #24
    orr w4, w4, w5, lsl #16
    orr w4, w4, w6, lsl #8
    orr w4, w4, w7
    and w4, w4, #0x7fffffff
    str w4, [x2, #H2C_GOAWAY_LAST_STREAM_ID]
    mov w3, #1
    str w3, [x2, #H2C_GOAWAY_RECEIVED]
    // answer with our own GOAWAY(NO_ERROR) — we will not open streams
    // either; the error code and our high-water mark go in the frame
    ldr x0, [x2, #H2C_FD]
    mov x1, #H2_ERR_NO_ERROR
    bl h2_send_goaway
    ldr x30, [sp], #16
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ret
.Lh2goaway_protocol_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2goaway_size_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret
