// This file is part of ymawky.
// Copyright (C) 2026 imtomt
//
// ymawky is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// ymawky is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ymawky. If not, see <https://www.gnu.org/licenses/>.

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_write_body
//
// Description: Send the response body as DATA frames. The body is split
//   into H2_DEFAULT_MAX_FRAME_SIZE (2^14) chunks; the last chunk
//   carries END_STREAM. An empty body sends a single empty DATA frame
//   with END_STREAM.
//
// Stage 11 — flow control (§5.2): every DATA chunk is bounded by
//   min(connection window, stream window, remaining), and both windows
//   are drained by the octets sent. When the body still has data but a
//   window is exhausted, the writer blocks reading frames from the
//   client and dispatching them — a WINDOW_UPDATE replenishes the
//   credit and transmission resumes. This keeps the per-connection loop
//   simple: the whole response is written inline, pausing only for the
//   credit the peer hasn't granted yet.
//
// Input/Arguments:
//   x0 — client fd
//   x1 — response struct
//   x2 — stream id
//
// Output/Returns:
//   x0 — 0 on success (carry clear); errno on failure (carry set), or
//     H2_ERR_* from a frame dispatched while waiting for credit
//
// Clobbered Registers:
//   x0-x8, x13, x19-x27 (saved/restored), x30
//
// Stack Usage:
//   96 bytes: stp x19, x20, [sp, #-96]!; ...; stp x27, x30, [sp, #64]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_write_body
h2_write_body:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x30, [sp, #64]
    mov x19, x0             // fd
    mov x20, x1             // response
    mov x21, x2             // stream id
    ldr x22, [x20, #RESP_BODY]
    ldr x23, [x20, #RESP_BODY_LENGTH]
    adr_l x26, h2_conn
    mov x0, x21
    bl h2_stream_find
    mov x27, x0             // stream entry, or 0 (no stream-level credit)
.Lh2wb_loop:
    // this chunk = min(max frame size, connection window, stream window,
    //                  remaining) — §5.2
    mov x24, #H2_DEFAULT_MAX_FRAME_SIZE
    ldr x8, [x26, #H2C_WINDOW]
    cmp x24, x8
    csel x24, x8, x24, hi
    cbnz x27, .Lh2wb_have_stream
    b .Lh2wb_min_remaining
.Lh2wb_have_stream:
    ldr x8, [x27, #H2S_WINDOW]
    cmp x24, x8
    csel x24, x8, x24, hi
.Lh2wb_min_remaining:
    cmp x24, x23
    csel x24, x23, x24, hi
    // a zero chunk with body remaining means the windows are exhausted —
    // read frames (WINDOW_UPDATE) until credit opens up; a zero chunk
    // with an empty body is the terminal empty DATA frame, which carries
    // no octets and consumes no credit (§5.2)
    cbnz x24, .Lh2wb_send
    cbnz x23, .Lh2wb_wait
.Lh2wb_send:
    // END_STREAM rides on the final chunk
    mov w25, #0
    cmp x24, x23
    b.ne 1f
    mov w25, #H2_FLAG_END_STREAM
1:
    // frame header at h2_frame_buf
    adr_l x13, h2_frame_buf
    mov w3, w24
    lsr w4, w3, #16
    strb w4, [x13, #0]
    lsr w4, w3, #8
    strb w4, [x13, #1]
    strb w3, [x13, #2]
    mov w3, #H2_FRAME_DATA
    strb w3, [x13, #3]
    strb w25, [x13, #4]
    mov w3, w21
    lsr w4, w3, #24
    strb w4, [x13, #5]
    lsr w4, w3, #16
    strb w4, [x13, #6]
    lsr w4, w3, #8
    strb w4, [x13, #7]
    strb w3, [x13, #8]
    // copy the chunk behind the header (zero-copy DATA is a later stage)
    add x0, x13, #H2_WIRE_HEADER_LEN
    mov x1, x22
    mov x2, x24
    bl memcpy
    // one write per frame
    mov x0, x19
    adr_l x1, h2_frame_buf
    mov x2, #H2_WIRE_HEADER_LEN
    add x2, x2, x24
    bl write_all
    b.cs .Lh2wb_err
    // the DATA octets drain both windows (§5.2)
    ldr x8, [x26, #H2C_WINDOW]
    sub x8, x8, x24
    str x8, [x26, #H2C_WINDOW]
    cbnz x27, .Lh2wb_dec_stream
    b .Lh2wb_advance
.Lh2wb_dec_stream:
    ldr x8, [x27, #H2S_WINDOW]
    sub x8, x8, x24
    str x8, [x27, #H2S_WINDOW]
.Lh2wb_advance:
    add x22, x22, x24
    sub x23, x23, x24
    cbnz x23, .Lh2wb_loop
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2wb_done
.Lh2wb_wait:
    // ── out of credit, body remaining — read a frame and dispatch it ──
    // The 9-byte wire header lands at buf[0..8] and is parsed before the
    // payload read overwrites it; the payload (≤ H2C_MAX_RX_FRAME_SIZE)
    // fits buf. WINDOW_UPDATE replenishes the credit; anything else is
    // still dispatched normally (SETTINGS, PING, ...). A dispatch error
    // aborts the response.
    mov x0, x19
    adr_l x1, buf
    mov x2, #H2_WIRE_HEADER_LEN
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, buf
    adr_l x1, h2_frame_header
    bl h2_parse_frame_header
    adr_l x0, h2_frame_header
    mov x1, x26
    bl h2_validate_frame
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    ldr w8, [x0, #H2F_LENGTH]
    mov x0, x19
    adr_l x1, buf
    mov x2, x8
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    adr_l x1, buf
    mov x2, x26
    bl h2_dispatch_frame
    b.cs .Lh2wb_dispatch_error
    b .Lh2wb_loop
.Lh2wb_dispatch_error:
    // stream errors (STREAM_CLOSED, and the REFUSED_STREAM a HEADERS
    // after GOAWAY answers with) — RST_STREAM that stream and keep
    // waiting for credit; anything else poisons the connection and
    // aborts the response
    cmp x0, #H2_ERR_STREAM_CLOSED
    b.eq .Lh2wb_rst_stream
    cmp x0, #H2_ERR_REFUSED_STREAM
    b.eq .Lh2wb_rst_stream
    b .Lh2wb_err
.Lh2wb_rst_stream:
    adr_l x9, h2_frame_header
    ldr w1, [x9, #H2F_STREAM_ID]
    cbz w1, .Lh2wb_loop       // stream 0 is never RST_STREAM'd — keep waiting
    mov x2, x0
    mov x0, x19
    bl h2_send_rst_stream
    b .Lh2wb_loop
.Lh2wb_err:
    // x0 = errno (or H2_ERR_*), carry set
.Lh2wb_done:
    ldp x27, x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
