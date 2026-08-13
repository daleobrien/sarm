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
// Function Name: h2_handle_ping
//
// Description: PING is a connection liveness probe (RFC 9113 §6.7). The
//   payload is exactly 8 opaque octets — any other length is a
//   FRAME_SIZE_ERROR connection error — and the frame is
//   connection-scoped: a stream id other than 0 is a PROTOCOL_ERROR. A
//   PING without the ACK flag is answered with a PING ACK carrying the
//   identical 8 octets (§6.7: "an endpoint MUST NOT respond to PING
//   frames containing this flag" — so an ACK is never answered). The
//   ACK goes out over the connection's client fd, which the connection
//   loop stores in H2C_FD; a write failure is ignored (the connection
//   is dead anyway).
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
//   x0-x4, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!; plus 32 bytes of stack frame
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_ping
h2_handle_ping:
    str x30, [sp, #-16]!   // save the return address
    // exactly 8 payload octets (§6.7)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #8
    b.ne .Lh2ping_size_error
    // connection-scoped — stream id must be 0 (§6.7)
    ldr w3, [x0, #H2F_STREAM_ID]
    cbnz w3, .Lh2ping_protocol_error
    // an ACK is never answered (§6.7)
    ldr w3, [x0, #H2F_FLAGS]
    tst w3, #H2_FLAG_ACK
    b.ne .Lh2ping_ok
    // build the ACK frame on the stack: 9-byte header + the same 8 octets
    sub sp, sp, #32
    mov x3, x1              // payload — survives the header build below
    mov w4, #8
    strb wzr, [sp, #0]
    strb wzr, [sp, #1]
    strb w4, [sp, #2]
    mov w4, #H2_FRAME_PING
    strb w4, [sp, #3]
    mov w4, #H2_FLAG_ACK
    strb w4, [sp, #4]
    strb wzr, [sp, #5]
    strb wzr, [sp, #6]
    strb wzr, [sp, #7]
    strb wzr, [sp, #8]
    ldr x4, [x3]            // the 8 opaque octets, echoed verbatim
    str x4, [sp, #9]
    ldr x0, [x2, #H2C_FD]   // the connection's client fd
    mov x1, sp
    mov x2, #17             // header + payload, one write
    bl write_all
    add sp, sp, #32
.Lh2ping_ok:
    ldr x30, [sp], #16
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ret
.Lh2ping_protocol_error:
    ldr x30, [sp], #16
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2ping_size_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret
