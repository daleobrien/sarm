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
// Function Name: h2_send_rst_stream
//
// Description: Send an RST_STREAM frame for a stream error, so the
//   connection can keep serving other streams (RFC 9113 §6.4).
//
// Input/Arguments:
//   x0 — fd, x1 — stream id, x2 — error code
//
// Output/Returns:
//   (none — write failures are ignored)
//
// Clobbered Registers:
//   x0-x4, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!; plus 32 bytes of stack frame
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_send_rst_stream
h2_send_rst_stream:
    str x30, [sp, #-16]!
    sub sp, sp, #32
    // payload length = 4
    mov w3, #4
    strb wzr, [sp, #0]
    strb wzr, [sp, #1]
    strb w3, [sp, #2]
    // type = RST_STREAM, flags = 0
    mov w3, #H2_FRAME_RST_STREAM
    strb w3, [sp, #3]
    strb wzr, [sp, #4]
    // stream id (4 bytes, big-endian)
    lsr w4, w1, #24
    strb w4, [sp, #5]
    lsr w4, w1, #16
    strb w4, [sp, #6]
    lsr w4, w1, #8
    strb w4, [sp, #7]
    strb w1, [sp, #8]
    // error code (4 bytes, big-endian)
    lsr w4, w2, #24
    strb w4, [sp, #9]
    lsr w4, w2, #16
    strb w4, [sp, #10]
    lsr w4, w2, #8
    strb w4, [sp, #11]
    strb w2, [sp, #12]
    mov x1, sp
    mov x2, #13
    bl write_all
    add sp, sp, #32
    ldr x30, [sp], #16
    ret
