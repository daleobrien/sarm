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
// Function Name: h2_handle_rst_stream
//
// Description: Abort a stream (§6.4). The payload is one 32-bit error
//   code; the stream moves to CLOSED. RST_STREAM on an idle stream, on
//   stream 0, or with an even (server-initiated) id is a PROTOCOL_ERROR
//   connection error. The error code itself is not recorded anywhere yet.
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
//   x0-x4, x9, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_rst_stream
h2_handle_rst_stream:
    str x30, [sp, #-16]!   // save the return address
    // exactly 4 payload bytes — one 32-bit error code (§6.4)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #4
    b.ne .Lh2_rst_size_error
    ldr w4, [x0, #H2F_STREAM_ID]
    cbz w4, .Lh2_rst_protocol_error
    tst w4, #1
    b.eq .Lh2_rst_protocol_error
    mov x0, x4
    bl h2_stream_find
    cbz x0, .Lh2_rst_protocol_error
    mov x1, #H2_EVENT_RECV_RST_STREAM
    bl h2_stream_event
    b.cs .Lh2_stream_error
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
.Lh2_rst_protocol_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2_rst_size_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret

// Shared error exit for the stream handlers: every handler saved x30 at
// entry the same way, so pop it back and pass the error through
// (x0 holds the error, carry is set). Duplicated per function file.
.Lh2_stream_error:
    ldr x30, [sp], #16
    ret
