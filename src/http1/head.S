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
// Function Name: head
//
// Description: Handle HEAD — reply with just the header, pretty short
//   n sweet. HEAD sends headers only: body_length = 0. Content-Length
//   still reflects the full resource (what GET would send).
//
// Input/Arguments:
//   none (uses the parsed `request` struct)
//
// Output/Returns:
//   none
//
// Clobbered Registers:
//   x0–x7, x9–x15, x19
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// for HEAD, reply with just the header. pretty short n sweet.
.global head
head:
    bl get_setup // this does basically everything we want.

    // HEAD sends headers only: body_length = 0. Content-Length still
    // reflects the full resource (what GET would send).
    mov x19, x0 // content_size
    adr_l x0, response
    mov x1, #200 // 200 OK
    mov x2, x19 // content_length
    mov x3, #-1 // range start — no range
    mov x4, #-1 // range end
    ldr_l x5, embedded_content // body ptr (not sent)
    mov x6, #0  // body length — headers only
    bl create_response
    bl http1_write_response
    b.cs L500

    // child_end will close the file descriptor
    b child_end

// local trampoline: b.cond/cbz can't reach reply_status across files
L500:
    mov x0, #500
    mov x1, #0
    b reply_status
