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
// Function Name: h2_write_headers
//
// Description: Encode the response struct as a HEADERS frame. The HPACK
//   block carries :status, content-type and content-length — plus
//   content-range for a ranged (206) response and content-encoding:
//   gzip when the embedded asset is gzipped (the HTTP/1 encoder sends
//   the same headers). The block is built into h2_frame_buf right after
//   the 9-byte frame header and the whole frame is written in one
//   write_all, so a partial write can't split the frame.
//
// HPACK notes: :status 200 is a static-table index (0x88); any other
// status is a literal with the indexed name ":status" (static 8).
// content-type / content-length / content-range / content-encoding use
// the literal-with-indexed-name form (static 31 / 28 / 30 / 26) with a
// plain 7-bit-prefix string length. Status 204 carries no content-type
// or content-length, matching the HTTP/1 encoder.
//
// Input/Arguments:
//   x0 — client fd
//   x1 — response struct
//   x2 — stream id
//   x3 — extra frame flags (H2_FLAG_END_STREAM for a bodyless response)
//
// Output/Returns:
//   x0 — 0 on success (carry clear); errno on failure (carry set), or
//     H2_ERR_INTERNAL_ERROR if the header block doesn't fit the buffer
//
// Clobbered Registers:
//   x0-x8, x19-x24 (saved/restored), x30
//
// Stack Usage:
//   64 bytes: stp x19, x20, [sp, #-64]!; stp x21, x22, [sp, #16];
//   stp x23, x24, [sp, #32]; str x30, [sp, #48]
// ─────────────────────────────────────────────────────────────────────

.data
// the content-encoding value the response encoder appends for gzipped
// embedded assets (HTTP/1's encoder sends the same header)
h2_gzip_str:
    .ascii "gzip"
.equ h2_gzip_str_len, . - h2_gzip_str

// h2_cr_buf — scratch for assembling the content-range header value
// ("start-end/total") in h2_write_headers before it is appended to the
// HPACK block with its string length prefix.
.align 3
h2_cr_buf:
    .skip h2_cr_buf_size

.text
.align 2
.global h2_write_headers
h2_write_headers:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    str x30, [sp, #48]
    mov x19, x0             // fd
    mov x20, x1             // response
    mov x21, x2             // stream id
    mov x22, x3             // extra flags
    adr_l x24, h2_frame_buf
    add x24, x24, #H2_WIRE_HEADER_LEN  // block base
    mov x23, #0             // block length

    // ── :status ──
    ldr x0, [x20, #RESP_STATUS]
    cmp x0, #200
    b.ne 1f
    mov w3, #0x88           // indexed header field — :status: 200 (§6.1)
    strb w3, [x24, x23]
    add x23, x23, #1
    b 2f
1:  // any other status — literal with the indexed name ":status" (8)
    mov w3, #0x08
    strb w3, [x24, x23]
    add x23, x23, #1
    ldr x0, [x20, #RESP_STATUS]
    bl itoa                // x0 -> digits, x1 = length
    mov x2, x1
    mov x1, x0
    bl .Lh2wh_append_str
2:
    	// ── content-type / content-length (skipped for 204, like HTTP/1) ──
    	ldr x0, [x20, #RESP_STATUS]
    	cmp x0, #204
    	b.eq .Lh2wh_encoding
    	// content-type — skipped for empty resources (matches HTTP/1). The
    	// static index is 31, which needs the two-octet 4-bit-prefix form:
    	// 0x0f (prefix max) then 31 - 15 = 16
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    	cbz x0, .Lh2wh_length
    	mov w3, #0x0f           // literal without indexing, 4-bit index max
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x10           // 31 - 15 = 16 → content-type
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	ldr x1, [x20, #RESP_CONTENT_TYPE]
    	ldr x2, [x20, #RESP_CONTENT_TYPE_LEN]
    	bl .Lh2wh_append_str
    .Lh2wh_length:
    	// content-length — static index 28: 0x0f then 28 - 15 = 13
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0d           // 28 - 15 = 13 → content-length
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	// the value is end - start + 1 for a ranged response, else the
    	// total resource length — mirroring the HTTP/1 encoder
    	ldr x0, [x20, #RESP_RANGE_START]
    	cmn x0, #1
    	b.eq .Lh2wh_cl_total
    	ldr x1, [x20, #RESP_RANGE_END]
    	sub x0, x1, x0
    	add x0, x0, #1
    	b .Lh2wh_cl_done
    .Lh2wh_cl_total:
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    .Lh2wh_cl_done:
    	bl itoa
    	mov x2, x1
    	mov x1, x0
    	bl .Lh2wh_append_str
    	// ── content-range — only for ranged (206) responses ──
    	// The name is static-table index 30, which needs the two-octet
    	// 4-bit-prefix form: 0x0f then 30 - 15 = 15
    	ldr x0, [x20, #RESP_RANGE_START]
    	cmn x0, #1
    	b.eq .Lh2wh_encoding
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0f           // 30 - 15 = 15 → content-range
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	// the value "start-end/total" is assembled in h2_cr_buf first so
    	// the HPACK string length prefix can be written before the data.
    	// x10 = value base, x11 = cursor — neither is clobbered by itoa
    	// (x0-x5), memcpy (x0-x4) or the ldr_l/str_l macros (x9)
    	adr_l x10, h2_cr_buf
    	mov x11, x10
    	ldr x0, [x20, #RESP_RANGE_START]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov w3, #'-'
    	strb w3, [x11]
    	add x11, x11, #1
    	ldr x0, [x20, #RESP_RANGE_END]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov w3, #'/'
    	strb w3, [x11]
    	add x11, x11, #1
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov x1, x10
    	sub x2, x11, x10
    	bl .Lh2wh_append_str
    .Lh2wh_encoding:
    	// ── content-encoding: gzip — only for gzipped embedded assets. The
    	// static index is 26: 0x0f then 26 - 15 = 11
    	ldr_l x9, resource_type
    	cmp x9, #1              // RES_EMBEDDED
    	b.ne .Lh2wh_build_done
    	ldr_l x9, embedded_gzip
    	cbz x9, .Lh2wh_build_done
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0b           // 26 - 15 = 11 → content-encoding
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	adr_l x1, h2_gzip_str
    	mov x2, #h2_gzip_str_len
    	bl .Lh2wh_append_str
.Lh2wh_build_done:
    // the fixed frame buffer must hold the block behind the 9-byte
    // header — the known content types are far below this
    cmp x23, #(h2_frame_buf_size - H2_WIRE_HEADER_LEN)
    b.hi .Lh2wh_too_big

    // ── frame header (RFC 9113 §4.1) ──
    adr_l x13, h2_frame_buf
    mov w3, w23             // payload length — 24-bit big-endian
    lsr w4, w3, #16
    strb w4, [x13, #0]
    lsr w4, w3, #8
    strb w4, [x13, #1]
    strb w3, [x13, #2]
    mov w3, #H2_FRAME_HEADERS
    strb w3, [x13, #3]
    mov w3, #H2_FLAG_END_HEADERS
    orr w3, w3, w22         // + END_STREAM when the caller asked for it
    strb w3, [x13, #4]
    mov w3, w21             // stream id — 31-bit big-endian
    lsr w4, w3, #24
    strb w4, [x13, #5]
    lsr w4, w3, #16
    strb w4, [x13, #6]
    lsr w4, w3, #8
    strb w4, [x13, #7]
    strb w3, [x13, #8]

    // ── one write — header + block can't be split by a partial write ──
    mov x0, x19
    adr_l x1, h2_frame_buf
    mov x2, #H2_WIRE_HEADER_LEN
    add x2, x2, x23
    bl write_all
    b.cs .Lh2wh_err
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2wh_done
.Lh2wh_too_big:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_INTERNAL_ERROR
    b .Lh2wh_done
.Lh2wh_err:
    // x0 = errno, carry set (write_all failed)
.Lh2wh_done:
    ldr x30, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

// Append the RFC 7541 §5.2 string representation of (x1, length x2) to
// the block at x24+x23, advancing x23. Handles the 7-bit-prefix long
// form, so content types longer than 127 bytes still encode correctly.
// The return address is saved on entry: the memcpy below clobbers x30,
// and this helper is entered via bl and must ret to its caller. Named
// labels only — numeric labels here would hijack the b.cond/b 1f,2f
// branches in h2_write_headers.
//
// Clobbered Registers:
//   x0-x5, x30 (saved/restored)
.Lh2wh_append_str:
    str x30, [sp, #-16]!
    cmp x2, #127
    b.hi .Lh2wh_str_long
    strb w2, [x24, x23]
    add x23, x23, #1
    b .Lh2wh_str_data
.Lh2wh_str_long:
    mov w3, #127
    strb w3, [x24, x23]
    add x23, x23, #1
    sub x3, x2, #127
.Lh2wh_str_long_loop:
    cmp x3, #128
    b.lo .Lh2wh_str_long_done
    and w4, w3, #0x7f
    orr w4, w4, #0x80       // continuation bit
    strb w4, [x24, x23]
    add x23, x23, #1
    lsr x3, x3, #7
    b .Lh2wh_str_long_loop
.Lh2wh_str_long_done:
    strb w3, [x24, x23]
    add x23, x23, #1
.Lh2wh_str_data:
    mov x0, x24
    add x0, x0, x23
    // x1 -> string, x2 = length — memcpy clobbers x0-x4 (and x30), so
    // save the length in x5 (untouched) across the copy
    mov x5, x2
    bl memcpy
    add x23, x23, x5
    ldr x30, [sp], #16
    ret
