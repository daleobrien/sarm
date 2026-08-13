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
// Function Name: h2_hpack_decode_block
//
// Description: Decode a complete HPACK header block (a HEADERS payload)
//   into the fixed h2_hpack_fields array. Each field is one
//   h2_hpack_decode_field call; size updates are skipped. The
//   consumption of every representation is checked against the block
//   length, so a truncated block is a decoding error instead of being
//   partially accepted, and the fixed output area bounds the field
//   count — a block that needs more than H2_HPACK_MAX_FIELDS is also a
//   decoding error. On error the fields decoded so far remain readable,
//   but the caller must treat the whole connection as failed
//   (COMPRESSION_ERROR is a connection error, RFC 9113 §4.3).
//
// Input/Arguments:
//   x0 — the block (HEADERS payload)
//   x1 — block length in bytes
//
// Output/Returns:
//   x0 — field count (h2_hpack_fields[0..count-1])
//   (carry clear = success / carry set = failure,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x9, x19-x22, x30 (x19-x22/x30 saved and restored)
//
// Stack Usage:
//   48 bytes: stp x19, x30, [sp, #-48]!, stp x20, x21, [sp, #16],
//     str x22, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_decode_block
h2_hpack_decode_block:
    stp x19, x30, [sp, #-48]!
    stp x20, x21, [sp, #16]
    str x22, [sp, #32]
    mov x19, x0                 // cursor
    mov x21, x1                 // bytes remaining
    adr_l x22, h2_hpack_fields
    mov x20, #0                 // field count
    // a fresh Huffman output area for this block
    adr_l x9, h2_hpack_str_off
    str xzr, [x9]
.Lhpack_block_loop:
    cbz x21, .Lhpack_block_done
    mov x0, x19
    bl h2_hpack_decode_field
    b.cs .Lhpack_block_err
    sub x7, x0, x19             // bytes this representation consumed
    cmp x7, x21
    b.hi .Lhpack_block_bad      // more than remained — truncated block
    sub x21, x21, x7            // remaining -= consumed
    mov x19, x0                 // cursor = next
    cbz x1, .Lhpack_block_loop  // size update — not a header field
    cmp x20, #H2_HPACK_MAX_FIELDS
    b.hs .Lhpack_block_bad      // fixed decode area is full
    str x1, [x22, #H2_HPACK_FIELD_NAME_PTR]
    str x2, [x22, #H2_HPACK_FIELD_NAME_LEN]
    str x3, [x22, #H2_HPACK_FIELD_VALUE_PTR]
    str x4, [x22, #H2_HPACK_FIELD_VALUE_LEN]
    add x22, x22, #H2_HPACK_FIELD_SIZE
    add x20, x20, #1
    b .Lhpack_block_loop
.Lhpack_block_done:
    mov x0, x20
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    cmn xzr, xzr                // success — carry clear
    ret
.Lhpack_block_bad:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhpack_block_err:
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    ret                         // carry + error already set
