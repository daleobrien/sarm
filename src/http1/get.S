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
// Function Name: get
//
// Description: Handle GET. Parse the Range header, build a 200/206
//   response with the correct body window (resolve resource → create
//   response → HTTP/1 encoder) and write it to the client.
//
// Input/Arguments:
//   x0 — header received (request buffer)
//   x1 — length of header
//
// Output/Returns:
//   nothing
//
// Clobbered Registers:
//   x0–x7, x9–x15, x19–x26
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// do the "GET /" stuff."
// input
// x0 -> header received
// x1 -> length of header
//
// returns
// nothing ! :)
.global get
get:
    mov x20, x0
    mov x21, x1

    bl get_setup

    // let's save file length into x19! please? we need to use it but only in
    // this func -- i really don't wanna do more stack shit here...
    mov x19, x0

    mov x0, x20
    mov x1, x21
    bl parse_range
    b.cs Lno_range

    // here there be range
    // empty file has no satisfiable range
    ;cbz x19, L416

    mov x22, x0
    mov x23, x1

    cmn x22, #1
    b.eq Lsuffix_range

    // non-suffix ranges on empty files are unsatisfiable
    cbz x19, L416

    cmn x23, #1
    b.eq Lopen_range

    // if we're here, both are concrete.
    // bytes=X-N
    cmp x22, x19
    b.hs L416

    // if x23 > filesize - 1, set it to filesize - 1 so we don't read other
    // memory.
    sub x1, x19, #1
    cmp x23, x1
    csel x23, x1, x23, hi
    b Lbuild_ranged_header

Lsuffix_range:
    // bytes=-X
    // Range: bytes=-0 is unsatisfiable.
    cbz x23, L416

    // bytes=-X on an empty file should be 200, not 206. just serve the whole
    // file :)
    cbz x19, Lno_range

    // if range is less than file length, handle it at 1f
    cmp x23, x19
    b.lo 1f

    // if range is bigger than or equal to the file size, just return the
    // whole file.
    mov x22, #0
    sub x23, x19, #1
    b Lbuild_ranged_header

1:
    // Range: bytes=-50 means file_len - 50
    sub x22, x19, x23 // start = len - range
    sub x23, x19, #1 // end = fiolesize - 1 (inclusive)
    b Lbuild_ranged_header

Lopen_range:
    // bytes=X-
    // if X >= filesize, it's not satisfiable :(
    cmp x22, x19
    b.hs L416

    // if it's bytes=N-, start range remains unchanged, but end becomes
    // file_len - 1
    sub x23, x19, #1
    b Lbuild_ranged_header

Lno_range:
    // just pretend start = 0, end = file_length.
    mov x22, #0
    sub x23, x19, #1

    // response metadata: 200 OK, no range
    mov x24, #200
    mov x25, #-1 // range start
    mov x26, #-1 // range end
    b Lcreate_response

Lbuild_ranged_header:
    // if start range >= filesize, that's unsatisfiable
    cmp x22, x19
    b.hs L416

    // response metadata: 206 Partial Content, with the range
    mov x24, #206
    mov x25, x22 // range start
    mov x26, x23 // range end
    // fallthrough

Lcreate_response:
    // resolve resource → create response → HTTP/1 encoder.
    // x19 = content_size, x22/x23 = body window, x24 = status,
    // x25/x26 = response range (-1/-1 = no range)
    adr_l x0, response
    mov x1, x24 // status
    mov x2, x19 // content_length
    mov x3, x25 // range_start
    mov x4, x26 // range_end
    ldr_l x5, embedded_content
    add x5, x5, x22 // body = content + start
    sub x6, x23, x22
    add x6, x6, #1  // body_length = end - start + 1
    bl create_response
    bl http1_write_response
    b.cs L500
    b child_end

// local trampolines: b.cond/cbz can't reach reply_status across files
L416:
    mov x0, #416
    mov x1, #0
    b reply_status
L500:
    mov x0, #500
    mov x1, #0
    b reply_status
