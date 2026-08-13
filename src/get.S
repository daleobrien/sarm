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

#include "defs.S"

.global get
.global head
.global create_response
.global response_code

// ═══════════════════════════════════════════════════════════════
//  Stage 5: Register Convention for the GET hot path
//
//  Callee-saved registers (preserved across function calls):
//    x19  — content_size (file length)
//    x20  — request header buffer pointer
//    x21  — request header length
//    x22  — range start offset
//    x23  — range end offset
//    x24  — response status (200/206)
//    x25  — response range_start (-1 = no range)
//    x26  — response range_end (-1 = no range)
//
//  Caller-saved / scratch registers (may be clobbered by calls):
//    x0–x7, x9–x15, x16–x18  — general scratch
//
//  Global memory is only accessed via ldr_l/str_l macros
//  when a value cannot be kept in a callee-saved register.
//  Key globals accessed in the hot path:
//    embedded_content → copied into the response struct before writev
//    response         → filled by create_response, read by the encoder
// ═══════════════════════════════════════════════════════════════

.text
.align 2

// fill a protocol-neutral response struct from the resolved resource
// globals (embedded_content, embedded_ct, ...) and explicit arguments.
//
// This is the "create response" step: resolve resource → create response
// → HTTP/1 encoder. The encoder (http1_write_response in header.S) — and
// a future HTTP/2 encoder — consume the same struct.
//
// input
// x0 -> response struct ptr
// x1 -> status code
// x2 -> content_length (total resource length)
// x3 -> range_start (-1 = no range)
// x4 -> range_end   (-1 = no range)
// x5 -> body ptr
// x6 -> body length
//
// output
// x0 -> response struct ptr (unchanged)
//
// clobbers x0–x6, x9–x14
create_response:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov x19, x0

    str x1, [x19, #RESP_STATUS]
    str x2, [x19, #RESP_CONTENT_LENGTH]
    str x3, [x19, #RESP_RANGE_START]
    str x4, [x19, #RESP_RANGE_END]
    str x5, [x19, #RESP_BODY]
    str x6, [x19, #RESP_BODY_LENGTH]

    // record the status for the request timing log
    str_l x1, response_code

    // content type: embedded_ct if the resource provides one, else derive
    // it from the request path (filesystem fallback).
    ldr_l x0, embedded_ct
    cbz x0, 1f
    ldr_l x1, embedded_ct_len
    b 2f
1:
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl get_filetype
2:
    str x0, [x19, #RESP_CONTENT_TYPE]
    str x1, [x19, #RESP_CONTENT_TYPE_LEN]

    mov x0, x19
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret


// setup for the "GET" and "HEAD" methods. resolves the resource (embedded
// table lookup) and fills the embedded_* globals the response builders
// read.
// none, uses .bss data
//
// output
// x0 -> length of file
// x1 -> file type, w1 can be S_IFREG or S_IFDIR
// NOTE this function opens a file and doesn't close it -- it saves the open
// file descriptor in file_des, which is in data.S's .data. child_end should
// close it, but be aware!
get_setup:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]

    // the request was already parsed into the `request` struct by
    // parse_request (ymawky.S dispatch) — read the path from there.
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]

    ldrb w1, [x0]
    cmp w1, #'*'
    b.eq L400

    // try embedded content lookup first
    str_l xzr, resource_type, x10
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cc Lembedded_found

    // not found in embedded table — 404
    b L404

Lembedded_found:
    // x0 = content_ptr, x1 = content_size, x2 = ct_ptr, x3 = ct_len, x4 = gzip, x5 = etag, x6 = etag_len
    str_l x0, embedded_content
    str_l x2, embedded_ct
    str_l x3, embedded_ct_len
    str_l x4, embedded_gzip
    str_l x5, embedded_etag
    str_l x6, embedded_etag_len
    mov x9, #1
    str_l x9, resource_type, x10
    mov x9, #-1
    str_l x9, file_des

    mov x0, x1   // return content_size
    mov w1, #S_IFREG

    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

// for HEAD, reply with just the header. pretty short n sweet.
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


// do the "GET /" stuff."
// input
// x0 -> header received
// x1 -> length of header
//
// returns
// nothing ! :)
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


// trampolines for conditional branches to reply_* / handle_fs_error in other
// files (b.cond / cbz can't reach across files; unconditional b can).
L400:
    mov x0, #400
    mov x1, #0
    b reply_status
L404:
    mov x0, #404
    mov x1, #0
    b reply_status
L416:
    mov x0, #416
    mov x1, #0
    b reply_status
L500:
    mov x0, #500
    mov x1, #0
    b reply_status
