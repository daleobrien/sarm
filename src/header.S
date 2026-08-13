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

.global handle_fs_error
.global http1_write_response
.global reply_status
.global header_buf
.global response_code

.data
header_200: .ascii "HTTP/1.1 200 OK"
.equ header_200_len, . - header_200

header_201: .ascii "HTTP/1.1 201 Created"
.equ header_201_len, . - header_201

header_204: .ascii "HTTP/1.1 204 No Content"
.equ header_204_len, . - header_204

header_206: .ascii "HTTP/1.1 206 Partial Content"
.equ header_206_len, . - header_206

header_400: .ascii "HTTP/1.1 400 Bad Request"
.equ header_400_len, . - header_400

header_403: .ascii "HTTP/1.1 403 Forbidden"
.equ header_403_len, . - header_403

header_404: .ascii "HTTP/1.1 404 Not Found"
.equ header_404_len, . - header_404

header_408: .ascii "HTTP/1.1 408 Request Timeout"
.equ header_408_len, . - header_408

header_409: .ascii "HTTP/1.1 409 Conflict"
.equ header_409_len, . - header_409

header_411: .ascii "HTTP/1.1 411 Length Required"
.equ header_411_len, . - header_411

header_413: .ascii "HTTP/1.1 413 Content Too Large"
.equ header_413_len, . - header_413

header_414: .ascii "HTTP/1.1 414 URI Too Long"
.equ header_414_len, . - header_414

header_416: .ascii "HTTP/1.1 416 Range Not Satisfiable"
.equ header_416_len, . - header_416

header_418: .ascii "HTTP/1.1 418 I'm a teapot"
.equ header_418_len, . - header_418

header_431: .ascii "HTTP/1.1 431 Request Header Fields Too Large"
.equ header_431_len, . - header_431

header_500: .ascii "HTTP/1.1 500 Internal Server Error"
.equ header_500_len, . - header_500

header_501: .ascii "HTTP/1.1 501 Not Implemented"
.equ header_501_len, . - header_501

header_502: .ascii "HTTP/1.1 502 Bad Gateway"
.equ header_502_len, . - header_502

header_503: .ascii "HTTP/1.1 503 Service Unavailable"
.equ header_503_len, . - header_503

header_505: .ascii "HTTP/1.1 505 HTTP Version Not Supported"
.equ header_505_len, . - header_505

header_507: .ascii "HTTP/1.1 507 Insufficient Storage"
.equ header_507_len, . - header_507

header_content_length: .ascii "\r\nContent-Length: "
.equ header_content_length_len, . - header_content_length

header_content_type: .ascii "\r\nContent-Type: "
.equ header_content_type_len, . - header_content_type

header_content_range: .ascii "\r\nContent-Range: bytes "
.equ header_content_range_len, . - header_content_range

header_content_encoding: .ascii "\r\nContent-Encoding: gzip"
.equ header_content_encoding_len, . - header_content_encoding

header_etag: .ascii "\r\nETag: "
.equ header_etag_len, . - header_etag

header_tail:
    .ascii "\r\nConnection: close\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nAllow: GET, HEAD, OPTIONS\r\nAccept-Ranges: bytes\r\nServer: ymawky\r\n\r\n"
.equ header_tail_len, . - header_tail

err_dir: .ascii ERR_DIR
.equ err_dir_len, . - err_dir
err_ext: .ascii ".html"
.equ err_ext_len, . - err_ext

arrows_out: .asciz "\n\n>>>\n"
.equ arrows_out_len, . - arrows_out

.align 3
// lookup table, like the MIME one, for headers. 24 bytes per entry, 8 bytes
// per each element
status_table:
    //    status, str pointer, length
    .quad 200,    header_200,  header_200_len
    .quad 201,    header_201,  header_201_len
    .quad 204,    header_204,  header_204_len
    .quad 206,    header_206,  header_206_len
    .quad 400,    header_400,  header_400_len
    .quad 403,    header_403,  header_403_len
    .quad 404,    header_404,  header_404_len
    .quad 408,    header_408,  header_408_len
    .quad 409,    header_409,  header_409_len
    .quad 411,    header_411,  header_411_len
    .quad 413,    header_413,  header_413_len
    .quad 414,    header_414,  header_414_len
    .quad 416,    header_416,  header_416_len
    .quad 418,    header_418,  header_418_len
    .quad 431,    header_431,  header_431_len
    .quad 500,    header_500,  header_500_len
    .quad 501,    header_501,  header_501_len
    .quad 502,    header_502,  header_502_len
    .quad 503,    header_503,  header_503_len
    .quad 505,    header_505,  header_505_len
    .quad 507,    header_507,  header_507_len

    .quad 0 // mark the end

.bss
.equ err_page_buf_size, 64
.align 3
err_page_buf: .skip err_page_buf_size
.align 3
.equ header_buf_size, RESPONSE_HEADER_SIZE
header_buf:   .skip header_buf_size
;header_len:   .skip 8

.text
.align 2
// input
// x0 -> status code
//
// returns
// x1 -> string pointer
// x2 -> length
find_http_code:
    adr_l x3, status_table
1:
    // load the first element
    ldr x4, [x3]
    cbz x4, 3f

    // found the matching entry
    cmp x4, x0
    b.eq 2f

    // jump to the next entry
    add x3, x3, #24
    b 1b

2:
    ldr x1, [x3, #8]
    ldr x2, [x3, #16]
    ret

3:
    mov x1, #0
    mov x2, #0
    ret

.align 2
// Encode a protocol-neutral response struct as an HTTP/1.1 response and
// write it (header + body) to the client socket.
//
// This is the HTTP/1 half of the protocol encoder split: handlers fill a
// `response` struct (resolve resource → create response) and this turns
// it into wire bytes. A future HTTP/2 encoder consumes the same struct.
//
// input
// x0 -> response struct pointer
//
// output
// carry clear on success, carry set if the header didn't fit in
// header_buf (the caller should reply 500).
//
// clobbers x0–x7, x9–x15
http1_write_response:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    mov x19, x0 // response pointer

    adr_l x13, header_buf
    mov x14, #0 // counter of bytes written to header_buf

    // ── status line ──
    ldr x0, [x19, #RESP_STATUS]
    bl find_http_code
    cmp x1, #0
    b.ne 1f

    // if we're here, find_http_code returned 0, which is... odd.
    // let's actually reply with 500, since that shouldn't happen - it means
    // we were given an unknown HTTP status, which is our fault.
    adr_l x1, header_500
    mov x2, #header_500_len

1:
    mov x0, x13
    // x1 is set by find_http_code
    // so is x2!
    // make sure we don't write past header_buf's memory!
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0 // store header_buf + offset, memcpy increments the pointer

    b Lhw_content_length

Lhw_content_length:
    ldr x24, [x19, #RESP_STATUS]
    // we don't want to write a content-length or content-type on a 204.
    cmp x24, #204
    b.eq Lheader_tail

    mov x2, header_content_length_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big

    mov x0, x13
    adr_l x1, header_content_length
    // x2 is already set
    bl memcpy
    mov x13, x0

    // content-length value: end - start + 1 for a ranged response, else
    // the total content length.
    ldr x22, [x19, #RESP_RANGE_START]
    cmn x22, #1
    b.eq 1f

    ldr x23, [x19, #RESP_RANGE_END]
    sub x0, x23, x22
    add x0, x0, #1
    b 2f

1:
    ldr x0, [x19, #RESP_CONTENT_LENGTH]

2:
    bl itoa
    // copy content-length string into header_buf
    mov x2, x1  // content_length_len (length of string)
    mov x1, x0  // content_length_str
    mov x0, x13 // header_buf + offset
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // skip all this stuff for no range
    cmn x22, #1
    b.eq Lhw_content_type

    // 206 path
    // write Content-Range: bytes
    adr_l x1, header_content_range
    mov x2, header_content_range_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // start range
    mov x0, x22
    bl itoa

    mov x2, x1
    mov x1, x0
    mov x0, x13
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // -
    add x14, x14, #1
    cb hi, x14, header_buf_size, Lheader_too_big
    mov w0, #'-'
    strb w0, [x13]
    add x13, x13, #1

    // end range
    mov x0, x23
    bl itoa

    mov x2, x1
    mov x1, x0
    mov x0, x13
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // /
    add x14, x14, #1
    cb hi, x14, header_buf_size, Lheader_too_big
    mov w0, #'/'
    strb w0, [x13]
    add x13, x13, #1

    // total size
    ldr x0, [x19, #RESP_CONTENT_LENGTH]
    bl itoa

    mov x2, x1  // content_length_len (length of string)
    mov x1, x0  // content_length_str
    mov x0, x13 // header_buf + offset
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

Lhw_content_type:
    // if it's an empty resource, don't bother with Content-Type.
    ldr x0, [x19, #RESP_CONTENT_LENGTH]
    cbz x0, Lheader_tail

    // copy "\r\nContent-Type:" to buffer
    mov x0, x13 // destination, header_buf + offset
    adr_l x1, header_content_type
    mov x2, header_content_type_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // write the content-type from the response struct
    ldr x1, [x19, #RESP_CONTENT_TYPE]
    ldr x2, [x19, #RESP_CONTENT_TYPE_LEN]
    mov x0, x13 // destination, header_buf
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

Lheader_tail:
    // Check if embedded content is gzipped — add Content-Encoding header
    ldr_l x9, resource_type
    cmp x9, #1   // RES_EMBEDDED
    b.ne 1f
    ldr_l x9, embedded_gzip
    cbz x9, 1f

    // write "\r\nContent-Encoding: gzip"
    mov x0, x13 // destination, header_buf + offset
    adr_l x1, header_content_encoding
    mov x2, header_content_encoding_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

1:
    // Check if embedded content has a precomputed ETag
    ldr_l x9, resource_type
    cmp x9, #1   // RES_EMBEDDED
    b.ne 2f
    ldr_l x10, embedded_etag
    cbz x10, 2f
    ldr_l x11, embedded_etag_len
    cbz x11, 2f

    // write "\r\nETag: "
    mov x0, x13 // destination, header_buf + offset
    adr_l x1, header_etag
    mov x2, header_etag_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy
    mov x13, x0

    // write the ETag value
    mov x1, x10
    mov x2, x11
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    mov x0, x13
    bl memcpy
    mov x13, x0

2:
    // write the \r\n\r\n
    mov x0, x13 // destination, header_buf + offset
    adr_l x1, header_tail
    mov x2, header_tail_len
    add x14, x14, x2
    cb hi, x14, header_buf_size, Lheader_too_big
    bl memcpy

    b Lhw_done
Lheader_too_big:
    str_l xzr, header_len
    cmp xzr, xzr // set carry
    b Lhw_epilogue

Lhw_done:
    str_l x14, header_len

    // ── write header + body to the client ──
    // Zero-copy response: header_buf + body via one writev syscall.
    // Set up 2 iovecs on the stack (16 bytes each = 32 bytes total).
    sub sp, sp, #32

    adr_l x0, header_buf
    str x0, [sp, #0]       // iov[0].iov_base = header_buf
    ldr_l x0, header_len
    str x0, [sp, #8]       // iov[0].iov_len  = header_len

    ldr x0, [x19, #RESP_BODY_LENGTH]
    cbz x0, 1f              // no body? only send the header

    ldr x1, [x19, #RESP_BODY]
    str x1, [sp, #16]      // iov[1].iov_base = response body
    str x0, [sp, #24]      // iov[1].iov_len  = body_length
    mov x2, #2             // 2 iovecs
    b 2f

1:
    mov x2, #1             // 1 iovec (header only, empty body)

2:
    ldr_l x0, clientfd
    mov x1, sp              // pointer to iovec array
    SCWINUM SYS_writev
    SCWISVC
    SCERR
    add sp, sp, #32
    // write errors are ignored — child_end closes the connection anyway.
    // only a header that didn't fit reports failure (carry set above).
    cmn xzr, xzr           // clear carry
    b Lhw_epilogue

Lhw_epilogue:
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.align 2
// input
// x0 -> http code
// x1 -> boolean, if 0 -> go to child_end; if nonzero -> ret
//
// returns
// nothing
//
// Serves error pages from the embedded table (www/err/<code>.html).
// No filesystem access — all content is embedded at build time.
reply_status:
    // save status code for request timing log
    str_l x0, response_code

    cbz x1, 1f // skip the stack pushing shit if we're just gonna b child_end

    stp x29, x30, [sp, #-96]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    str x27, [sp, #80]
1:
    mov x19, x0

    // this is used to check if we should "b child_end", or "ret".
    mov x27, x1

    // make sure the error code is valid: not an error below 400, and we don't
    // support anything above 507 (currently).
    cmp x0, #400
    b.lo sc_err    // x0 < 400 → not an error code, just write the header
    cmp x0, #507
    b.hi sc_err    // x0 > 507 → unsupported error code, just write header
    // fall through to 1f: 400–507, valid error

1:
    mov x20, #0 // how many bytes have we written to err_page_buf?
    mov x26, err_page_buf_size
    // do some bounds checks
    mov x21, #err_dir_len
    add x20, x20, x21
    cmp x20, x26

    b.hi sc_err

    // copy "www/err/" or whatever err_dir is set to, to err_page_buf
    adr_l x0, err_page_buf
    adr_l x1, err_dir
    mov x2, #err_dir_len
    bl memcpy
    mov x22, x0 // save pointer with offset from memcpy

    // itoa the error code
    mov x0, x19
    bl itoa

    // bounds check
    add x20, x20, x1 // x1 is length of itoa'd string from itoa
    cmp x20, x26

    b.hi sc_err

    // copy the itoa'd shit
    mov x2, x1
    mov x1, x0
    mov x0, x22
    bl memcpy
    mov x22, x0 // save it again

    // one last bounds check. gotta copy the ".html".
    mov x21, err_ext_len
    add x20, x20, x21
    cmp x20, x26

    b.hi sc_err

    // now copy it
    mov x0, x22
    adr_l x1, err_ext
    mov x2, err_ext_len
    bl memcpy

    // Null-terminate the assembled path
    strb wzr, [x0]

    // Now err_page_buf is "www/err/<code>.html". Look it up in the embedded
    // table — no filesystem open(), stat(), mmap(), or munmap().
    str_l xzr, resource_type
    adr_l x0, err_page_buf
    mov x1, x20   // path length
    bl lookup_embedded
    b.cs sc_err   // not found in embedded table → header only

    // Found in embedded table — x0=content, x1=size, x2=ct, x3=ct_len,
    // x4=gzip, x5=etag, x6=etag_len
    str_l x0, embedded_content
    str_l x2, embedded_ct
    str_l x3, embedded_ct_len
    str_l x4, embedded_gzip
    str_l x5, embedded_etag
    str_l x6, embedded_etag_len
    mov x9, #1
    str_l x9, resource_type, x10

    mov x24, x1  // save content_size
    mov x25, x0  // save content_ptr

    // Build the response and hand it to the HTTP/1 encoder.
    adr_l x0, response
    mov x1, x19  // status
    mov x2, x24  // content_length
    mov x3, #-1  // range start
    mov x4, #-1  // range end
    mov x5, x25  // body ptr
    mov x6, x24  // body length
    bl create_response
    bl http1_write_response
    b sc_epilogue

sc_err:
    // if something went wrong during this function, just send the header by
    // itself -- with no body. no custom pages if embedded lookup failed.
    str_l xzr, resource_type
    adr_l x0, response
    mov x1, x19  // status
    mov x2, #0   // content_length
    mov x3, #-1  // range start
    mov x4, #-1  // range end
    mov x5, #0   // body ptr
    mov x6, #0   // body length
    bl create_response
    bl http1_write_response

sc_epilogue:
    // write the \n\n>>>\n to indicate data we're sending
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, arrows_out
    mov x2, arrows_out_len
    SCWISVC
    SCERR

    // write the header to stdout
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, header_buf
    ldr_l x2, header_len
    SCWISVC
    SCERR

    cbnz x27, 3f // if x27 (x1) is nonzero, ret instead of branching to child_end
2:
    b child_end
3:
    ldr x27, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

    

// handler function for fstat64() failing. route to the proper HTTP reponse
// based on errno.
// TODO this should probably go in file.S?
// input
// x0 -> errno
//
// output
// none, branches to reply_status and quits.
handle_fs_error:
    cb eq, x0, #ENAMETOOLONG, L414
    cb eq, x0, #EINVAL, L400
    // 403 since it's caused by O_NOFOLLOW_ANY most likely. if we ever allow
    // symlinks, note that this should be 508.
    cb eq, x0, #ELOOP, L403
    cb eq, x0, #ENOTDIR, L404
    cb eq, x0, #ENOENT, L404
    cb eq, x0, #EACCES, L403
    cb eq, x0, #EPERM, L403
    cb eq, x0, #EROFS, L403
    cb eq, x0, #EISDIR, L403
    cb eq, x0, #EFAULT, L500
    cb eq, x0, #EBUSY, L409
    cb eq, x0, #ENOTEMPTY, L409
    cb eq, x0, #ENOSPC, L507
    cb eq, x0, #EDQUOT, L507
    cb eq, x0, #EFBIG, L413

    b L500

L400:
    mov x0, #400
    b reply_status
L403:
    mov x0, #403
    b reply_status
L404:
    mov x0, #404
    b reply_status
L409:
    mov x0, #409
    b reply_status
L413:
    mov x0, #413
    b reply_status
L414:
    mov x0, #414
    b reply_status
L500:
    mov x0, #500
    b reply_status
L507:
    mov x0, #507
    b reply_status
