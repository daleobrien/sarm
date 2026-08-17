#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: http1_write_response
//
// Description: Encode a protocol-neutral response struct as an HTTP/1.1
//   response and write it (header + body) to the client socket. This is
//   the HTTP/1 half of the protocol encoder split: handlers fill a
//   `response` struct (resolve resource → create response) and this
//   turns it into wire bytes. A future HTTP/2 encoder consumes the same
//   struct. Builds the status line (via find_http_code), then
//   Content-Length/Content-Range/Content-Type, plus Content-Encoding
//   and ETag for embedded resources, into header_buf and sends
//   header + body with a single writev.
//
// Input/Arguments:
//   x0 — response struct pointer
//
// Output/Returns:
//   carry clear = success, carry set = header didn't fit in header_buf
//   (the caller should reply 500)
//
// Clobbered Registers:
//   x0–x5, x9–x11, x13–x14, x16 (x19–x24 saved and restored)
//
// Stack Usage:
//   64 bytes frame (stp x29, x30, [sp, #-64]! ...) plus 32 transient
//   bytes for the writev iovec array
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
header_content_length: .ascii "\r\nContent-Length: "
.equ header_content_length_len, . - header_content_length

.align 4
header_content_type: .ascii "\r\nContent-Type: "
.equ header_content_type_len, . - header_content_type

.align 4
header_content_range: .ascii "\r\nContent-Range: bytes "
.equ header_content_range_len, . - header_content_range

.align 4
header_content_encoding: .ascii "\r\nContent-Encoding: gzip"
.equ header_content_encoding_len, . - header_content_encoding

.align 4
header_etag: .ascii "\r\nETag: "
.equ header_etag_len, . - header_etag

.align 4
header_tail:
    .ascii "\r\nConnection: close\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nAllow: GET, HEAD, OPTIONS\r\nAccept-Ranges: bytes\r\nServer: sarm\r\n\r\n"
.equ header_tail_len, . - header_tail
    .align 4 // pad the string block to a 16-byte multiple

// the 500 status-line string lives in find_http_code.S; this copies its
// length here so `mov x2, #header_500_len` can be an immediate.
.equ header_500_len, 34 // matches find_http_code.S

// header_buf lives in data.S; this copies its size here so the bounds
// checks (`cb hi, x14, header_buf_size, ...`) can use an immediate.
.equ header_buf_size, RESPONSE_HEADER_SIZE // matches data.S

.text
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
.global http1_write_response
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
