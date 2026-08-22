#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: reply_status
//
// Description: Send an HTTP error response. Serves error pages from the
//   embedded table (www/err/<code>.html) when available; otherwise
//   replies with the header alone. No filesystem access — all content
//   is embedded at build time. Also dumps the header to stdout for the
//   request log.
//
// Input/Arguments:
//   x0 — http code
//   x1 — boolean: if 0 → go to http1_keepalive_continue (close or
//        continue the connection, per keep_alive_decision), if
//        nonzero → ret
//
// Output/Returns:
//   nothing
//
// Clobbered Registers:
//   x0–x6, x9–x10 (scratch); (x19–x27 saved and restored) when the
//   stack frame is set up (x1 != 0)
//
// Stack Usage:
//   96 bytes when x1 != 0 (stp x29, x30, [sp, #-96]! ...), none when
//   x1 == 0, plus ITOA_BUF_STACK bytes on both paths for the buffer
//   `bl itoa` formats the status code into (itoa writes into the
//   caller's buffer, not a global — see src/util/itoa.S). That scratch
//   is allocated after the conditional prologue and released at
//   sc_epilogue, so it is balanced on the `ret` path and on the
//   `b http1_keepalive_continue` path alike — the latter loops back
//   into child.S's read loop and would otherwise leak a frame's worth
//   of stack per request on a kept-alive connection.
// ─────────────────────────────────────────────────────────────────────

rodata
.align 4
err_dir: .ascii ERR_DIR
.equ err_dir_len, . - err_dir
.align 4
err_ext: .ascii ".html"
.equ err_ext_len, . - err_ext

.bss
.equ err_page_buf_size, 64
.align 4
err_page_buf: .skip err_page_buf_size

.text
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
.global reply_status
reply_status:
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

    // itoa scratch, allocated on both the framed and the frameless
    // path, released at sc_epilogue. sp is stable from here until then
    // (every call below restores it), so `mov x1, sp` at the itoa call
    // site names this buffer.
    sub sp, sp, #ITOA_BUF_STACK

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
    mov x1, sp   // itoa scratch (this frame, not a global)
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
    add sp, sp, #ITOA_BUF_STACK   // release the itoa scratch (both paths)
    cbnz x27, 3f // if x27 (x1) is nonzero, ret instead of continuing the connection
2:
    b http1_keepalive_continue
3:
    ldr x27, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret
