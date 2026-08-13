#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: parse_request
//
// Description: Parse a raw HTTP/1 request into the protocol-neutral
//   `request` struct (the seam HTTP/2 will later share). Detects the
//   method, then for GET/HEAD/OPTIONS parses the path and query and
//   fills REQ_PATH, REQ_QUERY and REQ_AUTHORITY (the Host header value).
//   BREW/unknown methods do NOT get their path parsed — the dispatch
//   replies 418/501, matching the old behavior of rejecting those
//   methods before any path handling.
//
// Input/Arguments:
//   x0 -> request buffer (raw header, e.g. "GET / HTTP/1.1\r\n...")
//   x1 -> header length (one byte past the final \r\n\r\n)
//
// Output/Returns:
//   the global `request` struct is filled:
//     REQ_METHOD      = GET_ID / HEAD_ID / OPTIONS_ID / BREW_ID / UNKNOWN_ID
//     REQ_PATH        = docroot-prefixed, percent-decoded path string
//     REQ_PATH_LENGTH
//     REQ_QUERY       = query string, or 0
//     REQ_QUERY_LENGTH
//     REQ_AUTHORITY   = Host header value, or 0 if absent
//     REQ_STREAM_ID   = 0  (HTTP/1 has no streams)
//   carry clear = success (even for unknown methods), carry set = parse
//   failed (caller replies 400)
//
// Clobbered Registers:
//   x0-x15; preserves x19-x28 (x19-x27 saved and restored)
//
// Stack Usage:
//   80 bytes: stp x29, x30, [sp, #-80]!
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
host_match_str: .ascii "Host"
.equ host_match_len, 4
.align 4

.text
.align 2
.global parse_request
parse_request:
    stp x29, x30, [sp, #-80]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    str x27, [sp, #72]

    mov x19, x0 // request buffer
    mov x20, x1 // header length

    adr_l x23, request

    // ── method detection (direct word compares; see dispatch in ymawky.S) ──
    ldr w5, [x19]              // first 4 bytes of request

    // GET ?
    movz w6, #0x4547           // "GE" (LE word)
    movk w6, #0x2054, lsl #16  // "T "
    cmp w5, w6
    b.eq Lreq_get

    // HEAD ?  (compare first 4 bytes, then 5th byte)
    movz w6, #0x4548           // "HE"
    movk w6, #0x4441, lsl #16  // "AD"
    cmp w5, w6
    b.ne 1f
    ldrb w7, [x19, #4]
    cmp w7, #' '
    b.eq Lreq_head
1:
    // OPTIONS ?  (8 bytes → single 64-bit LDR + compare)
    ldr x5, [x19]              // first 8 bytes of request
    movz x6, #0x504F           // "OP"
    movk x6, #0x4954, lsl #16  // "TI"
    movk x6, #0x4E4F, lsl #32  // "ON"
    movk x6, #0x2053, lsl #48  // "S "
    cmp x5, x6
    b.eq Lreq_options

    // BREW ?  (compare first 4 bytes, then 5th byte)
    ldr w5, [x19]
    movz w6, #0x5242           // "BR"
    movk w6, #0x5745, lsl #16  // "EW"
    cmp w5, w6
    b.ne 1f
    ldrb w7, [x19, #4]
    cmp w7, #' '
    b.eq Lreq_brew
1:
    // none of the above — unknown method
    mov x21, UNKNOWN_ID
    b Lreq_method_done
Lreq_get:
    mov x21, GET_ID
    mov x22, #1 // default to index.html
    b Lreq_method_done
Lreq_head:
    mov x21, HEAD_ID
    mov x22, #1 // default to index.html
    b Lreq_method_done
Lreq_options:
    mov x21, OPTIONS_ID
    mov x22, #0 // no default file for OPTIONS
    b Lreq_method_done
Lreq_brew:
    mov x21, BREW_ID
Lreq_method_done:
    str x21, [x23, #REQ_METHOD]
    str xzr, [x23, #REQ_STREAM_ID] // HTTP/1 is never on a stream

    // BREW/unknown methods are answered 418/501 by the dispatch without
    // any path handling — same as the pre-Stage-1 flow.
    cmp x21, #BREW_ID
    b.eq Lreq_skip_parse
    cmp x21, #UNKNOWN_ID
    b.eq Lreq_skip_parse

    // path + query, via the existing HTTP/1 path scanner
    mov x0, x19
    mov x1, x20
    mov x2, x22
    bl parse_path
    b.cs p_req_fail // no "/" or "*" within the first 16 bytes

    mov x24, x0 // path
    mov x25, x1 // path length
    mov x26, x2 // query
    mov x27, x3 // query length

    // percent-decode, then run the path safety checks. decode_url is
    // deliberately run before check_path_traversal so that %2e%2e%2f
    // decodes to ../ and is caught.
    mov x0, x24
    mov x1, x25
    bl decode_url
    cbz x0, p_req_fail
    mov x24, x0
    mov x25, x1

    mov x0, x24
    mov x1, x25
    bl check_path_safety
    cbz x0, p_req_fail

    mov x0, x24
    mov x1, x25
    bl check_path_traversal
    cbz x0, p_req_fail

    str x24, [x23, #REQ_PATH]
    str x25, [x23, #REQ_PATH_LENGTH]
    str x26, [x23, #REQ_QUERY]
    str x27, [x23, #REQ_QUERY_LENGTH]

    // authority = value of the Host: header, if present
    mov x0, x19
    mov x1, x20
    adr_l x2, host_match_str
    mov x3, host_match_len
    bl get_header_field
    b.cs p_req_no_authority

    // copy the Host value into authority_buf, NUL-terminated
    mov x24, x0 // value start
    mov x25, x1 // remaining header length
    adr_l x26, authority_buf
    mov x27, #0 // bytes copied
1:
    cbz x25, 2f
    cmp x27, #AUTHORITY_BUF_SIZE
    b.hs 2f // value too long — truncate
    ldrb w3, [x24]
    cmp w3, #'\r'
    b.eq 2f
    strb w3, [x26, x27]
    add x27, x27, #1
    add x24, x24, #1
    sub x25, x25, #1
    b 1b
2:
    strb wzr, [x26, x27] // NUL-terminate
    str x26, [x23, #REQ_AUTHORITY]
    b p_req_done

p_req_no_authority:
    str xzr, [x23, #REQ_AUTHORITY]

p_req_done:
    cmn xzr, xzr // clear carry
    b p_req_epilogue

Lreq_skip_parse:
    cmn xzr, xzr // clear carry
    b p_req_epilogue

p_req_fail:
    cmp xzr, xzr // set carry

p_req_epilogue:
    ldr x27, [sp, #72]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret

// trampolines for conditional branches to reply_* in errors.S (which is too
// far for b.cond / cbz to reach directly).
L400:
    mov x0, #400
    mov x1, #0
    b reply_status
