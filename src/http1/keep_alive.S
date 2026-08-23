#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: http1_should_keep_alive
//
// Description: Decide whether an HTTP/1 connection may stay open for
//   another request, per the close rule documented in
//   src/http1/README.md (Plan.md Phase 1, Step 2). A pure predicate: it
//   reads the raw request buffer and the response status about to be
//   sent, touches no per-connection state. Wired into the `Connection:`
//   response header by http1_write_response (Step 3); Step 6 wires it
//   into the read/reset loop.
//
//   Close whenever:
//     - the header length is 0 (no request has actually been observed —
//       nothing to justify keeping the connection alive on);
//     - the method is not GET, HEAD or OPTIONS (unknown methods are
//       the 501 path);
//     - the response status means the parser lost sync (400, 408, 413,
//       431, 500);
//     - the request carries a Content-Length or Transfer-Encoding
//       header (detected only, never parsed — sarm never reads a
//       request body, so it cannot skip one to find the next request
//       line, and a body left in the socket would be misparsed as the
//       next request);
//     - the request is HTTP/1.0 without "Connection: keep-alive";
//     - the request carries "Connection: close".
//   Keep alive otherwise.
//
// Input/Arguments:
//   x0 -> raw request buffer (header, e.g. "GET / HTTP/1.1\r\n...")
//   x1 -> header length (one byte past the final \r\n\r\n)
//   x2 -> method id (GET_ID / HEAD_ID / OPTIONS_ID / UNKNOWN_ID)
//   x3 -> response status code about to be sent
//
// Output/Returns:
//   x0 -> 1 = keep the connection open, 0 = close it
//
// Clobbered Registers:
//   x0-x4, x9, x10; preserves x19-x28 (x19-x27 saved and restored)
//
// Stack Usage:
//   80 bytes: stp x29, x30, [sp, #-80]!
// ─────────────────────────────────────────────────────────────────────

rodata
.align 4
cl_match_str:     .ascii "Content-Length"
.equ cl_match_len, 14
.align 4
te_match_str:     .ascii "Transfer-Encoding"
.equ te_match_len, 17
.align 4
conn_match_str:   .ascii "Connection"
.equ conn_match_len, 10
.align 4
close_match_str:  .ascii "close"
.equ close_match_len, 5
.align 4
ka_match_str:     .ascii "keep-alive"
.equ ka_match_len, 10
.align 4
http10_match_str: .ascii "HTTP/1.0"
.align 4

.text
.align 2
.global http1_should_keep_alive
http1_should_keep_alive:
    stp x29, x30, [sp, #-80]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    str x27, [sp, #72]

    mov x19, x0 // request buffer
    mov x20, x1 // header length
    mov x21, x2 // method id
    mov x22, x3 // response status

    // a zero-length buffer means no request was actually observed (e.g.
    // no caller has run a request through this connection yet) -- there
    // is nothing here to justify keeping anything alive.
    cbz x20, Lhka_close

    // ── method: only GET/HEAD/OPTIONS may keep the connection open ──
    cmp x21, #GET_ID
    b.eq Lhka_method_ok
    cmp x21, #HEAD_ID
    b.eq Lhka_method_ok
    cmp x21, #OPTIONS_ID
    b.eq Lhka_method_ok
    b Lhka_close
Lhka_method_ok:

    // ── status: these mean the parser lost sync in the header ──
    cmp x22, #400
    b.eq Lhka_close
    cmp x22, #408
    b.eq Lhka_close
    cmp x22, #413
    b.eq Lhka_close
    cmp x22, #431
    b.eq Lhka_close
    cmp x22, #500
    b.eq Lhka_close

    // ── body-indicating headers: detect only, never parse ──
    mov x0, x19
    mov x1, x20
    adr_l x2, cl_match_str
    mov x3, cl_match_len
    bl get_header_field
    b.cc Lhka_close // found -> Content-Length present

    mov x0, x19
    mov x1, x20
    adr_l x2, te_match_str
    mov x3, te_match_len
    bl get_header_field
    b.cc Lhka_close // found -> Transfer-Encoding present

    // ── HTTP version: does the request line end in "HTTP/1.0"? ──
    mov x24, #0
Lhka_scan_crlf:
    cmp x24, x20
    b.hs Lhka_version_11 // ran off the end without a \r -- treat as 1.1
    ldrb w0, [x19, x24]
    cmp w0, #'\r'
    b.eq Lhka_found_cr
    add x24, x24, #1
    b Lhka_scan_crlf
Lhka_found_cr:
    cmp x24, #8
    b.lo Lhka_version_11 // request line too short to end in "HTTP/1.0"
    sub x25, x24, #8
    mov x0, x19
    add x0, x0, x25
    adr_l x1, http10_match_str
    mov x2, #8
    bl streqn_i
    cbz x0, Lhka_version_11
    mov x26, #1 // is_http10
    b Lhka_version_done
Lhka_version_11:
    mov x26, #0
Lhka_version_done:

    // ── Connection header value: absent(0) / keep-alive(1) / close(2) ──
    mov x0, x19
    mov x1, x20
    adr_l x2, conn_match_str
    mov x3, conn_match_len
    bl get_header_field
    b.cs Lhka_conn_absent // not found

    mov x9, x0  // value ptr
    mov x10, x1 // remaining length in header from value start

    // "close" ?
    cmp x10, #close_match_len
    b.lo Lhka_conn_try_ka
    mov x0, x9
    adr_l x1, close_match_str
    mov x2, #close_match_len
    bl streqn_i
    cbz x0, Lhka_conn_try_ka
    cmp x10, #close_match_len
    b.eq Lhka_conn_is_close
    ldrb w0, [x9, #close_match_len]
    cmp w0, #'\r'
    b.eq Lhka_conn_is_close
    cmp w0, #' '
    b.eq Lhka_conn_is_close
    cmp w0, #'\t'
    b.eq Lhka_conn_is_close
    cmp w0, #';'
    b.eq Lhka_conn_is_close
    cmp w0, #','
    b.eq Lhka_conn_is_close
    b Lhka_conn_try_ka
Lhka_conn_is_close:
    mov x27, #2
    b Lhka_conn_done

    // "keep-alive" ?
Lhka_conn_try_ka:
    cmp x10, #ka_match_len
    b.lo Lhka_conn_absent
    mov x0, x9
    adr_l x1, ka_match_str
    mov x2, #ka_match_len
    bl streqn_i
    cbz x0, Lhka_conn_absent
    cmp x10, #ka_match_len
    b.eq Lhka_conn_is_ka
    ldrb w0, [x9, #ka_match_len]
    cmp w0, #'\r'
    b.eq Lhka_conn_is_ka
    cmp w0, #' '
    b.eq Lhka_conn_is_ka
    cmp w0, #'\t'
    b.eq Lhka_conn_is_ka
    cmp w0, #';'
    b.eq Lhka_conn_is_ka
    cmp w0, #','
    b.eq Lhka_conn_is_ka
    b Lhka_conn_absent
Lhka_conn_is_ka:
    mov x27, #1
    b Lhka_conn_done

Lhka_conn_absent:
    mov x27, #0
Lhka_conn_done:

    // ── apply the rule ──
    cmp x27, #2
    b.eq Lhka_close // Connection: close -> always close

    cbnz x26, Lhka_check_10 // HTTP/1.0 needs an explicit keep-alive
    b Lhka_keep             // HTTP/1.1, no close -> keep-alive

Lhka_check_10:
    cmp x27, #1
    b.eq Lhka_keep
    b Lhka_close

Lhka_keep:
    mov x0, #1
    b Lhka_epilogue

Lhka_close:
    mov x0, #0

Lhka_epilogue:
    ldr x27, [sp, #72]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
