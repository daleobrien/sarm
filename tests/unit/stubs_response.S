// Stub symbols for the Stage 2 response unit tests (test_response.c).
//
// test_response links the REAL header.S (http1_write_response,
// reply_status), get.S (create_response), parse.S, file.S, data.S, and
// util.S. Unlike stubs.S — which stubs out the header/get functions for
// the other test suites — this file only provides the symbols that would
// otherwise live in the embedded table (embedded.S) and in ymawky.S.
// This file is part of ymawky.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only

#include "defs.S"

// ── stubs for embedded.S (lookup_embedded in file.S needs these) ───

.data
.align 3

// Six embedded entries so the HTTP/2 tests can resolve real files of
// every Stage 10 MIME type (.html/.css/.js/.svg/.png), exercise Range
// responses over a small fixed body, and — since Stage 11 — retrieve a
// file (www/big.bin, 70000 bytes) larger than the initial flow-control
// window. The 80-byte entry layout mirrors embedded.S; the linear scan
// in lookup_embedded compares path strings, so the hash is ignored.
// Error-page lookups ("www/err/<code>.html") still miss, which matches
// the current build and keeps the reply_status tests unchanged.
stub_index_path:
    .asciz "www/index.html"
stub_index_path_end:
stub_index_content:
    .ascii "<h1>hello h2</h1>"
stub_index_content_end:
stub_index_ct:
    .asciz "text/html; charset=utf-8"
stub_index_ct_end:
stub_index_etag:
    .asciz "\"stub-etag\""
stub_index_etag_end:

stub_css_path:
    .asciz "www/assets/style.css"
stub_css_path_end:
stub_css_content:
    .ascii "body{color:red}"
stub_css_content_end:
stub_css_ct:
    .asciz "text/css; charset=utf-8"
stub_css_ct_end:
stub_css_etag:
    .asciz "\"stub-css-etag\""
stub_css_etag_end:

stub_js_path:
    .asciz "www/assets/app.js"
stub_js_path_end:
stub_js_content:
    .ascii "console.log(1)"
stub_js_content_end:
stub_js_ct:
    .asciz "text/javascript; charset=utf-8"
stub_js_ct_end:
stub_js_etag:
    .asciz "\"stub-js-etag\""
stub_js_etag_end:

stub_svg_path:
    .asciz "www/logo.svg"
stub_svg_path_end:
stub_svg_content:
    .ascii "<svg/>"
stub_svg_content_end:
stub_svg_ct:
    .asciz "image/svg+xml"
stub_svg_ct_end:
stub_svg_etag:
    .asciz "\"stub-svg-etag\""
stub_svg_etag_end:

stub_png_path:
    .asciz "www/logo.png"
stub_png_path_end:
stub_png_content:
    .ascii "\x89PNG-not-a-real-png"
stub_png_content_end:
stub_png_ct:
    .asciz "image/png"
stub_png_ct_end:
stub_png_etag:
    .asciz "\"stub-png-etag\""
stub_png_etag_end:

// ── Stage 11 — a big file for the flow-control tests ──
// 70000 bytes, larger than the 65535-byte initial flow-control window,
// so serving it exercises WINDOW_UPDATE-driven transmission (h2_write_body
// pauses when the credit runs out and resumes once the client replenishes
// it).
stub_big_path:
    .asciz "www/big.bin"
stub_big_path_end:
stub_big_content:
    .space 70000, 0x61      // 70000 'a's
stub_big_content_end:
stub_big_ct:
    .asciz "text/plain; charset=utf-8"
stub_big_ct_end:
stub_big_etag:
    .asciz "\"stub-big-etag\""
stub_big_etag_end:

.align 3
embedded_files:
    .8byte 0                                      // hash (linear scan ignores it)
    .8byte stub_index_path, (stub_index_path_end - stub_index_path - 1)
    .8byte stub_index_content, (stub_index_content_end - stub_index_content)
    .8byte stub_index_ct, (stub_index_ct_end - stub_index_ct - 1)
    .8byte 0                                      // gzip flag — raw content
    .8byte stub_index_etag, (stub_index_etag_end - stub_index_etag - 1)

    .8byte 0
    .8byte stub_css_path, (stub_css_path_end - stub_css_path - 1)
    .8byte stub_css_content, (stub_css_content_end - stub_css_content)
    .8byte stub_css_ct, (stub_css_ct_end - stub_css_ct - 1)
    .8byte 0
    .8byte stub_css_etag, (stub_css_etag_end - stub_css_etag - 1)

    .8byte 0
    .8byte stub_js_path, (stub_js_path_end - stub_js_path - 1)
    .8byte stub_js_content, (stub_js_content_end - stub_js_content)
    .8byte stub_js_ct, (stub_js_ct_end - stub_js_ct - 1)
    .8byte 0
    .8byte stub_js_etag, (stub_js_etag_end - stub_js_etag - 1)

    .8byte 0
    .8byte stub_svg_path, (stub_svg_path_end - stub_svg_path - 1)
    .8byte stub_svg_content, (stub_svg_content_end - stub_svg_content)
    .8byte stub_svg_ct, (stub_svg_ct_end - stub_svg_ct - 1)
    .8byte 0
    .8byte stub_svg_etag, (stub_svg_etag_end - stub_svg_etag - 1)

    .8byte 0
    .8byte stub_png_path, (stub_png_path_end - stub_png_path - 1)
    .8byte stub_png_content, (stub_png_content_end - stub_png_content)
    .8byte stub_png_ct, (stub_png_ct_end - stub_png_ct - 1)
    .8byte 0
    .8byte stub_png_etag, (stub_png_etag_end - stub_png_etag - 1)

    .8byte 0
    .8byte stub_big_path, (stub_big_path_end - stub_big_path - 1)
    .8byte stub_big_content, (stub_big_content_end - stub_big_content)
    .8byte stub_big_ct, (stub_big_ct_end - stub_big_ct - 1)
    .8byte 0
    .8byte stub_big_etag, (stub_big_etag_end - stub_big_etag - 1)

embedded_count:
    .quad 6

.global embedded_files
.global embedded_count

// ── stub for ymawky.S (reply_status tails into child_end) ───────────

.text
.align 2

// child_end — normally in ymawky.S, where it closes the client fd, logs
// request timing, and exits the child process (so it never returns). The
// test calls reply_status with flag=1, which returns via its own frame
// instead of reaching this symbol; this stub only exists so the linker
// can resolve the `b child_end` in get/head/reply_status.
child_end:
    ret

.global child_end
