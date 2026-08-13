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

// One tiny embedded entry so the HTTP/2 tests can resolve a real file
// ("www/index.html"). The 80-byte entry layout mirrors embedded.S; the
// linear scan in lookup_embedded compares path strings, so the hash is
// ignored. Error-page lookups ("www/err/<code>.html") still miss, which
// matches the current build and keeps the reply_status tests unchanged.
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

.align 3
embedded_files:
    .8byte 0                                      // hash (linear scan ignores it)
    .8byte stub_index_path, (stub_index_path_end - stub_index_path - 1)
    .8byte stub_index_content, (stub_index_content_end - stub_index_content)
    .8byte stub_index_ct, (stub_index_ct_end - stub_index_ct - 1)
    .8byte 0                                      // gzip flag — raw content
    .8byte stub_index_etag, (stub_index_etag_end - stub_index_etag - 1)

embedded_count:
    .quad 1

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
