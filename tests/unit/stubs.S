// Stub symbols for unit testing — provides minimal definitions for
// symbols that the tested .S files reference from other source files
// that we don't want to fully link.
// This file is part of ymawky.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only

#include "defs.S"

// ── stubs for embedded.S (lookup_embedded in file.S needs these) ───

.data
.align 3

// One tiny embedded entry so HTTP/2 tests can resolve a real file
// ("www/index.html"), mirroring the 80-byte entry layout of embedded.S:
//   +0:  hash (8 bytes)
//   +8:  path_ptr
//   +16: path_len
//   +24: content_ptr
//   +32: content_size
//   +40: ct_ptr
//   +48: ct_len
//   +56: gzip flag
//   +64: etag_ptr
//   +72: etag_len
// lookup_embedded's linear scan compares path strings, so the hash is
// ignored here.
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

// ── stubs for header.S (L400/L403/L414/L500 in parse.S need this) ──

.text
.align 2

// reply_status is called by error paths in parse.S and file.S.
// Our tests shouldn't hit error paths, but the linker needs the symbol.
// We provide a stub that just returns (tests don't exercise error paths).
reply_status:
    ret

.global reply_status

// handle_fs_error — called by error paths in file/get code
handle_fs_error:
    ret

.global handle_fs_error

// build_header — called by get.S via reply_status
build_header:
    mov x0, #0
    ret

.global build_header

// header_buf — needed by build_header and reply_status.
// Tests won't use it but linker needs it.
.bss
.align 3
header_buf:
    .skip 512

.global header_buf
