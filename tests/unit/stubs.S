// Stub symbols for unit testing — provides minimal definitions for
// symbols that the tested .S files reference from other source files
// that we don't want to fully link.

#include "defs.S"

// ── stubs for embedded.S (lookup_embedded in file.S needs these) ───

.data
.align 3

// One tiny embedded entry so HTTP/2 tests can resolve a real file
// ("www/index.html"), mirroring the 72-byte entry layout of embedded.S:
//   +0:  path_ptr
//   +8:  path_len
//   +16: content_ptr
//   +24: content_size
//   +32: ct_ptr
//   +40: ct_len
//   +48: gzip flag
//   +56: etag_ptr
//   +64: etag_len
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
// Pointer columns are offsets from embedded_files, matching what
// embed_www.sh generates (docs/SECURITY.md Step 13) — lookup_embedded
// adds the base back.
OBJECT embedded_files
    .8byte (stub_index_path - embedded_files), (stub_index_path_end - stub_index_path - 1)
    .8byte (stub_index_content - embedded_files), (stub_index_content_end - stub_index_content)
    .8byte (stub_index_ct - embedded_files), (stub_index_ct_end - stub_index_ct - 1)
    .8byte 0                                      // gzip flag — raw content
    .8byte (stub_index_etag - embedded_files), (stub_index_etag_end - stub_index_etag - 1)
ENDOBJ embedded_files

OBJECT embedded_count
    .quad 1
ENDOBJ embedded_count


// ── stubs for header.S (L400/L403/L414/L500 in parse.S need this) ──

.text
.align 2

// reply_status is called by error paths in parse.S and file.S.
// Our tests shouldn't hit error paths, but the linker needs the symbol.
// We provide a stub that just returns (tests don't exercise error paths).
FUNC reply_status
    ret
ENDFUNC reply_status


// handle_fs_error — called by error paths in file/get code
FUNC handle_fs_error
    ret
ENDFUNC handle_fs_error


// build_header — called by get.S via reply_status
FUNC build_header
    mov x0, #0
    ret
ENDFUNC build_header


// header_buf — needed by build_header and reply_status.
// Tests won't use it but linker needs it.
.bss
.align 3
OBJECT header_buf
    .skip 512
ENDOBJ header_buf

