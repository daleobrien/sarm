#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared parse-module state
//
// Description: Buffers and constants shared by the request-parsing
//   functions (parse_path, parse_h2_path, parse_request). The length
//   constants (www_prefix_len, default_file_len, filename_buf_size,
//   query_buf_size) live in defs.S so every consuming file sees them.
//   Single-user data stays in the function's own file.
//
// Exported Symbols:
//   www_prefix    — docroot prefix (DOCROOT from config.S)
//   default_file  — default filename (DEFAULT_FILE from config.S)
//   filename_buf  — docroot-prefixed filename scratch (PATH_MAX)
//   query_buf     — query-string scratch
//   authority_buf — NUL-terminated copy of the Host/:authority value
// ─────────────────────────────────────────────────────────────────────

.data
www_prefix: .ascii DOCROOT // DOCROOT from config.S
default_file: .ascii DEFAULT_FILE // also from config.S

.bss
// probably way too defensive, but can't hurt, eh?
filename_buf: .skip filename_buf_size + 1
.align 3 // fix broken alignment again
query_buf: .skip query_buf_size
.align 3
// authority_buf holds a NUL-terminated copy of the Host header value.
// +1 leaves room for the terminator when the value fills the buffer.
// The size bound lives in defs.S (AUTHORITY_BUF_SIZE), shared with the
// HTTP/2 request builder.
authority_buf: .skip AUTHORITY_BUF_SIZE + 1

.global www_prefix
.global default_file
.global filename_buf
.global query_buf
.global authority_buf
