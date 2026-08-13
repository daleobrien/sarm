#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared HPACK decode state
//
// Description: The decoder's fixed output areas, shared by the decode
//   functions (h2_hpack_decode_block, h2_huffman_decode) and read by
//   the HTTP/2 request builder (h2_build_request, src/h2/). The static
//   table and its strings live in h2_hpack_static_lookup.S (their only
//   consumer); the RFC 7541 Appendix B Huffman table is included here.
//
// Exported Symbols:
//   h2_hpack_fields   — decoded header fields of the current block
//   h2_hpack_str_buf  — Huffman-decoded string output
//   h2_hpack_str_off  — current write offset into h2_hpack_str_buf
//   h2_huffman_table  — RFC 7541 Appendix B code table (included)
//   h2_huffman_len_start — per-code-length start indices (included)
// ─────────────────────────────────────────────────────────────────────

// ── RFC 7541 Appendix B — the static Huffman code ───────────────────
// (code length, code) plus a per-length start index. See the decoder
// below for how the two tables drive h2_huffman_decode.
.global h2_huffman_table
.global h2_huffman_len_start
#include "../h2_huffman_table.S"

// ── decoded-field output area ────────────────────────────────────────
// h2_hpack_decode_block fills this with H2_HPACK_MAX_FIELDS entries of
// H2_HPACK_FIELD_SIZE bytes (name ptr, name len, value ptr, value len).
// Zeroed at startup; each decode rewrites the first `count` entries.
.bss
.align 3
h2_hpack_fields:
    .skip H2_HPACK_MAX_FIELDS * H2_HPACK_FIELD_SIZE

// h2_hpack_str_buf — decoded Huffman string output. Huffman strings
// don't point into the input block (they are re-expanded), so the
// decoder writes them here, appending within one header block decode.
// h2_hpack_decode_block resets the write offset on entry; a decoded
// string that would overflow the buffer is a COMPRESSION_ERROR. The
// decoded strings stay valid until the next block decode, which is long
// enough for h2_build_request to copy out the pseudo-headers.
.align 3
h2_hpack_str_buf:
    .skip H2_HPACK_STR_BUF_SIZE

// current write offset into h2_hpack_str_buf
h2_hpack_str_off:
    .skip 8

.global h2_hpack_fields
.global h2_hpack_str_buf
.global h2_hpack_str_off
