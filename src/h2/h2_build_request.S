// This file is part of ymawky.
// Copyright (C) 2026 imtomt
//
// ymawky is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// ymawky is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ymawky. If not, see <https://www.gnu.org/licenses/>.

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_build_request
//
// Description: Convert a decoded HEADERS block (h2_hpack_fields[0..count))
//   into the protocol-neutral `request` struct. The request
//   pseudo-headers are extracted and validated (RFC 9113 §8.3):
//     - every pseudo-header must precede the regular header fields
//     - a pseudo-header may appear at most once
//     - undefined pseudo-headers (e.g. :status in a request) are
//       malformed
//     - :method is required and must not be empty
//     - :path is required for the methods we process (GET/HEAD/OPTIONS)
//       and must be origin-form or asterisk-form (§8.3.1)
//     - :scheme and :authority are carried but not otherwise validated
//   Any violation is a PROTOCOL_ERROR stream error (RFC 9113 §8.1.1).
//   The path is assembled exactly like HTTP/1's parse_request:
//   parse_h2_path builds the docroot-prefixed filename and splits the
//   query, then decode_url / check_path_safety / check_path_traversal
//   percent-decode and validate it, and the :authority value is copied
//   into authority_buf — the same buffers and helpers HTTP/1 uses, so
//   an HTTP/2 request and its HTTP/1 twin reach the handlers
//   identically (8.4). BREW/unknown methods skip path handling entirely,
//   matching parse_request; only REQ_METHOD and REQ_STREAM_ID are set
//   for them. A regular `range` header value is copied into h2_range_buf
//   and recorded in REQ_RANGE_PTR/REQ_RANGE_LEN for the Range machinery,
//   and a path rejected by check_path_safety / check_path_traversal is
//   not a protocol error — the request decodes cleanly with
//   REQ_FORBIDDEN set, so h2_process_request can answer 403.
//
// Input/Arguments:
//   x0 — stream id
//   x1 — number of decoded header fields
//
// Output/Returns:
//   x0 — 0 on success (carry clear); the `request` struct is filled
//   x0 = H2_ERR_PROTOCOL_ERROR on failure (carry set)
//
// Clobbered Registers:
//   x0-x18, x19-x24 (saved/restored), x30
//
// Stack Usage:
//   160 bytes: stp x19, x20, [sp, #-160]!; ...; str x30, [sp, #48]
// ─────────────────────────────────────────────────────────────────────

.data
// Byte-exact names h2_build_request compares decoded field names and
// values against. The pseudo-headers are the four a request may carry;
// the method strings mirror parse_request's case-sensitive detection.
.align 1
h2_pseudo_method:
    .asciz ":method"
.equ h2_pseudo_method_len, . - h2_pseudo_method - 1
h2_pseudo_path:
    .asciz ":path"
.equ h2_pseudo_path_len, . - h2_pseudo_path - 1
h2_pseudo_scheme:
    .asciz ":scheme"
.equ h2_pseudo_scheme_len, . - h2_pseudo_scheme - 1
h2_pseudo_authority:
    .asciz ":authority"
.equ h2_pseudo_authority_len, . - h2_pseudo_authority - 1
h2_method_get:
    .asciz "GET"
.equ h2_method_get_len, . - h2_method_get - 1
h2_method_head:
    .asciz "HEAD"
.equ h2_method_head_len, . - h2_method_head - 1
h2_method_options:
    .asciz "OPTIONS"
.equ h2_method_options_len, . - h2_method_options - 1
h2_method_brew:
    .asciz "BREW"
.equ h2_method_brew_len, . - h2_method_brew - 1

// the request header name h2_build_request matches to feed the Range
// machinery (matched case-insensitively, like HTTP/1's
// get_header_field/parse_range)
h2_range_name:
    .asciz "range"
.equ h2_range_name_len, 5

// h2_range_buf — persistent copy of the request's Range header value
// ("bytes=0-99"). The decoded value points into h2_hpack_str_buf, which
// is per-block scratch, so it is copied here — like :authority into
// authority_buf — to survive until h2_process_request parses it.
// h2_range_buf_size is defined in defs.S.
.align 3
h2_range_buf:
    .skip h2_range_buf_size

.text
.align 2
.global h2_build_request
h2_build_request:
    stp x19, x20, [sp, #-160]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    str x30, [sp, #48]
    // zero the value slots: method, path, scheme, authority — each a
    // (ptr, len) pair — plus the range header (ptr, len) and the
    // forbidden flag, so requests that don't set them never inherit the
    // previous request's values
    stp xzr, xzr, [sp, #64]
    stp xzr, xzr, [sp, #80]
    stp xzr, xzr, [sp, #96]
    stp xzr, xzr, [sp, #112]
    stp xzr, xzr, [sp, #128]    // REQ_RANGE_PTR / REQ_RANGE_LEN
    str xzr, [sp, #144]         // REQ_FORBIDDEN

    mov x19, x0             // stream id
    mov x20, x1             // field count
    adr_l x21, h2_hpack_fields
    mov x22, #0             // field index
    mov x23, #0             // a regular header has been seen
    mov x24, #UNKNOWN_ID    // method id

.Lh2_req_loop:
    cmp x22, x20
    b.hs .Lh2_req_scan_done
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    ldr x4, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x5, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    ldrb w6, [x0]
    cmp w6, #':'
    b.ne .Lh2_req_normal
    // a pseudo-header — it must come before any regular header
    cbnz x23, .Lh2_req_pseudo_after_normal
    // classify the name with exact byte compares
    adr_l x2, h2_pseudo_method
    mov x3, h2_pseudo_method_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_method_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_path
    mov x3, h2_pseudo_path_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_path_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_scheme
    mov x3, h2_pseudo_scheme_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_scheme_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_authority
    mov x3, h2_pseudo_authority_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_authority_hit
    b .Lh2_req_unknown_pseudo
.Lh2_req_method_hit:
    ldr x6, [sp, #64]       // already seen — duplicate
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #64]
    str x7, [sp, #72]
    b .Lh2_req_next
.Lh2_req_path_hit:
    ldr x6, [sp, #80]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #80]
    str x7, [sp, #88]
    b .Lh2_req_next
.Lh2_req_scheme_hit:
    ldr x6, [sp, #96]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #96]
    str x7, [sp, #104]
    b .Lh2_req_next
.Lh2_req_authority_hit:
    ldr x6, [sp, #112]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #112]
    str x7, [sp, #120]
    b .Lh2_req_next
.Lh2_req_normal:
    mov x23, #1             // regular headers follow the pseudo-headers
    // ── Stage 10 — a regular `range` header feeds the Range machinery ──
    // Matched case-insensitively like HTTP/1's get_header_field; the
    // first occurrence wins (later duplicates are ignored).
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    cmp x1, h2_range_name_len
    b.ne .Lh2_req_next
    adr_l x1, h2_range_name
    mov x2, h2_range_name_len
    bl streqn_i
    cbz x0, .Lh2_req_next
    ldr x6, [sp, #128]       // already seen — keep the first
    cbnz x6, .Lh2_req_next
    // copy the value into h2_range_buf so it outlives the per-block
    // HPACK string buffer (same reason :authority is copied)
    ldr x0, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    adr_l x7, h2_range_buf
    mov x8, #0              // bytes copied
1:  cbz x1, 2f
    cmp x8, h2_range_buf_size
    b.hs 2f                 // too long — truncate, like authority_buf
    ldrb w3, [x0, x8]
    strb w3, [x7, x8]
    add x8, x8, #1
    sub x1, x1, #1
    b 1b
2:  str x7, [sp, #128]
    str x8, [sp, #136]
    b .Lh2_req_next
.Lh2_req_next:
    add x21, x21, #H2_HPACK_FIELD_SIZE
    add x22, x22, #1
    b .Lh2_req_loop

.Lh2_req_scan_done:
    // :method must be present and non-empty (§8.3.1)
    ldr x0, [sp, #64]
    cbz x0, .Lh2_req_missing_method
    ldr x1, [sp, #72]
    cbz x1, .Lh2_req_missing_method
    // map the method string to a method id (case-sensitive, like HTTP/1)
    adr_l x2, h2_method_get
    mov x3, h2_method_get_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_get
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_head
    mov x3, h2_method_head_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_head
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_options
    mov x3, h2_method_options_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_options
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_brew
    mov x3, h2_method_brew_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_brew
    b .Lh2_req_method_done  // unknown method — x24 stays UNKNOWN_ID
.Lh2_req_m_get:
    mov x24, #GET_ID
    b .Lh2_req_method_done
.Lh2_req_m_head:
    mov x24, #HEAD_ID
    b .Lh2_req_method_done
.Lh2_req_m_options:
    mov x24, #OPTIONS_ID
    b .Lh2_req_method_done
.Lh2_req_m_brew:
    mov x24, #BREW_ID
.Lh2_req_method_done:
    // BREW/UNKNOWN get no path handling — mirroring parse_request, only
    // the method and stream id are recorded
    cmp x24, #OPTIONS_ID
    b.hi .Lh2_req_store_method_only
    // :path is required for the methods we process
    ldr x0, [sp, #80]
    cbz x0, .Lh2_req_missing_path
    ldr x1, [sp, #88]
    cbz x1, .Lh2_req_missing_path
    // assemble the docroot-prefixed path; the default file is for
    // GET/HEAD only, OPTIONS keeps the bare docroot
    mov x2, #1
    cmp x24, #OPTIONS_ID
    b.ne 1f
    mov x2, #0
1:
    bl parse_h2_path
    b.cs .Lh2_req_bad_path
    str x0, [sp, #80]       // assembled filename (filename_buf)
    str x1, [sp, #88]       // filename length
    str x2, [sp, #96]       // query string (query_buf), or 0
    str x3, [sp, #104]      // query length
    // percent-decode in place, then the same safety checks as HTTP/1
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl decode_url
    cbz x0, .Lh2_req_bad_path
    str x0, [sp, #80]
    str x1, [sp, #88]
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl check_path_safety
    cbz x0, .Lh2_req_forbidden
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl check_path_traversal
    cbz x0, .Lh2_req_forbidden
    // copy :authority into authority_buf, NUL-terminated (bounded)
    ldr x0, [sp, #112]
    cbz x0, .Lh2_req_no_authority
    ldr x1, [sp, #120]
    adr_l x8, authority_buf
    mov x9, #0              // bytes copied
1:
    cbz x1, 2f
    cmp x9, AUTHORITY_BUF_SIZE
    b.hs 2f                 // too long — truncate
    ldrb w3, [x0, x9]
    strb w3, [x8, x9]
    add x9, x9, #1
    sub x1, x1, #1
    b 1b
2:
    strb wzr, [x8, x9]
    mov x7, x8
    b .Lh2_req_store
.Lh2_req_no_authority:
    mov x7, #0
.Lh2_req_store:
    adr_l x0, request
    str x24, [x0, #REQ_METHOD]
    str x19, [x0, #REQ_STREAM_ID]
    ldr x1, [sp, #80]
    str x1, [x0, #REQ_PATH]
    ldr x2, [sp, #88]
    str x2, [x0, #REQ_PATH_LENGTH]
    ldr x3, [sp, #96]
    str x3, [x0, #REQ_QUERY]
    ldr x4, [sp, #104]
    str x4, [x0, #REQ_QUERY_LENGTH]
    str x7, [x0, #REQ_AUTHORITY]
    ldr x5, [sp, #128]
    str x5, [x0, #REQ_RANGE_PTR]
    ldr x5, [sp, #136]
    str x5, [x0, #REQ_RANGE_LEN]
    ldr x5, [sp, #144]
    str x5, [x0, #REQ_FORBIDDEN]
    b .Lh2_req_ok
.Lh2_req_store_method_only:
    adr_l x0, request
    str x24, [x0, #REQ_METHOD]
    str x19, [x0, #REQ_STREAM_ID]
    ldr x5, [sp, #128]
    str x5, [x0, #REQ_RANGE_PTR]
    ldr x5, [sp, #136]
    str x5, [x0, #REQ_RANGE_LEN]
    ldr x5, [sp, #144]
    str x5, [x0, #REQ_FORBIDDEN]
.Lh2_req_ok:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2_req_epilogue
.Lh2_req_dup:
.Lh2_req_pseudo_after_normal:
.Lh2_req_unknown_pseudo:
.Lh2_req_missing_method:
.Lh2_req_missing_path:
.Lh2_req_bad_path:
.Lh2_req_bad:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
.Lh2_req_epilogue:
    ldr x30, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #160
    ret

// A path the server refuses to serve (unsafe bytes, traversal) is not a
// protocol violation — the request decodes, and h2_process_request
// answers 403. The decoded path is stored for completeness; the handler
// never looks at it.
.Lh2_req_forbidden:
    mov x7, #0              // no authority copy — the path is rejected
    mov x6, #1
    str x6, [sp, #144]
    b .Lh2_req_store
