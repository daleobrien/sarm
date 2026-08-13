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

#include "defs.S"

// HPACK header compression (RFC 7541) — Stage 7, minimal HPACK.
//
// A decoder for the header field representations a static-table-only
// implementation accepts:
//   - indexed header field (§6.1)
//   - literal header field with incremental indexing (§6.2.1) — accepted
//     but never stored: the dynamic table max size is 0, so an entry
//     added to it would be evicted immediately
//   - literal header field without indexing (§6.2.2)
//   - literal header field never indexed (§6.2.3)
//   - dynamic table size update (§6.3) — only size 0
// Integer decoding (§5.1) and string decoding (§5.2) are the building
// blocks. Strings may be Huffman-coded; the RFC 7541 Appendix B static
// Huffman table (h2_huffman_table, generated into h2_huffman_table.S)
// drives the decoder, which writes decoded bytes into h2_hpack_str_buf.
// The RFC 7541 Appendix A static table (h2_hpack_static_table) provides
// the names and values for indices 1..61. h2_hpack_decode_field
// handles one representation, h2_hpack_decode_block loops over a whole
// HEADERS payload into the fixed h2_hpack_fields array.
//
// The dynamic table is disabled: the opening SETTINGS frame advertises
// SETTINGS_HEADER_TABLE_SIZE = 0 (http2.S). The decoder rejects
// everything that would need a dynamic table — any size update above 0
// (§6.3) and any index beyond the static table — as
// H2_ERR_COMPRESSION_ERROR connection errors (RFC 9113 §4.3). A
// Huffman string whose padding is invalid, that contains the EOS
// symbol, or that decodes past h2_hpack_str_buf is rejected the same
// way.
//
// The decoded fields point into the input block (zero-copy) or into
// h2_hpack_str_buf (Huffman-decoded); the block lives in the
// connection buffer, so fields are only valid for the duration of the
// connection's copy of the frame. h2_hpack_decode_block
// bounds-checks its consumption against the block length, so a
// truncated block is rejected rather than accepted. The primitives
// below assume the caller has a well-formed block in memory.
//
// Error convention (shared with the rest of ymawky):
//   carry clear = success, x0 = result
//   carry set   = failure, x0 = H2_ERR_COMPRESSION_ERROR

.global h2_hpack_static_table
.global h2_hpack_fields
.global h2_hpack_decode_int
.global h2_hpack_decode_string
.global h2_hpack_static_lookup
.global h2_hpack_decode_field
.global h2_hpack_decode_block
.global h2_huffman_decode

// ── RFC 7541 Appendix A — the 61-entry static table ──────────────────
// Each entry is four quadwords: name pointer, name length, value
// pointer, value length. The lengths are assembled next to each string
// (`.equ len, . - str - 1` for the NUL-terminated .asciz), so editing a
// string keeps its length correct automatically. 47 of the 61 values
// are empty and share hp_empty.
.data
.align 3
h2_hpack_static_table:
    //   1  :authority                    (empty)
    .quad hp_s_authority, hp_l_authority, hp_empty, 0
    //   2  :method                       GET
    .quad hp_s_method, hp_l_method, hp_v_get, hp_l_get
    //   3  :method                       POST
    .quad hp_s_method, hp_l_method, hp_v_post, hp_l_post
    //   4  :path                         /
    .quad hp_s_path, hp_l_path, hp_v_slash, hp_l_slash
    //   5  :path                         /index.html
    .quad hp_s_path, hp_l_path, hp_v_index, hp_l_index
    //   6  :scheme                       http
    .quad hp_s_scheme, hp_l_scheme, hp_v_http, hp_l_http
    //   7  :scheme                       https
    .quad hp_s_scheme, hp_l_scheme, hp_v_https, hp_l_https
    //   8  :status                       200
    .quad hp_s_status, hp_l_status, hp_v_200, hp_l_200
    //   9  :status                       204
    .quad hp_s_status, hp_l_status, hp_v_204, hp_l_204
    //  10  :status                       206
    .quad hp_s_status, hp_l_status, hp_v_206, hp_l_206
    //  11  :status                       304
    .quad hp_s_status, hp_l_status, hp_v_304, hp_l_304
    //  12  :status                       400
    .quad hp_s_status, hp_l_status, hp_v_400, hp_l_400
    //  13  :status                       404
    .quad hp_s_status, hp_l_status, hp_v_404, hp_l_404
    //  14  :status                       500
    .quad hp_s_status, hp_l_status, hp_v_500, hp_l_500
    //  15  accept-charset                (empty)
    .quad hp_s_accept_charset, hp_l_accept_charset, hp_empty, 0
    //  16  accept-encoding               gzip, deflate
    .quad hp_s_accept_encoding, hp_l_accept_encoding, hp_v_gzip_deflate, hp_l_gzip_deflate
    //  17  accept-language               (empty)
    .quad hp_s_accept_language, hp_l_accept_language, hp_empty, 0
    //  18  accept-ranges                 (empty)
    .quad hp_s_accept_ranges, hp_l_accept_ranges, hp_empty, 0
    //  19  accept                        (empty)
    .quad hp_s_accept, hp_l_accept, hp_empty, 0
    //  20  access-control-allow-origin   (empty)
    .quad hp_s_access_control_allow_origin, hp_l_access_control_allow_origin, hp_empty, 0
    //  21  age                           (empty)
    .quad hp_s_age, hp_l_age, hp_empty, 0
    //  22  allow                         (empty)
    .quad hp_s_allow, hp_l_allow, hp_empty, 0
    //  23  authorization                 (empty)
    .quad hp_s_authorization, hp_l_authorization, hp_empty, 0
    //  24  cache-control                 (empty)
    .quad hp_s_cache_control, hp_l_cache_control, hp_empty, 0
    //  25  content-disposition           (empty)
    .quad hp_s_content_disposition, hp_l_content_disposition, hp_empty, 0
    //  26  content-encoding              (empty)
    .quad hp_s_content_encoding, hp_l_content_encoding, hp_empty, 0
    //  27  content-language              (empty)
    .quad hp_s_content_language, hp_l_content_language, hp_empty, 0
    //  28  content-length                (empty)
    .quad hp_s_content_length, hp_l_content_length, hp_empty, 0
    //  29  content-location              (empty)
    .quad hp_s_content_location, hp_l_content_location, hp_empty, 0
    //  30  content-range                 (empty)
    .quad hp_s_content_range, hp_l_content_range, hp_empty, 0
    //  31  content-type                  (empty)
    .quad hp_s_content_type, hp_l_content_type, hp_empty, 0
    //  32  cookie                        (empty)
    .quad hp_s_cookie, hp_l_cookie, hp_empty, 0
    //  33  date                          (empty)
    .quad hp_s_date, hp_l_date, hp_empty, 0
    //  34  etag                          (empty)
    .quad hp_s_etag, hp_l_etag, hp_empty, 0
    //  35  expect                        (empty)
    .quad hp_s_expect, hp_l_expect, hp_empty, 0
    //  36  expires                       (empty)
    .quad hp_s_expires, hp_l_expires, hp_empty, 0
    //  37  from                          (empty)
    .quad hp_s_from, hp_l_from, hp_empty, 0
    //  38  host                          (empty)
    .quad hp_s_host, hp_l_host, hp_empty, 0
    //  39  if-match                      (empty)
    .quad hp_s_if_match, hp_l_if_match, hp_empty, 0
    //  40  if-modified-since             (empty)
    .quad hp_s_if_modified_since, hp_l_if_modified_since, hp_empty, 0
    //  41  if-none-match                 (empty)
    .quad hp_s_if_none_match, hp_l_if_none_match, hp_empty, 0
    //  42  if-range                      (empty)
    .quad hp_s_if_range, hp_l_if_range, hp_empty, 0
    //  43  if-unmodified-since           (empty)
    .quad hp_s_if_unmodified_since, hp_l_if_unmodified_since, hp_empty, 0
    //  44  last-modified                 (empty)
    .quad hp_s_last_modified, hp_l_last_modified, hp_empty, 0
    //  45  link                          (empty)
    .quad hp_s_link, hp_l_link, hp_empty, 0
    //  46  location                      (empty)
    .quad hp_s_location, hp_l_location, hp_empty, 0
    //  47  max-forwards                  (empty)
    .quad hp_s_max_forwards, hp_l_max_forwards, hp_empty, 0
    //  48  proxy-authenticate            (empty)
    .quad hp_s_proxy_authenticate, hp_l_proxy_authenticate, hp_empty, 0
    //  49  proxy-authorization           (empty)
    .quad hp_s_proxy_authorization, hp_l_proxy_authorization, hp_empty, 0
    //  50  range                         (empty)
    .quad hp_s_range, hp_l_range, hp_empty, 0
    //  51  referer                       (empty)
    .quad hp_s_referer, hp_l_referer, hp_empty, 0
    //  52  refresh                       (empty)
    .quad hp_s_refresh, hp_l_refresh, hp_empty, 0
    //  53  retry-after                   (empty)
    .quad hp_s_retry_after, hp_l_retry_after, hp_empty, 0
    //  54  server                        (empty)
    .quad hp_s_server, hp_l_server, hp_empty, 0
    //  55  set-cookie                    (empty)
    .quad hp_s_set_cookie, hp_l_set_cookie, hp_empty, 0
    //  56  strict-transport-security     (empty)
    .quad hp_s_strict_transport_security, hp_l_strict_transport_security, hp_empty, 0
    //  57  transfer-encoding             (empty)
    .quad hp_s_transfer_encoding, hp_l_transfer_encoding, hp_empty, 0
    //  58  user-agent                    (empty)
    .quad hp_s_user_agent, hp_l_user_agent, hp_empty, 0
    //  59  vary                          (empty)
    .quad hp_s_vary, hp_l_vary, hp_empty, 0
    //  60  via                           (empty)
    .quad hp_s_via, hp_l_via, hp_empty, 0
    //  61  www-authenticate              (empty)
    .quad hp_s_www_authenticate, hp_l_www_authenticate, hp_empty, 0

// ── the table's strings ──────────────────────────────────────────────

// the shared empty value
hp_empty:
    .asciz ""

// names, in table order
hp_s_authority:
    .asciz ":authority"
.equ hp_l_authority, . - hp_s_authority - 1
hp_s_method:
    .asciz ":method"
.equ hp_l_method, . - hp_s_method - 1
hp_s_path:
    .asciz ":path"
.equ hp_l_path, . - hp_s_path - 1
hp_s_scheme:
    .asciz ":scheme"
.equ hp_l_scheme, . - hp_s_scheme - 1
hp_s_status:
    .asciz ":status"
.equ hp_l_status, . - hp_s_status - 1
hp_s_accept_charset:
    .asciz "accept-charset"
.equ hp_l_accept_charset, . - hp_s_accept_charset - 1
hp_s_accept_encoding:
    .asciz "accept-encoding"
.equ hp_l_accept_encoding, . - hp_s_accept_encoding - 1
hp_s_accept_language:
    .asciz "accept-language"
.equ hp_l_accept_language, . - hp_s_accept_language - 1
hp_s_accept_ranges:
    .asciz "accept-ranges"
.equ hp_l_accept_ranges, . - hp_s_accept_ranges - 1
hp_s_accept:
    .asciz "accept"
.equ hp_l_accept, . - hp_s_accept - 1
hp_s_access_control_allow_origin:
    .asciz "access-control-allow-origin"
.equ hp_l_access_control_allow_origin, . - hp_s_access_control_allow_origin - 1
hp_s_age:
    .asciz "age"
.equ hp_l_age, . - hp_s_age - 1
hp_s_allow:
    .asciz "allow"
.equ hp_l_allow, . - hp_s_allow - 1
hp_s_authorization:
    .asciz "authorization"
.equ hp_l_authorization, . - hp_s_authorization - 1
hp_s_cache_control:
    .asciz "cache-control"
.equ hp_l_cache_control, . - hp_s_cache_control - 1
hp_s_content_disposition:
    .asciz "content-disposition"
.equ hp_l_content_disposition, . - hp_s_content_disposition - 1
hp_s_content_encoding:
    .asciz "content-encoding"
.equ hp_l_content_encoding, . - hp_s_content_encoding - 1
hp_s_content_language:
    .asciz "content-language"
.equ hp_l_content_language, . - hp_s_content_language - 1
hp_s_content_length:
    .asciz "content-length"
.equ hp_l_content_length, . - hp_s_content_length - 1
hp_s_content_location:
    .asciz "content-location"
.equ hp_l_content_location, . - hp_s_content_location - 1
hp_s_content_range:
    .asciz "content-range"
.equ hp_l_content_range, . - hp_s_content_range - 1
hp_s_content_type:
    .asciz "content-type"
.equ hp_l_content_type, . - hp_s_content_type - 1
hp_s_cookie:
    .asciz "cookie"
.equ hp_l_cookie, . - hp_s_cookie - 1
hp_s_date:
    .asciz "date"
.equ hp_l_date, . - hp_s_date - 1
hp_s_etag:
    .asciz "etag"
.equ hp_l_etag, . - hp_s_etag - 1
hp_s_expect:
    .asciz "expect"
.equ hp_l_expect, . - hp_s_expect - 1
hp_s_expires:
    .asciz "expires"
.equ hp_l_expires, . - hp_s_expires - 1
hp_s_from:
    .asciz "from"
.equ hp_l_from, . - hp_s_from - 1
hp_s_host:
    .asciz "host"
.equ hp_l_host, . - hp_s_host - 1
hp_s_if_match:
    .asciz "if-match"
.equ hp_l_if_match, . - hp_s_if_match - 1
hp_s_if_modified_since:
    .asciz "if-modified-since"
.equ hp_l_if_modified_since, . - hp_s_if_modified_since - 1
hp_s_if_none_match:
    .asciz "if-none-match"
.equ hp_l_if_none_match, . - hp_s_if_none_match - 1
hp_s_if_range:
    .asciz "if-range"
.equ hp_l_if_range, . - hp_s_if_range - 1
hp_s_if_unmodified_since:
    .asciz "if-unmodified-since"
.equ hp_l_if_unmodified_since, . - hp_s_if_unmodified_since - 1
hp_s_last_modified:
    .asciz "last-modified"
.equ hp_l_last_modified, . - hp_s_last_modified - 1
hp_s_link:
    .asciz "link"
.equ hp_l_link, . - hp_s_link - 1
hp_s_location:
    .asciz "location"
.equ hp_l_location, . - hp_s_location - 1
hp_s_max_forwards:
    .asciz "max-forwards"
.equ hp_l_max_forwards, . - hp_s_max_forwards - 1
hp_s_proxy_authenticate:
    .asciz "proxy-authenticate"
.equ hp_l_proxy_authenticate, . - hp_s_proxy_authenticate - 1
hp_s_proxy_authorization:
    .asciz "proxy-authorization"
.equ hp_l_proxy_authorization, . - hp_s_proxy_authorization - 1
hp_s_range:
    .asciz "range"
.equ hp_l_range, . - hp_s_range - 1
hp_s_referer:
    .asciz "referer"
.equ hp_l_referer, . - hp_s_referer - 1
hp_s_refresh:
    .asciz "refresh"
.equ hp_l_refresh, . - hp_s_refresh - 1
hp_s_retry_after:
    .asciz "retry-after"
.equ hp_l_retry_after, . - hp_s_retry_after - 1
hp_s_server:
    .asciz "server"
.equ hp_l_server, . - hp_s_server - 1
hp_s_set_cookie:
    .asciz "set-cookie"
.equ hp_l_set_cookie, . - hp_s_set_cookie - 1
hp_s_strict_transport_security:
    .asciz "strict-transport-security"
.equ hp_l_strict_transport_security, . - hp_s_strict_transport_security - 1
hp_s_transfer_encoding:
    .asciz "transfer-encoding"
.equ hp_l_transfer_encoding, . - hp_s_transfer_encoding - 1
hp_s_user_agent:
    .asciz "user-agent"
.equ hp_l_user_agent, . - hp_s_user_agent - 1
hp_s_vary:
    .asciz "vary"
.equ hp_l_vary, . - hp_s_vary - 1
hp_s_via:
    .asciz "via"
.equ hp_l_via, . - hp_s_via - 1
hp_s_www_authenticate:
    .asciz "www-authenticate"
.equ hp_l_www_authenticate, . - hp_s_www_authenticate - 1

// non-empty values
hp_v_get:
    .asciz "GET"
.equ hp_l_get, . - hp_v_get - 1
hp_v_post:
    .asciz "POST"
.equ hp_l_post, . - hp_v_post - 1
hp_v_slash:
    .asciz "/"
.equ hp_l_slash, . - hp_v_slash - 1
hp_v_index:
    .asciz "/index.html"
.equ hp_l_index, . - hp_v_index - 1
hp_v_http:
    .asciz "http"
.equ hp_l_http, . - hp_v_http - 1
hp_v_https:
    .asciz "https"
.equ hp_l_https, . - hp_v_https - 1
hp_v_200:
    .asciz "200"
.equ hp_l_200, . - hp_v_200 - 1
hp_v_204:
    .asciz "204"
.equ hp_l_204, . - hp_v_204 - 1
hp_v_206:
    .asciz "206"
.equ hp_l_206, . - hp_v_206 - 1
hp_v_304:
    .asciz "304"
.equ hp_l_304, . - hp_v_304 - 1
hp_v_400:
    .asciz "400"
.equ hp_l_400, . - hp_v_400 - 1
hp_v_404:
    .asciz "404"
.equ hp_l_404, . - hp_v_404 - 1
hp_v_500:
    .asciz "500"
.equ hp_l_500, . - hp_v_500 - 1
hp_v_gzip_deflate:
    .asciz "gzip, deflate"
.equ hp_l_gzip_deflate, . - hp_v_gzip_deflate - 1

// ── RFC 7541 Appendix B — the static Huffman code ───────────────────
// (code length, code) plus a per-length start index. See the decoder
// below for how the two tables drive h2_huffman_decode.
.global h2_huffman_table
.global h2_huffman_len_start
#include "h2_huffman_table.S"

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

.text
.align 2

// ── 5.1 — integer decoding ───────────────────────────────────────────
// Decode the RFC 7541 §5.1 integer that starts at x0: the value sits in
// the low N bits of the first octet; if it equals 2^N - 1, continuation
// octets follow (7 payload bits each, continuation bit 0x80, most
// significant group first). The bits above N in the first octet belong
// to the field representation and are ignored.
//
// Values are bounded to 32 bits: an encoding that would overflow — or
// that is longer than a 32-bit value needs — is a decoding error
// (COMPRESSION_ERROR). This also bounds the read loop, so a hostile
// block can never make the decoder walk off the end of memory or loop
// forever.
//
// input
// x0 -> first octet of the integer
// x1 = prefix length N (1..8)
//
// output
// success — carry clear, x0 = value, x1 = bytes consumed (>= 1)
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR
//
// clobbers x0, x1, x2, x3, x4, x5, x6, x7
h2_hpack_decode_int:
    mov w3, #1
    lsl w3, w3, w1              // 1 << N
    sub w3, w3, #1              // mask = 2^N - 1
    ldrb w2, [x0]               // first octet
    and w2, w2, w3              // prefix value (zero-extends to x2)
    mov w4, #1                  // bytes consumed
    cmp w2, w3
    b.lo .Lhpack_int_done       // value < mask — the single-octet form

    // multi-octet form: value = mask + Σ (octet & 0x7f) << (7 * i)
    mov x5, #0                  // shift amount
.Lhpack_int_loop:
    ldrb w6, [x0, x4]           // next continuation octet
    add x4, x4, #1              // consumed++
    cmp x5, #32                 // shift past the 32-bit value bound?
    b.hs .Lhpack_int_error      //   yes — over-long encoding
    and w7, w6, #0x7f           // payload bits
    lsl x7, x7, x5              // place them at their weight
    add x2, x2, x7              // value += chunk
    tbnz x2, #32, .Lhpack_int_error // value overflowed 32 bits
    add x5, x5, #7
    tbz w6, #7, .Lhpack_int_done
    b .Lhpack_int_loop

.Lhpack_int_done:
    mov x0, x2
    mov x1, x4
    cmn xzr, xzr                // success — carry clear
    ret
.Lhpack_int_error:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
    ret

// ── 5.2 — string decoding ────────────────────────────────────────────
// Decode the RFC 7541 §5.2 string that starts at x0. The H bit (§5.2)
// selects Huffman coding: a Huffman string's length prefix is decoded
// the same way, then h2_huffman_decode expands the code into
// h2_hpack_str_buf. The length is a 7-bit-prefix integer; the string
// data follows verbatim.
//
// input
// x0 -> first octet of the string representation
//
// output
// success — carry clear
//   x0 -> the string data (first byte)
//   x1 = string length in bytes
//   x2 = bytes consumed by the whole representation (prefix + data)
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR
//   (invalid Huffman padding, EOS symbol, output overflow)
//
// clobbers x0-x7, x19-x21, x30 (x19-x21/x30 saved/restored)
h2_hpack_decode_string:
    stp x19, x30, [sp, #-32]!
    str x20, [sp, #16]
    str x21, [sp, #24]
    mov x19, x0                 // input ptr — decode_int clobbers x0-x7
    ldrb w3, [x0]
    tbnz w3, #7, .Lhpack_str_huffman
    mov x1, #7                  // string length prefix is 7 bits (§5.2)
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x3, x0                  // length
    mov x4, x1                  // prefix bytes consumed
    add x0, x19, x4             // string data follows the length prefix
    mov x1, x3                  // length
    add x2, x4, x3              // total consumed = prefix + data
    ldp x19, x30, [sp], #32
    cmn xzr, xzr
    ret
.Lhpack_str_huffman:
    // Huffman-coded string (§5.2) — decode the length, then expand the
    // code with h2_huffman_decode into h2_hpack_str_buf
    mov x1, #7
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x20, x0                 // encoded length (bytes)
    mov x21, x1                 // prefix bytes consumed
    add x0, x19, x21            // the Huffman code bytes
    mov x1, x20
    bl h2_huffman_decode
    b.cs .Lhpack_str_error
    // h2_huffman_decode: x0 -> decoded, x1 = decoded len, x2 = consumed
    add x2, x21, x20            // total consumed = prefix + encoded bytes
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #32
    cmn xzr, xzr
    ret
.Lhpack_str_error:
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #32
    ret                         // carry + error already set

// ── 6.1 — static table lookup ────────────────────────────────────────
// Resolve a static-table index (RFC 7541 Appendix A) to its name and
// value. Index 0 and indices beyond the 61-entry static table are
// decoding errors — with the dynamic table disabled, there is nothing
// else an index could address.
//
// input
// x0 = index (1..61)
//
// output
// success — carry clear
//   x0 -> name, x1 = name length, x2 -> value, x3 = value length
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR (index out of range)
//
// clobbers x0-x4, x9
h2_hpack_static_lookup:
    cbz x0, .Lhpack_lookup_bad
    cmp x0, #H2_HPACK_STATIC_TABLE_SIZE
    b.hi .Lhpack_lookup_bad
    sub x0, x0, #1              // table is zero-based
    adr_l x9, h2_hpack_static_table
    lsl x0, x0, #5              // entry stride = H2_HPACK_ENTRY_SIZE (32)
    add x9, x9, x0
    ldr x0, [x9, #H2_HPACK_ENTRY_NAME_PTR]
    ldr x1, [x9, #H2_HPACK_ENTRY_NAME_LEN]
    ldr x2, [x9, #H2_HPACK_ENTRY_VALUE_PTR]
    ldr x3, [x9, #H2_HPACK_ENTRY_VALUE_LEN]
    cmn xzr, xzr
    ret
.Lhpack_lookup_bad:
    cmp xzr, xzr
    mov x0, #H2_ERR_COMPRESSION_ERROR
    ret

// ── 6.1-6.3 — one header field representation ────────────────────────
// Decode a single HPACK header field. The first octet's pattern bits
// select the representation:
//
//   1xxxxxxx  indexed header field (§6.1) — the name/value come from
//             the table, so the index must be 1..61 (index 0 is a
//             decoding error; the dynamic table would start at 62)
//   01xxxxxx  literal with incremental indexing (§6.2.1) — decoded like
//             the other literals but with a 6-bit name index, and never
//             stored (the dynamic table max size is 0, so an entry
//             "added" to it would be evicted immediately)
//   001xxxxx  dynamic table size update (§6.3) — only size 0 is
//             acceptable; anything above our advertised maximum (0) is
//             a decoding error, and size 0 is a no-op, not a field
//   0000xxxx  literal without indexing (§6.2.2): a 4-bit name index
//             (0 = a new name string follows) plus a value string
//   0001xxxx  literal never indexed (§6.2.3): identical structure, the
//             never-index hint is ignored by a decoder
//
// The decoded name and value point into the input block (zero-copy) or
// into h2_hpack_str_buf (Huffman-decoded).
//
// input
// x0 -> first octet of the field
//
// output
// success — carry clear
//   x0 -> next octet after the field
//   x1 -> name (0 for a size update — not a field, just advance)
//   x2 = name length
//   x3 -> value
//   x4 = value length
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR
//
// clobbers x0-x6, x9, x19, x20, x21, x30 (x19/x20/x21/x30 saved/restored)
h2_hpack_decode_field:
    stp x19, x30, [sp, #-48]!
    stp x20, x21, [sp, #16]
    str x22, [sp, #32]
    mov x21, x0                 // input ptr — survives the sub-calls
    ldrb w6, [x0]               // first octet
    tbz w6, #7, .Lhpack_field_not_indexed

    // ── indexed header field (§6.1) ────────────────────────────────
    mov x1, #7
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    cbz x0, .Lhpack_field_bad   // index 0 is never valid (§6.1)
    mov x6, x1                  // bytes consumed (the index octets)
    bl h2_hpack_static_lookup
    b.cs .Lhpack_field_err
    // lookup: x0 -> name, x1 = name len, x2 -> value, x3 = value len
    mov x4, x3
    mov x3, x2
    mov x2, x1
    mov x1, x0
    add x0, x21, x6             // next = input + consumed
    b .Lhpack_field_ok

.Lhpack_field_not_indexed:
    tbz w6, #6, .Lhpack_field_not_incremental
    // ── literal with incremental indexing (§6.2.1) — accepted, never
    // stored: our dynamic table max size is 0 (SETTINGS_HEADER_TABLE_SIZE
    // = 0), so an entry "added" to it would be evicted immediately. The
    // decode is identical to §6.2.2/§6.2.3, except the name index uses
    // a 6-bit prefix ──
    mov x1, #6
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    mov x6, x1                  // prefix bytes consumed
    cbz x0, .Lhpack_field_inc_new_name
    bl h2_hpack_static_lookup   // indexed name
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr — survives the string decode
    mov x20, x1                 // name len
    add x0, x21, x6             // the value string follows the index
    b .Lhpack_field_literal_value
.Lhpack_field_inc_new_name:
    // the value string follows the name string in the input block — x6
    // (the index prefix bytes) is clobbered by the name decode, so save
    // the name string's input start first
    add x22, x21, x6
    add x0, x21, x6             // the name string follows the index
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr
    mov x20, x1                 // name len
    add x0, x22, x2             // the value string follows the name
    b .Lhpack_field_literal_value

.Lhpack_field_not_incremental:
    tbz w6, #5, .Lhpack_field_literal
    // ── dynamic table size update (§6.3) ──
    mov x1, #5
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    cbnz x0, .Lhpack_field_bad  // any size above our max (0) is an error
    // size 0 — accepted no-op: not a header field, so name = 0 tells
    // the caller to skip it and just advance
    mov x0, x21
    add x0, x0, x1              // next = input + consumed
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    b .Lhpack_field_ok

.Lhpack_field_literal:
    // ── literal without indexing (§6.2.2) / never indexed (§6.2.3) ──
    // 4-bit name index; 0 means a new name string follows
    mov x1, #4
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    mov x6, x1                  // prefix bytes consumed
    cbz x0, .Lhpack_field_new_name
    bl h2_hpack_static_lookup   // indexed name
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr — survives the string decode
    mov x20, x1                 // name len
    add x0, x21, x6             // the value string follows the index
    b .Lhpack_field_literal_value
.Lhpack_field_new_name:
    // the value string follows the name string in the input block — x6
    // (the index prefix bytes) is clobbered by the name decode, so save
    // the name string's input start first
    add x22, x21, x6
    add x0, x21, x6             // the name string follows the index
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr
    mov x20, x1                 // name len
    add x0, x22, x2             // the value string follows the name
.Lhpack_field_literal_value:
    // remember where the value string starts in the input block — the
    // decode may put a Huffman-expanded value in h2_hpack_str_buf, so
    // `next` must come from the input position, never the value pointer
    mov x22, x0
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    // decode_string: x0 -> value, x1 = value len, x2 = consumed
    mov x3, x0                  // value ptr
    mov x4, x1                  // value len
    add x0, x22, x2             // next = value start + consumed
    mov x1, x19                 // name ptr
    mov x2, x20                 // name len

.Lhpack_field_ok:
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    cmn xzr, xzr                // success — carry clear
    ret

.Lhpack_field_bad:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhpack_field_err:
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    ret                         // carry + error already set

// ── a whole header block ─────────────────────────────────────────────
// Decode a complete HPACK header block (a HEADERS payload) into the
// fixed h2_hpack_fields array. Each field is one h2_hpack_decode_field
// call; size updates are skipped. The consumption of every
// representation is checked against the block length, so a truncated
// block is a decoding error instead of being partially accepted, and
// the fixed output area bounds the field count — a block that needs
// more than H2_HPACK_MAX_FIELDS is also a decoding error. On error the
// fields decoded so far remain readable, but the caller must treat the
// whole connection as failed (COMPRESSION_ERROR is a connection error,
// RFC 9113 §4.3).
//
// The field count lives in x20 (callee-saved): the decoder below can
// reach h2_huffman_decode, which clobbers the caller-saved x8.
//
// input
// x0 -> the block (HEADERS payload)
// x1 = block length in bytes
//
// output
// success — carry clear, x0 = field count (h2_hpack_fields[0..count-1])
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR
//
// clobbers x0-x9, x19-x22, x30 (saved/restored)
h2_hpack_decode_block:
    stp x19, x30, [sp, #-48]!
    stp x20, x21, [sp, #16]
    str x22, [sp, #32]
    mov x19, x0                 // cursor
    mov x21, x1                 // bytes remaining
    adr_l x22, h2_hpack_fields
    mov x20, #0                 // field count
    // a fresh Huffman output area for this block
    adr_l x9, h2_hpack_str_off
    str xzr, [x9]
.Lhpack_block_loop:
    cbz x21, .Lhpack_block_done
    mov x0, x19
    bl h2_hpack_decode_field
    b.cs .Lhpack_block_err
    sub x7, x0, x19             // bytes this representation consumed
    cmp x7, x21
    b.hi .Lhpack_block_bad      // more than remained — truncated block
    sub x21, x21, x7            // remaining -= consumed
    mov x19, x0                 // cursor = next
    cbz x1, .Lhpack_block_loop  // size update — not a header field
    cmp x20, #H2_HPACK_MAX_FIELDS
    b.hs .Lhpack_block_bad      // fixed decode area is full
    str x1, [x22, #H2_HPACK_FIELD_NAME_PTR]
    str x2, [x22, #H2_HPACK_FIELD_NAME_LEN]
    str x3, [x22, #H2_HPACK_FIELD_VALUE_PTR]
    str x4, [x22, #H2_HPACK_FIELD_VALUE_LEN]
    add x22, x22, #H2_HPACK_FIELD_SIZE
    add x20, x20, #1
    b .Lhpack_block_loop
.Lhpack_block_done:
    mov x0, x20
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    cmn xzr, xzr                // success — carry clear
    ret
.Lhpack_block_bad:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhpack_block_err:
    ldr x22, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x19, x30, [sp], #48
    ret                         // carry + error already set

// ── 5.2 — Huffman string decoding (RFC 7541 Appendix B) ─────────────
// Expand a Huffman-coded string into h2_hpack_str_buf at the current
// write offset (appending, so several Huffman strings decoded from one
// header block coexist). The bitstream is consumed MSB-first; after
// each bit the accumulated code is looked up in the range of table
// entries whose code length matches (h2_huffman_len_start[N]), so each
// look-up only scans the handful of same-length codes. A match emits
// the symbol and resets the accumulator. After the last byte the
// leftover bits are padding (§5.2): at most 7 bits, all ones — the
// most significant bits of the EOS code — and the EOS symbol itself is
// a decoding error.
//
// input
// x0 -> Huffman-coded bytes
// x1 = encoded byte count
//
// output
// success — carry clear
//   x0 -> decoded string (h2_hpack_str_buf + old write offset)
//   x1 = decoded byte count
//   x2 = encoded bytes consumed (== x1-in: the length field is exact)
// failure — carry set, x0 = H2_ERR_COMPRESSION_ERROR
//   (EOS symbol, invalid padding, output overflow)
//
// clobbers x0-x18, x19-x28 (saved/restored), x30
h2_huffman_decode:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    str x30, [sp, #80]
    mov x19, x0             // src
    mov x20, x1             // encoded byte count
    adr_l x9, h2_hpack_str_off
    ldr x21, [x9]           // write offset
    adr_l x22, h2_hpack_str_buf
    add x22, x22, x21       // output ptr
    mov x23, #0             // decoded byte count
    lsl x24, x20, #3        // total bits in the stream
    mov x25, #0             // bit position
    mov x26, #0             // accumulated code
    mov x27, #0             // accumulated code length

.Lhuff_bit_loop:
    cmp x25, x24
    b.hs .Lhuff_padding
    // bit = (src[pos >> 3] >> (7 - (pos & 7))) & 1
    lsr x8, x25, #3
    ldrb w2, [x19, x8]
    and w3, w25, #7
    mov w8, #7
    sub w3, w8, w3
    lsr w2, w2, w3
    and w2, w2, #1
    // acc = (acc << 1) | bit
    lsl x26, x26, #1
    orr x26, x26, x2
    add x27, x27, #1
    add x25, x25, #1
    // scan only the entries with this code length
    adr_l x9, h2_huffman_len_start
    ldr w2, [x9, x27, lsl #2]
    add x8, x27, #1
    ldr w3, [x9, x8, lsl #2]
    adr_l x10, h2_huffman_table
.Lhuff_scan:
    cmp x2, x3
    b.hs .Lhuff_bit_loop
    lsl x8, x2, #3          // entry offset (8 bytes each)
    ldr w11, [x10, x8]      // code (u32, LSB-aligned)
    cmp w11, w26
    b.ne .Lhuff_scan_next
    // code matched — check the output bound, then emit the symbol
    add x13, x8, #4
    ldr w11, [x10, x13]     // symbol (u32)
    cmp w11, #256
    b.eq .Lhuff_eos         // EOS inside a string is a decoding error
    add x12, x21, x23       // write offset + decoded so far
    cmp x12, #H2_HPACK_STR_BUF_SIZE
    b.hs .Lhuff_overflow
    strb w11, [x22, x23]
    add x23, x23, #1
    mov x26, #0
    mov x27, #0
    b .Lhuff_bit_loop
.Lhuff_scan_next:
    add x2, x2, #1
    b .Lhuff_scan

.Lhuff_padding:
    // the leftover bits are padding: at most 7, all ones (a prefix of
    // the EOS code, whose 30 bits are all ones)
    cmp x27, #7
    b.hi .Lhuff_bad_padding
    cbz x27, .Lhuff_done
    mov x8, #1
    lsl x8, x8, x27
    sub x8, x8, #1          // (1 << len) - 1 — all ones
    cmp x26, x8
    b.ne .Lhuff_bad_padding
.Lhuff_done:
    adr_l x9, h2_hpack_str_off
    add x21, x21, x23
    str x21, [x9]           // next string appends after this one
    mov x0, x22             // the decoded string start
    mov x1, x23             // decoded length
    mov x2, x20             // encoded bytes consumed
    cmn xzr, xzr            // success — carry clear
    b .Lhuff_epilogue
.Lhuff_eos:
.Lhuff_overflow:
.Lhuff_bad_padding:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhuff_epilogue:
    ldr x30, [sp, #80]
    ldp x27, x28, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
