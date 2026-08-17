#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_static_lookup
//
// Description: Resolve a static-table index (RFC 7541 Appendix A) to
//   its name and value. Index 0 and indices beyond the 61-entry static
//   table are decoding errors here — callers that need the combined
//   static+dynamic address space (RFC 7541 §2.3.3) go through
//   h2_hpack_table_lookup instead, which routes indices above 61 to
//   the dynamic table (hpack/dynamic_table/). This file also holds the
//   table and its strings (h2_hpack_static_table, hp_* labels);
//   h2_hpack_static_lookup is their only consumer.
//
// Input/Arguments:
//   x0 — index (1..61)
//
// Output/Returns:
//   x0 — name pointer
//   x1 — name length
//   x2 — value pointer
//   x3 — value length
//   (carry clear = success / carry set = failure — index out of range,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
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
.align 4
hp_empty:
    .asciz ""

// names, in table order
.align 4
hp_s_authority:
    .asciz ":authority"
.equ hp_l_authority, . - hp_s_authority - 1
.align 4
hp_s_method:
    .asciz ":method"
.equ hp_l_method, . - hp_s_method - 1
.align 4
hp_s_path:
    .asciz ":path"
.equ hp_l_path, . - hp_s_path - 1
.align 4
hp_s_scheme:
    .asciz ":scheme"
.equ hp_l_scheme, . - hp_s_scheme - 1
.align 4
hp_s_status:
    .asciz ":status"
.equ hp_l_status, . - hp_s_status - 1
.align 4
hp_s_accept_charset:
    .asciz "accept-charset"
.equ hp_l_accept_charset, . - hp_s_accept_charset - 1
.align 4
hp_s_accept_encoding:
    .asciz "accept-encoding"
.equ hp_l_accept_encoding, . - hp_s_accept_encoding - 1
.align 4
hp_s_accept_language:
    .asciz "accept-language"
.equ hp_l_accept_language, . - hp_s_accept_language - 1
.align 4
hp_s_accept_ranges:
    .asciz "accept-ranges"
.equ hp_l_accept_ranges, . - hp_s_accept_ranges - 1
.align 4
hp_s_accept:
    .asciz "accept"
.equ hp_l_accept, . - hp_s_accept - 1
.align 4
hp_s_access_control_allow_origin:
    .asciz "access-control-allow-origin"
.equ hp_l_access_control_allow_origin, . - hp_s_access_control_allow_origin - 1
.align 4
hp_s_age:
    .asciz "age"
.equ hp_l_age, . - hp_s_age - 1
.align 4
hp_s_allow:
    .asciz "allow"
.equ hp_l_allow, . - hp_s_allow - 1
.align 4
hp_s_authorization:
    .asciz "authorization"
.equ hp_l_authorization, . - hp_s_authorization - 1
.align 4
hp_s_cache_control:
    .asciz "cache-control"
.equ hp_l_cache_control, . - hp_s_cache_control - 1
.align 4
hp_s_content_disposition:
    .asciz "content-disposition"
.equ hp_l_content_disposition, . - hp_s_content_disposition - 1
.align 4
hp_s_content_encoding:
    .asciz "content-encoding"
.equ hp_l_content_encoding, . - hp_s_content_encoding - 1
.align 4
hp_s_content_language:
    .asciz "content-language"
.equ hp_l_content_language, . - hp_s_content_language - 1
.align 4
hp_s_content_length:
    .asciz "content-length"
.equ hp_l_content_length, . - hp_s_content_length - 1
.align 4
hp_s_content_location:
    .asciz "content-location"
.equ hp_l_content_location, . - hp_s_content_location - 1
.align 4
hp_s_content_range:
    .asciz "content-range"
.equ hp_l_content_range, . - hp_s_content_range - 1
.align 4
hp_s_content_type:
    .asciz "content-type"
.equ hp_l_content_type, . - hp_s_content_type - 1
.align 4
hp_s_cookie:
    .asciz "cookie"
.equ hp_l_cookie, . - hp_s_cookie - 1
.align 4
hp_s_date:
    .asciz "date"
.equ hp_l_date, . - hp_s_date - 1
.align 4
hp_s_etag:
    .asciz "etag"
.equ hp_l_etag, . - hp_s_etag - 1
.align 4
hp_s_expect:
    .asciz "expect"
.equ hp_l_expect, . - hp_s_expect - 1
.align 4
hp_s_expires:
    .asciz "expires"
.equ hp_l_expires, . - hp_s_expires - 1
.align 4
hp_s_from:
    .asciz "from"
.equ hp_l_from, . - hp_s_from - 1
.align 4
hp_s_host:
    .asciz "host"
.equ hp_l_host, . - hp_s_host - 1
.align 4
hp_s_if_match:
    .asciz "if-match"
.equ hp_l_if_match, . - hp_s_if_match - 1
.align 4
hp_s_if_modified_since:
    .asciz "if-modified-since"
.equ hp_l_if_modified_since, . - hp_s_if_modified_since - 1
.align 4
hp_s_if_none_match:
    .asciz "if-none-match"
.equ hp_l_if_none_match, . - hp_s_if_none_match - 1
.align 4
hp_s_if_range:
    .asciz "if-range"
.equ hp_l_if_range, . - hp_s_if_range - 1
.align 4
hp_s_if_unmodified_since:
    .asciz "if-unmodified-since"
.equ hp_l_if_unmodified_since, . - hp_s_if_unmodified_since - 1
.align 4
hp_s_last_modified:
    .asciz "last-modified"
.equ hp_l_last_modified, . - hp_s_last_modified - 1
.align 4
hp_s_link:
    .asciz "link"
.equ hp_l_link, . - hp_s_link - 1
.align 4
hp_s_location:
    .asciz "location"
.equ hp_l_location, . - hp_s_location - 1
.align 4
hp_s_max_forwards:
    .asciz "max-forwards"
.equ hp_l_max_forwards, . - hp_s_max_forwards - 1
.align 4
hp_s_proxy_authenticate:
    .asciz "proxy-authenticate"
.equ hp_l_proxy_authenticate, . - hp_s_proxy_authenticate - 1
.align 4
hp_s_proxy_authorization:
    .asciz "proxy-authorization"
.equ hp_l_proxy_authorization, . - hp_s_proxy_authorization - 1
.align 4
hp_s_range:
    .asciz "range"
.equ hp_l_range, . - hp_s_range - 1
.align 4
hp_s_referer:
    .asciz "referer"
.equ hp_l_referer, . - hp_s_referer - 1
.align 4
hp_s_refresh:
    .asciz "refresh"
.equ hp_l_refresh, . - hp_s_refresh - 1
.align 4
hp_s_retry_after:
    .asciz "retry-after"
.equ hp_l_retry_after, . - hp_s_retry_after - 1
.align 4
hp_s_server:
    .asciz "server"
.equ hp_l_server, . - hp_s_server - 1
.align 4
hp_s_set_cookie:
    .asciz "set-cookie"
.equ hp_l_set_cookie, . - hp_s_set_cookie - 1
.align 4
hp_s_strict_transport_security:
    .asciz "strict-transport-security"
.equ hp_l_strict_transport_security, . - hp_s_strict_transport_security - 1
.align 4
hp_s_transfer_encoding:
    .asciz "transfer-encoding"
.equ hp_l_transfer_encoding, . - hp_s_transfer_encoding - 1
.align 4
hp_s_user_agent:
    .asciz "user-agent"
.equ hp_l_user_agent, . - hp_s_user_agent - 1
.align 4
hp_s_vary:
    .asciz "vary"
.equ hp_l_vary, . - hp_s_vary - 1
.align 4
hp_s_via:
    .asciz "via"
.equ hp_l_via, . - hp_s_via - 1
.align 4
hp_s_www_authenticate:
    .asciz "www-authenticate"
.equ hp_l_www_authenticate, . - hp_s_www_authenticate - 1

// non-empty values
.align 4
hp_v_get:
    .asciz "GET"
.equ hp_l_get, . - hp_v_get - 1
.align 4
hp_v_post:
    .asciz "POST"
.equ hp_l_post, . - hp_v_post - 1
.align 4
hp_v_slash:
    .asciz "/"
.equ hp_l_slash, . - hp_v_slash - 1
.align 4
hp_v_index:
    .asciz "/index.html"
.equ hp_l_index, . - hp_v_index - 1
.align 4
hp_v_http:
    .asciz "http"
.equ hp_l_http, . - hp_v_http - 1
.align 4
hp_v_https:
    .asciz "https"
.equ hp_l_https, . - hp_v_https - 1
.align 4
hp_v_200:
    .asciz "200"
.equ hp_l_200, . - hp_v_200 - 1
.align 4
hp_v_204:
    .asciz "204"
.equ hp_l_204, . - hp_v_204 - 1
.align 4
hp_v_206:
    .asciz "206"
.equ hp_l_206, . - hp_v_206 - 1
.align 4
hp_v_304:
    .asciz "304"
.equ hp_l_304, . - hp_v_304 - 1
.align 4
hp_v_400:
    .asciz "400"
.equ hp_l_400, . - hp_v_400 - 1
.align 4
hp_v_404:
    .asciz "404"
.equ hp_l_404, . - hp_v_404 - 1
.align 4
hp_v_500:
    .asciz "500"
.equ hp_l_500, . - hp_v_500 - 1
.align 4
hp_v_gzip_deflate:
    .asciz "gzip, deflate"
.equ hp_l_gzip_deflate, . - hp_v_gzip_deflate - 1
.align 4

.text
.align 2
.global h2_hpack_static_lookup
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
