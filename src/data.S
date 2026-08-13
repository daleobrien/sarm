#include "defs.S"

.global file_des
.global buf
.global header_len
.global clientfd
.global request_id
.global resource_type
.global response_code

.global embedded_content
.global embedded_ct
.global embedded_ct_len
.global embedded_gzip
.global embedded_etag
.global embedded_etag_len
.global req_start
.global req_end
.global request_ctx
.global request
.global response

.data
file_des:     .quad -1 // file descriptor for GET/HEAD and stuff. should be
                       // initialized to -1 so we can check if it's set.
.bss
// + 1 so we can NULL terminate, even if content is BUF_SIZE bytes long
buf:          .skip BUF_SIZE + 1
.align 3 // + 1 breaks alignment

// request — protocol-neutral request representation (the HTTP/2 seam).
// Fixed layout; offsets defined in defs.S (REQ_METHOD, REQ_PATH, ...).
// Filled by parse_request in parse.S for HTTP/1; an HTTP/2 HEADERS
// decoder will fill the same struct later.
.align 3
request:      .skip REQUEST_SIZE

// response — protocol-neutral response representation (the seam the
// HTTP/1 and future HTTP/2 encoders share). Fixed layout; offsets in
// defs.S (RESP_STATUS, RESP_CONTENT_TYPE, ...). Filled by the handlers
// (get/head/reply_status), consumed by http1_write_response.
.align 3
response:     .skip RESPONSE_SIZE

// request_ctx — unified per-request state block.
// Note: the protocol-neutral request fields (path, query, authority,
// stream_id) live in the separate `request` struct above, filled by
// parse_request. The old filename_str/filename_len/query_str/query_len/
// docroot_len globals were removed in Stage 1 (they were the parser
// driving response generation directly).
request_ctx:
header_len:   .skip 8
clientfd:     .skip 8
request_id:       .skip 8
resource_type:    .skip 8

embedded_content: .skip 8
embedded_ct:      .skip 8
embedded_ct_len:  .skip 8
embedded_gzip:    .skip 8
embedded_etag:    .skip 8
embedded_etag_len:.skip 8

.align 3
req_start:    .skip 16 // struct timeval for request start
.align 3
req_end:      .skip 16 // struct timeval for request end
.align 3
response_code: .skip 8 // HTTP status code for log
