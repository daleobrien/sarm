#include "defs.S"

.global file_des
.global buf
.global header_len
.global clientfd
.global filename_str
.global filename_len
.global docroot_len
.global query_str
.global query_len
.global request_id
.global resource_type

.global embedded_content
.global embedded_ct
.global embedded_ct_len
.global embedded_gzip
.global embedded_etag
.global embedded_etag_len
.global request_ctx

.data
file_des:     .quad -1 // file descriptor for GET/HEAD and stuff. should be
                       // initialized to -1 so we can check if it's set.
.bss
// + 1 so we can NULL terminate, even if content is BUF_SIZE bytes long
buf:          .skip BUF_SIZE + 1
.align 3 // + 1 breaks alignment

// request_ctx — unified per-request state block.
// Offsets defined in defs.S (CTX_HEADER_LEN, CTX_CLIENT_FD, ...).
// Functions access via:  adr_l x19, request_ctx
//                          ldr x0, [x19, #CTX_FILENAME_STR]
request_ctx:
header_len:   .skip 8      // CTX_HEADER_LEN
clientfd:     .skip 8      // CTX_CLIENT_FD
filename_str: .skip 8      // CTX_FILENAME_STR
filename_len: .skip 8      // CTX_FILENAME_LEN
query_str:    .skip 8      // CTX_QUERY_STR
query_len:    .skip 8      // CTX_QUERY_LEN
docroot_len:      .skip 8  // CTX_DOCROOT_LEN
request_id:       .skip 8  // CTX_REQUEST_ID
resource_type:    .skip 8  // CTX_RESOURCE_TYPE

embedded_content: .skip 8  // CTX_EMBED_CONTENT
embedded_ct:      .skip 8  // CTX_EMBED_CT
embedded_ct_len:  .skip 8  // CTX_EMBED_CT_LEN
embedded_gzip:    .skip 8  // CTX_EMBED_GZIP
embedded_etag:    .skip 8  // CTX_EMBED_ETAG
embedded_etag_len:.skip 8  // CTX_EMBED_ETAG_LEN
