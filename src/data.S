#include "defs.S"



.data
.align 4 // 16-byte alignment for every string and buffer
OBJECT file_des
              .quad -1 // file descriptor for GET/HEAD and stuff. should be
                       // initialized to -1 so we can check if it's set.
ENDOBJ file_des

// connection_mode — protocol in use on the current connection
// (CONNECTION_HTTP1 / CONNECTION_HTTP2, see defs.S). Defaults to HTTP/1,
// which keeps existing connections untouched; h2_verify_preface sets it
// to CONNECTION_HTTP2 once the client preface checks out.
.align 4
OBJECT connection_mode
                 .quad CONNECTION_HTTP1
ENDOBJ connection_mode

// worker_count — how many pre-forked accept workers to run (Plan.md
// Phase 3, Step 14), set by `--workers N` / `--workers auto`. Default 1,
// which is bit-identical to the pre-Phase-3 server: main.S forks no
// workers at all and runs the accept loop in the original process.
// Clamped to [1, MAX_WORKERS] (config.S) at parse time, so every later
// reader can trust the value without re-checking it. Lives in .data
// rather than .bss precisely because its default is nonzero.
.align 4
OBJECT worker_count
              .quad 1
ENDOBJ worker_count

rodata
// h2_preface — the 24-byte HTTP/2 client connection preface
// (RFC 9113 §3.4), compared byte-for-byte by h2_verify_preface. Read
// with three 8-byte loads (h2_verify_preface), so it starts 16-aligned
// and is padded out to a 16-byte multiple.
.align 4
OBJECT h2_preface
    .ascii "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
.equ h2_preface_len, . - h2_preface
ENDOBJ h2_preface
    .align 4 // pad the 24-byte string to 32 bytes

.bss
// + 1 so we can NULL terminate, even if content is BUF_SIZE bytes long.
// The size is rounded up to a 16-byte multiple so the buffers that follow
// stay 16-aligned without extra padding.
.align 4
OBJECT buf
              .skip (BUF_SIZE + 1 + 15) & ~15
ENDOBJ buf

// request — protocol-neutral request representation (the HTTP/2 seam).
// Fixed layout; offsets defined in defs.S (REQ_METHOD, REQ_PATH, ...).
// Filled by parse_request in parse.S for HTTP/1; an HTTP/2 HEADERS
// decoder will fill the same struct later.
.align 4
OBJECT request
              .skip REQUEST_SIZE
ENDOBJ request

// response — protocol-neutral response representation (the seam the
// HTTP/1 and future HTTP/2 encoders share). Fixed layout; offsets in
// defs.S (RESP_STATUS, RESP_CONTENT_TYPE, ...). Filled by the handlers
// (get/head/reply_status), consumed by http1_write_response.
.align 4
OBJECT response
              .skip RESPONSE_SIZE
ENDOBJ response

// Per-request state. Note: the protocol-neutral request fields (path,
// query, authority, stream_id) live in the separate `request` struct
// above, filled by parse_request. The old filename_str/filename_len/
// query_str/query_len/docroot_len globals were removed in Stage 1 (they
// were the parser driving response generation directly).
//
// 8-byte values padded to 16-byte slots — every field starts on a
// 16-byte boundary, and each is only ever reached through its own label.
OBJECT header_len
              .skip 16
ENDOBJ header_len
OBJECT clientfd
              .skip 16
ENDOBJ clientfd
OBJECT resource_type
                  .skip 16
ENDOBJ resource_type

// request_header_len — length of the raw request header currently in
// `buf` (one byte past the final \r\n\r\n), set by child.S once the
// header terminator is found. http1_should_keep_alive reads it (via
// http1_write_response) to detect Connection/Content-Length/
// Transfer-Encoding on the request that produced the response being
// encoded — see Plan.md Phase 1, Step 3.
OBJECT request_header_len
                    .skip 16
ENDOBJ request_header_len

// request_total_len — total bytes in `buf` when the header terminator was
// found (request_header_len <= this). The difference is leftover
// pipelined bytes belonging to the next request; http1_keepalive_continue
// (child.S) shifts them to the front of buf before resuming the read loop
// — see Plan.md Phase 1, Step 5.
OBJECT request_total_len
                   .skip 16
ENDOBJ request_total_len

// request_budget — requests remaining on this connection before sarm
// sends Connection: close and ends it (HTTP1_KEEPALIVE_BUDGET in
// config.S), decremented per request by child.S. http1_write_response
// ANDs "budget > 0" into the keep-alive decision alongside
// http1_should_keep_alive's result — see Plan.md Phase 1, Step 6.
OBJECT request_budget
                .skip 16
ENDOBJ request_budget

// keep_alive_decision — the keep-alive/close decision http1_write_response
// just made for the response it encoded (http1_should_keep_alive's result,
// ANDed with request_budget > 0). http1_keepalive_continue reads this
// after the handler returns, so the loop-vs-close behavior always matches
// the Connection: header the client just received, by construction.
OBJECT keep_alive_decision
                     .skip 16
ENDOBJ keep_alive_decision

OBJECT embedded_content
                  .skip 16
ENDOBJ embedded_content
OBJECT embedded_ct
                  .skip 16
ENDOBJ embedded_ct
OBJECT embedded_ct_len
                  .skip 16
ENDOBJ embedded_ct_len
OBJECT embedded_gzip
                  .skip 16
ENDOBJ embedded_gzip
OBJECT embedded_etag
                  .skip 16
ENDOBJ embedded_etag
OBJECT embedded_etag_len
                  .skip 16

.align 4
// no_fork — nonzero when argv[1] was a debug letter rather than a port.
// The accept loop then serves each connection inline, one at a time,
// so a debugger stays attached to the process doing the work; child_end
// reads it to decide whether to exit (a forked child) or loop back to
// accept (the debug, single-process case).
ENDOBJ embedded_etag_len
OBJECT no_fork
              .skip 8
ENDOBJ no_fork
