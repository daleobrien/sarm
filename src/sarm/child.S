#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: child
//
// Description: Handle one client connection: set a receive timeout on
//   the socket, read the request into buf, detect the protocol (HTTP/2
//   client preface vs HTTP/1) on the first read, and find the header
//   terminator (Lcheck_leftover/read_loop/Lheader_found/Lno_header). The
//   2: block then logs the request, verifies the HTTP version, parses
//   the request, and dispatches GET/HEAD/OPTIONS to the http1 handlers.
//   read_failed maps read errors to a silent close, a 408, or a 500 via
//   the reply_status trampolines at the bottom of the file.
//
//   Every handler tail-branches to http1_keepalive_continue once its
//   response is written (Plan.md Phase 1, Step 6) rather than always
//   going to child_end: on keep-alive it resets per-request state,
//   shifts any leftover pipelined bytes (Step 5) to the front of buf,
//   and resumes at Lcheck_leftover — the same entry a fresh connection
//   uses, so a complete next request already sitting in the leftover
//   bytes is served without blocking in read() for more.
//
// Input/Arguments:
//   (none — uses the clientfd global set by the accept loop)
//
// Output/Returns:
//   (never returns — branches to child_end or a reply_status trampoline)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x7, x9, x16, x22, x23, x24, x25, x30
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
.global rcv_timeout    // main.S arms the same timeout on the TLS path
rcv_timeout:           // struct timeval for SO_RCVTIMEO
    .quad RECV_TIMEOUT // tv_sec
    .quad 0            // tv_usec

.text
.align 2
.global child
child:
    // setsockopt() with a SO_RCVTIMEO timeout from config.S, to prevent
    // connections from staying open indefinitely
    SCWINUM SYS_setsockopt
    ldr_l x0, clientfd
    mov x1, #SOL_SOCKET
    mov x2, #SO_RCVTIMEO
    adr_l x3, rcv_timeout
    mov x4, #16 // struct timeval is 16 bytes
    SCWISVC
    SCERR
    b.cs Lchild_end

#ifndef __linux__
    // setsockopt(), SO_NOSIGPIPE (macOS only; Linux ignores SIGPIPE instead)
    SCWINUM SYS_setsockopt
    ldr_l x0, clientfd
    mov x1, #SOL_SOCKET
    mov x2, #SO_NOSIGPIPE
    adr_l x3, one
    mov x4, #4
    SCWISVC
    SCERR
    b.cs Lchild_end
#endif



    // one keep-alive request budget for the whole connection (Plan.md
    // Phase 1, Step 6) -- decremented per request at Lheader_found.
    mov x0, #HTTP1_KEEPALIVE_BUDGET
    str_l x0, request_budget, x9

    // read(client_fd, buffer, buffer_size)
    mov x7, #0
    mov x25, #0 // protocol not yet detected (0 = undetected, 1 = decided)

// Entry point for both a fresh connection (x7 == 0, falls straight
// through to read_loop) and a kept-alive connection resuming with
// leftover pipelined bytes already in buf (Step 5): check whether a
// full header is already sitting in those bytes before blocking in
// read() for more. http1_keepalive_continue below is the other caller.
Lcheck_leftover:
    cbz x7, read_loop
    adr_l x0, buf
    mov x1, x7
    bl parse_header_end
    cmp x1, #0
    b.ne Lheader_found
    // no complete header in the leftover bytes yet -- need to read more,
    // unless the buffer is already full without ever finding one.
    cmp x7, #BUF_SIZE
    b.ge L431
    b read_loop

read_loop:
    SCWINUM SYS_read
    ldr_l x0, clientfd
    adr_l x1, buf
    add x1, x1, x7 // account for buffer being partially filled
    mov x22, #BUF_SIZE
    sub x2, x22, x7 // BUF_SIZE - bytes_read
    SCWISVC
    SCERR
    b.cs read_failed
    mov x22, x0 // stash number of bytes read() got in x22

    add x7, x7, x0 // save x0 because parse_header_end clobbers it. cumulatively

    // ── protocol detection — the first data decides HTTP/2 vs HTTP/1 ──
    // The HTTP/2 client connection preface ("PRI * HTTP/2.0\r\n\r\n...")
    // starts every HTTP/2 connection (RFC 9113 §3.4); if the buffered
    // bytes match its prefix, hand the connection to the HTTP/2 loop,
    // which finishes reading the preface and then serves frames. Anything
    // else keeps the existing HTTP/1 flow. The bytes are never consumed
    // here, so both paths see the same data (Phase 16, Option B).
    cbnz x25, 1f          // already decided — skip
    mov x25, #1           // detect once, on the first data
    adr_l x0, buf
    mov x1, x7
    bl h2_probe
    cbz x0, 1f            // not the preface → HTTP/1
    ldr_l x0, clientfd
    adr_l x1, buf
    mov x2, x7
    bl h2_connection_loop
    b child_end           // the loop returns when the connection ends
1:
    adr_l x0, buf
    mov x1, x7
    bl parse_header_end
    cmp x1, #0
    b.eq Lno_header

    // header end was found, break out of the karmic cycle of reading
    b Lheader_found

Lheader_found:
    mov x23, x1 // end of header index (one byte after \r\n\r\n)
    mov x24, x7 // total bytes
    str_l x23, request_header_len, x9 // for http1_should_keep_alive (Step 3)
    str_l x24, request_total_len, x9  // for the leftover-bytes shift (Step 5)

    ldr_l x9, request_budget
    sub x9, x9, #1
    str_l x9, request_budget, x10

    b 2f // break from the hell of reading

Lno_header:
    cmp x22, #0 // x22 is number of bytes from read() now
    b.ne 1f // if nonzero, check buffer fill state
    cmp x7, #0 // if we read nothing,
    b.eq Lchild_end // go to child_end and silently exit

    // otherwise if we're done reading but still no header, send 400
    b L400

1:
    cmp x7, #BUF_SIZE
    b.ge L431

    b read_loop

read_failed:
    // if read was interrupted by a signal, retry instead of exiting. doesn't
    // affect x7/buf offset.
    cmp x0, #EINTR
    b.eq read_loop
    // check if errno is ECONNRESET, ECONNABORTED, etc — silently exit.
    // ETIMEDOUT from SO_RCVTIMEO sends a 408 before closing.
    cb eq, x0, #ECONNRESET, Lchild_end
    cb eq, x0, #ETIMEDOUT, L408
    cb eq, x0, #ECONNABORTED, Lchild_end
    cb eq, x0, #EPIPE, Lchild_end
    cb eq, x0, #ENETDOWN, Lchild_end
    cb eq, x0, #ENETUNREACH, Lchild_end
    cb eq, x0, #ENETRESET, Lchild_end
    cb eq, x0, #EHOSTDOWN, Lchild_end
    cb eq, x0, #EHOSTUNREACH, Lchild_end

    b L500

2:
    // let's make sure buf is NULL terminated
    adr_l x1, buf
    strb wzr, [x1, x24] // x24 -> length of bytes read

    adr_l x0, buf
    mov x1, x23
    bl verify_http_version

    // ── parse the request into the protocol-neutral request struct, then
    // dispatch on the parsed method (parse → request → dispatch) ──
    adr_l x0, buf
    mov x1, x23
    bl parse_request
    b.cs L400

    adr_l x9, request
    ldr w0, [x9, #REQ_METHOD]
    cmp w0, #GET_ID
    b.eq Lget_method
    cmp w0, #HEAD_ID
    b.eq Lhead_method
    cmp w0, #OPTIONS_ID
    b.eq Loptions_method
    cmp w0, #BREW_ID
    b.eq L418

    // none of the above — unknown method
    b L501

Lget_method:
    adr_l x0, buf
    mov x1, x23
    b get

Lhead_method:
    b head

Loptions_method:
    b options

L400:
    mov x0, #400
    mov x1, #0
    b reply_status
L408:
    mov x0, #408
    mov x1, #0
    b reply_status
L418:
    mov x0, #418
    mov x1, #0
    b reply_status
L431:
    mov x0, #431
    mov x1, #0
    b reply_status
L500:
    mov x0, #500
    mov x1, #0
    b reply_status
L501:
    mov x0, #501
    mov x1, #0
    b reply_status

// local trampoline: b.cond/cbz can't reach child_end across files
Lchild_end:
    b child_end

// ─────────────────────────────────────────────────────────────────────
// Function Name: http1_keepalive_continue
//
// Description: The shared continuation every HTTP/1 response handler
//   (get, head, reply_status) tail-branches to once a response has been
//   written, instead of always going straight to child_end (Plan.md
//   Phase 1, Step 6). Reads keep_alive_decision — set by
//   http1_write_response for the response that was just sent, so this
//   always agrees with the Connection: header the client just received.
//   Close (keep_alive_decision == 0): behaves exactly as before this
//   step, branching to child_end. Keep alive: resets per-request state
//   (http1_reset_request), shifts any leftover pipelined bytes in `buf`
//   to the front (Step 5), and resumes the connection at
//   Lcheck_leftover — the same entry point a fresh connection uses,
//   just with x7 possibly nonzero and x25 already 1 (protocol stays
//   decided for the life of the connection).
//
// Input/Arguments:
//   (none — reads the keep_alive_decision / request_header_len /
//   request_total_len globals)
//
// Output/Returns:
//   (never returns — branches to child_end or Lcheck_leftover)
//
// Clobbered Registers:
//   x0-x4, x7, x9, x10, x25, x30
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────
.global http1_keepalive_continue
http1_keepalive_continue:
    ldr_l x0, keep_alive_decision
    cbz x0, Lchild_end

    bl http1_reset_request

    // load x10 first: ldr_l's default scratch is x9, so loading into x9
    // second (last) avoids the second call's address computation
    // clobbering the value the first call just loaded into x9.
    ldr_l x10, request_total_len
    ldr_l x9, request_header_len
    subs x7, x10, x9
    b.gt Lhkc_shift
    mov x7, #0
    b Lhkc_resume

Lhkc_shift:
    // move the leftover pipelined bytes (the start of the next request)
    // to the front of buf -- safe as an ascending memcpy since dst < src
    adr_l x0, buf
    adr_l x1, buf
    add x1, x1, x9
    mov x2, x7
    bl memcpy

Lhkc_resume:
    mov x25, #1 // protocol already decided for this connection
    b Lcheck_leftover
