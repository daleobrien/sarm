#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: child
//
// Description: Handle one client connection: set a receive timeout on
//   the socket, read the request into buf, detect the protocol (HTTP/2
//   client preface vs HTTP/1) on the first read, and find the header
//   terminator (read_loop/Lheader_found/Lno_header). The 2: block then
//   logs the request, verifies the HTTP version,
//   parses the request, and dispatches GET/HEAD/OPTIONS to the http1
//   handlers. read_failed maps read errors to a silent close, a 408, or
//   a 500 via the reply_status trampolines at the bottom of the file.
//
// Input/Arguments:
//   (none — uses the clientfd global set by the accept loop)
//
// Output/Returns:
//   (never returns — branches to child_end or a reply_status trampoline)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x7, x22, x23, x24, x25
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



    // read(client_fd, buffer, buffer_size)
    mov x7, #0
    mov x25, #0 // protocol not yet detected (0 = undetected, 1 = decided)
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
