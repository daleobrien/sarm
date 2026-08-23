#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: child / child_with_data
//
// Description: Handle one client connection: read the request into buf
//   (the receive timeout is already armed by main.S), detect the protocol (HTTP/2
//   client preface vs HTTP/1) on the first read, and find the header
//   terminator (Lcheck_leftover/read_loop/Lread_got_data/Lheader_found/
//   Lno_header). The 2: block then logs the request, verifies the HTTP
//   version, parses the request, and dispatches GET/HEAD/OPTIONS to the
//   http1 handlers. read_failed maps read errors to a silent close, a
//   408, or a 500 via the reply_status trampolines at the bottom of the
//   file.
//
//   Two entry points share everything past socket setup:
//     - `child` — fresh connection, nothing read yet; blocks in
//       read_loop for the first bytes as before.
//     - `child_with_data` — fresh connection whose first bytes main.S
//       already read for real, off the accept-time protocol-detection
//       read (Plan.md Phase 2, Step 9, which replaced a MSG_PEEK that
//       used to leave those bytes for child to read again). Skips
//       straight to Lread_got_data with those bytes already accounted
//       for in x7, so they're never read twice.
//
//   Every handler tail-branches to http1_keepalive_continue once its
//   response is written (Plan.md Phase 1, Step 6) rather than always
//   going to child_end: on keep-alive it resets per-request state,
//   shifts any leftover pipelined bytes (Step 5) to the front of buf,
//   and resumes at Lcheck_leftover — the same entry a fresh connection
//   uses, so a complete next request already sitting in the leftover
//   bytes is served without blocking in read() for more. (Lcheck_leftover
//   only checks for an already-complete header, not the h2 preface —
//   that's already been decided earlier in the same connection by then.)
//
// Input/Arguments:
//   child: none. child_with_data: x0 = bytes already read (> 0).
//   Both use the clientfd global set by the accept loop.
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

rodata
.align 4
.global rcv_timeout    // main.S arms the same timeout on the TLS path
rcv_timeout:           // struct timeval for SO_RCVTIMEO
    .quad RECV_TIMEOUT // tv_sec
    .quad 0            // tv_usec

.text
.align 2
.global child
child:
    mov x22, #0                 // fresh connection, nothing read yet
    b Lchild_common

// Entry for a fresh connection whose first bytes were already read for
// real by main.S's accept-time read (Plan.md Phase 2, Step 9 — replaces
// the old MSG_PEEK). Falls into the same socket setup `child` uses,
// then resumes exactly where read_loop would be after that first read()
// completed, instead of blocking to read the same bytes again.
//
// Input: x0 = bytes already read (> 0; main.S handles the 0-byte/error
// cases itself before ever branching here).
.global child_with_data
child_with_data:
    mov x22, x0

Lchild_common:
    // SO_RCVTIMEO is armed once, in main.S's Lmain_serve, before the
    // protocol read — that covers this (plaintext) path too, so setting
    // it again here would just be a second syscall for the same socket
    // option (Plan.md Phase 2, Step 8).

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

    mov x7, x22 // 0 for `child`; bytes already read for `child_with_data`
    mov x25, #0 // protocol not yet detected (0 = undetected, 1 = decided)

    // `child_with_data` already has real bytes in buf and needs the
    // full post-read handling below (h2 preface probe + header search),
    // not Lcheck_leftover's leftover-bytes-only check (Step 5) — that
    // one deliberately skips the h2 probe because a keep-alive
    // continuation has already decided the protocol earlier in the same
    // connection, which isn't true here.
    cbnz x22, Lread_got_data

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

// Entry point once bytes are known to be sitting in buf, whether just
// read by read_loop above or handed in already-read by child_with_data
// (Step 9): x7 = total bytes buffered so far, x22 = bytes from the most
// recent read, x25 = protocol-decided flag.
Lread_got_data:
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
    // SO_RCVTIMEO expiring is documented (POSIX, Linux socket(7)) to
    // report EAGAIN/EWOULDBLOCK, not ETIMEDOUT -- read() never actually
    // returns ETIMEDOUT for this, but the check is harmless to keep in
    // case some platform genuinely does. Either way, send a 408 before
    // closing.
    cb eq, x0, #ECONNRESET, Lchild_end
    cb eq, x0, #ETIMEDOUT, L408
    cb eq, x0, #EAGAIN, L408
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
