#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: _main
//
// Description: Server entry point and lifecycle. This file also holds
//   the other lifecycle labels: skip_argv (optional argv[1] handling —
//   numeric = port override, letter = debug flag), loop (the accept()
//   loop, which forks a child per connection and hands it to child or
//   — for TLS — straight to h2_connection_loop), exit (shutdown banner +
//   close, falls through into fatal_exit), and fatal_exit (exit(1)).
//   Prints a banner, creates and configures the listening socket,
//   sets up SIGCHLD/SIGPIPE handlers, then runs the accept loop.
//
// Input/Arguments:
//   x0 — argc
//   x1 — argv
//
// Output/Returns:
//   (never returns — exits via fatal_exit)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x5, x9, x16, x21, x28, x30, sp (transient syscall/stack use)
//
// Stack Usage:
//   none (sp scratch only for the sigaction struct blocks)
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
addr:
    .byte 0x02, 0x00             // AF_INET (2) + padding byte
    .byte 0x1f, 0x90             // Port 8080, big-endian
#ifdef __linux__
    .byte 0x00, 0x00, 0x00, 0x00 // 0.0.0.0 (container needs all interfaces)
#else
    .byte 0x7F, 0x00, 0x00, 0x01 // 127.0.0.1
#endif
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // padding
.align 4

get_req:
    .ascii "GET "
.equ get_req_len, . - get_req

.align 4
head_req:
    .ascii "HEAD "
.equ head_req_len, . - head_req

.align 4
options_req:
    .ascii "OPTIONS "
.equ options_req_len, . - options_req

.align 4
brew_req:
    .ascii "BREW "
.equ brew_req_len, . - brew_req

// other data definitions...

.align 4
http_: .ascii "HTTP/"
.equ http_len, . - http_

.align 4
http_1_0: .ascii "HTTP/1.0"
.equ http_1_0_len, . - http_1_0

.align 4
http_1_1: .ascii "HTTP/1.1"
.equ http_1_1_len, . - http_1_1

.bss
.align 4
sockfd:             .skip 8

.text
.align 2

.extern tls_server_handshake
.extern h2_connection_loop
.extern child
.extern child_with_data
.extern child_end

#ifdef __linux__
.global _start
#else
.global _main
#endif
.global skip_argv
.global loop
.global exit

#ifdef __linux__
_start:
#endif
_main:
    mov x28, #0
    // did we get an argument
    cmp x0, #1
    b.le skip_argv

    ldr x9, [x1, #8] // argv[1] pointer
    ldrb w0, [x9] // first byte of string
    // if it's less than 'A' (0x41), it's probably a number. so if it is, just
    // treat it as a port. otherwise, if it's > A (so any letter), let's treat
    // it as a debug option. pretty hack-y, but supes helpful for debugging, so
    // we can automatically not fork().
    cmp w0, #'A'
    b.lt 2f

    mov x28, #1
    str_l x28, no_fork
    b skip_argv

2:
    // get argv0.
    ldr x0, [x1, #8]
    bl atoi
    b.cs fatal_exit

    // now x0 contains the integer representation of argv[1]
    mov x2, #65535
    cmp x0, x2
    b.gt fatal_exit

    // overwrite the address struct's port with the custom port.
    rev16 w0, w0 // make x0 big-endian, which the port needs to be
    adr_l x1, addr
    strh w0, [x1, #2]

skip_argv:
    // socket(AF_INET, SOCK_STREAM, 0)
    SCWINUM SYS_socket
    mov x0, #AF_INET
    mov x1, #SOCK_STREAM
    mov x2, #0 // nothin, TCP
    SCWISVC
    SCERR
    b.cs fatal_exit

    str_l x0, sockfd

    // setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &value, 4)
    SCWINUM SYS_setsockopt
    ldr_l x0, sockfd
    mov x1, #SOL_SOCKET
    mov x2, #SO_REUSEADDR
    adr_l x3, one
    mov x4, #4 // sizeof int
    SCWISVC
    SCERR
    b.cs exit

    // bind(sockfd, &addr, 16)
    SCWINUM SYS_bind
    ldr_l x0, sockfd
    adr_l x1, addr
    mov x2, #16 // the struct is 16 bytes
    SCWISVC
    SCERR
    b.cs exit

    // listen(sockfd, 128) — was 5; a fork-bound accept loop that only
    // gets back to accept() after handing off each connection can leave
    // a burst sitting in the backlog, and 5 drops connections under load
    // (Plan.md Phase 2, Step 7).
    SCWINUM SYS_listen
    ldr_l x0, sockfd
    mov x1, #128
    SCWISVC
    SCERR
    b.cs exit

    // set up SIG_IGN on SIGCHLD, with SA_NOCLDWAIT to tell the kernel to auto
    // reap children. previously zombies were piling up :(
#ifdef __linux__
    sub sp, sp, #32
    mov x0, #SIG_IGN
    str x0, [sp, #0]  // sa_handler = SIG_IGN
    mov x0, #SA_NOCLDWAIT
    str x0, [sp, #8]  // sa_flags = SA_NOCLDWAIT
    str xzr, [sp, #16] // sa_restorer = NULL
    str xzr, [sp, #24] // sa_mask = 0

    SCWINUM SYS_rt_sigaction
    mov w0, #SIGCHLD_
    mov x1, sp
    mov x2, #0 // old action = NULL
    mov x3, #8 // sigsetsize
    SCWISVC
    SCERR
    add sp, sp, #32
#else
    sub sp, sp, #32
    mov x0, #SIG_IGN
    mov x1, #SA_NOCLDWAIT
    str x0, [sp, #0]  // sa_handler = SIG_IGN
    str x0, [sp, #8]   // sp_tramp
    str wzr, [sp, #16] // sa_mask = 0
    str x1, [sp, #20] // sa_flags = SA_NOCLDWAIT

    SCWINUM SYS_sigaction
    mov w0, #SIGCHLD_
    mov x1, sp
    mov x2, #0 // old action = NULL
    SCWISVC
    SCERR
    add sp, sp, #32
#endif
    b.cs exit

    // ignore SIGPIPE so write() returns EPIPE instead of killing us
#ifdef __linux__
    sub sp, sp, #32
    mov x0, #SIG_IGN
    str x0, [sp, #0]  // sa_handler = SIG_IGN
    str xzr, [sp, #8]  // sa_flags = 0
    str xzr, [sp, #16] // sa_restorer = NULL
    str xzr, [sp, #24] // sa_mask = 0

    SCWINUM SYS_rt_sigaction
    mov w0, #SIGPIPE_
    mov x1, sp
    mov x2, #0
    mov x3, #8 // sigsetsize
    SCWISVC
    SCERR
    add sp, sp, #32
#else
    sub sp, sp, #32
    mov x0, #SIG_IGN
    str x0, [sp, #0] // sa_handler = SIG_IGN
    str x0, [sp, #8] // sa_tramp = SIG_IGN
    str wzr, [sp, #16] // sa_mask = 0
    str wzr, [sp, #20] // sa_flags = 0

    SCWINUM SYS_sigaction
    mov w0, #SIGPIPE_
    mov x1, sp
    mov x2, #0
    SCWISVC
    SCERR
    add sp, sp, #32
#endif
    b.cs exit

loop:
    // accept(sockfd, NULL, NULL)
#ifdef __linux__
    SCWINUM SYS_accept4
    ldr_l x0, sockfd
    mov x1, #0
    mov x2, #0
    mov x3, #0 // flags = 0
#else
    SCWINUM SYS_accept
    ldr_l x0, sockfd
    mov x1, #0
    mov x2, #0
#endif
    SCWISVC
    SCERR
    b.cs loop // loop if accept() failed.

    // store x0 (return of accept) in clientfd
    str_l x0, clientfd

    // ── fork a child to serve this connection ───────────────────────
    // Every connection gets its own process, so the parent returns to
    // accept() immediately. This matters far more for HTTP/2 than it
    // did for HTTP/1: an h2 connection is persistent, so serving it on
    // the accept loop leaves every other connection stuck in the listen
    // backlog until this one goes away. Browsers routinely open a second
    // connection (Safari puts `crossorigin` subresources on their own),
    // and those requests then hang — the resources never load.
    // SIGCHLD is already SIG_IGN with SA_NOCLDWAIT above, so the kernel
    // reaps the children for us; the per-connection globals (clientfd,
    // h2_conn, h2_streams, buf) become private copies at fork, which is
    // exactly the isolation the single-connection-at-a-time code assumed.
    ldr_l x9, no_fork
    cbnz x9, Lmain_serve        // debug flag — serve inline, no fork
#ifdef __linux__
    // arm64 Linux has no fork(); clone(SIGCHLD, NULL, ...) is the same
    // thing — a NULL child stack means "share the parent's", i.e. COW.
    SCWINUM SYS_clone
    mov x0, #SIGCHLD_LINUX      // flags
    mov x1, #0                  // child stack — NULL
    mov x2, #0                  // parent_tid
    mov x3, #0                  // tls
    mov x4, #0                  // child_tid
    SCWISVC
    SCERR
    b.cs Lmain_fork_failed
    cbz x0, Lmain_child         // 0 in the child, pid in the parent
#else
    SCWINUM SYS_fork
    SCWISVC
    SCERR
    b.cs Lmain_fork_failed
    // Darwin's raw fork() puts a pid in x0 for *both* processes (the
    // child gets its parent's); x1 is the discriminator — 1 in the
    // child, 0 in the parent. libc's wrapper zeroes x0 on that basis.
    cbnz x1, Lmain_child
#endif
    // ── parent — hand the connection over and go back to accept() ──
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR
    b loop

Lmain_fork_failed:
    // out of processes — drop this connection rather than serve it on
    // the accept loop, where it could block every later one
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR
    b loop

Lmain_child:
    // the listening socket belongs to the parent — a child holding it
    // open would keep the port bound after the parent exits
    SCWINUM SYS_close
    ldr_l x0, sockfd
    SCWISVC
    SCERR
Lmain_serve:
    // Arm the receive timeout before anything reads from the socket.
    // child.S sets this too, but only on the plaintext path — and an
    // h2-over-TLS connection is persistent, so without it a client that
    // goes away without a FIN would leave its child blocked in read()
    // forever. Harmless to set twice; the plaintext path is unchanged.
    SCWINUM SYS_setsockopt
    ldr_l x0, clientfd
    mov x1, #SOL_SOCKET
    mov x2, #SO_RCVTIMEO
    adr_l x3, rcv_timeout
    mov x4, #16 // struct timeval is 16 bytes
    SCWISVC
    SCERR

    // ── protocol detection (PLAN.MD Phase 20; real read, not a peek,
    //    since Plan.md Phase 2 Step 9) ────────────────────────────────
    // A TLS 1.3 ClientHello always starts with a handshake record (type
    // 0x16, RFC 8446 §5.1), which no plaintext HTTP/1 or HTTP/2 request
    // ever does (HTTP/1 starts with a method like "GET", HTTP/2 with the
    // "PRI *" preface). Previously this was decided by a MSG_PEEK
    // recvfrom() that left the byte on the socket for child/
    // tls_server_handshake to read again; now the bytes are read for
    // real, straight into buf, and handed to whichever path is chosen —
    // one fewer syscall per connection, and child.S already knows how
    // to resume with a buffer that isn't empty (Step 5's leftover-bytes
    // mechanism), so child_with_data reuses exactly that.
    SCWINUM SYS_read
    ldr_l x0, clientfd
    adr_l x1, buf
    mov x2, #BUF_SIZE
    SCWISVC
    SCERR
    b.cs Lmain_tls_close        // read failed — close like a dead connection
    mov x21, x0                 // bytes read (0 = EOF); survives the calls below
    cbz x21, Lmain_tls_close    // 0 bytes read — client already closed

    adr_l x1, buf
    ldrb w2, [x1]
    cmp w2, #TLS_RECORD_HANDSHAKE
    b.eq Lmain_tls_detected

    // not TLS — hand the plaintext path the bytes already read instead
    // of making it read them again
    mov x0, x21
    b child_with_data
Lmain_tls_detected:

    // tls_server_handshake copies these bytes into its own scratch
    // buffer before reading anything else off the wire (see its header
    // comment) — a conforming TLS 1.3 client's first flight is exactly
    // one ClientHello record, so this is the whole record (or a prefix
    // of it) and nothing beyond it.
    ldr_l x0, clientfd
    adr_l x1, buf
    mov x2, x21
    bl tls_server_handshake
    b.cs Lmain_tls_close        // handshake failed — close, never reaches H2

    ldr_l x0, clientfd
    adr_l x1, buf
    mov x2, #0
    bl h2_connection_loop       // returns when the connection ends

Lmain_tls_close:
    // transport_mode is a single global (one connection in flight at a
    // time, PLAN.MD's connection-per-loop model) — reset it before the
    // next accept, which may well be a plaintext connection.
    adr_l x9, transport_mode
    str xzr, [x9]               // TRANSPORT_PLAIN == 0
    b child_end


exit:
    // shutdown(sockfd, SHUT_RDRW)
    SCWINUM SYS_shutdown
    ldr_l x0, sockfd
    mov x1, #2 // SHUT_RDRW
    SCWISVC
    SCERR

    // close(sockfd)
    SCWINUM SYS_close
    ldr_l x0, sockfd
    SCWISVC
    SCERR
    // fallthrough
fatal_exit:
    // exit(1)
    SCWINUM SYS_exit
    mov x0, #1
    SCWISVC
    SCERR
