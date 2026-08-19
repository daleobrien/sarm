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

// ── Phase 3, Step 14 option tokens ────────────────────────────────
// Matched with streqn over a length that INCLUDES the NUL, so a longer
// argument sharing the prefix ("--workersplease") is a mismatch rather
// than a match on the first 9 bytes.
.align 4
opt_workers: .asciz "--workers"
.equ opt_workers_len, . - opt_workers

.align 4
opt_auto: .asciz "auto"
.equ opt_auto_len, . - opt_auto

// hw_logicalcpu — the sysctl name `--workers auto` resolves. Passed to
// the raw sysctlbyname syscall, which (unlike libc's wrapper) wants the
// name length as its second argument; that length excludes the NUL.
.align 4
hw_logicalcpu: .asciz "hw.logicalcpu"
.equ hw_logicalcpu_len, . - hw_logicalcpu - 1

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

// worker_pids / worker_pid_count — the pids of the accept workers this
// process forked at startup (Plan.md Phase 3, Step 15), so shutdown
// (Step 16) can signal them. Only the FORKED workers are listed: the
// original process is a worker too, but never needs to signal itself.
// SIGCHLD is SIG_IGN with SA_NOCLDWAIT, so nothing wait()s on these —
// the list exists purely to address them.
.align 4
worker_pid_count:   .skip 8
worker_pids:        .skip (MAX_WORKERS * 8)

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

// ─────────────────────────────────────────────────────────────────────
// Function Name: detect_cpus
//
// Description: How many logical CPUs this machine has, for
//   `--workers auto` (Plan.md Phase 3, Step 14). macOS answers via
//   sysctlbyname("hw.logicalcpu"); the raw syscall takes the name
//   length as its second argument, where libc's wrapper computes it.
//
//   Linux has no equivalent one-call answer (it would mean
//   sched_getaffinity plus a popcount over the returned mask, or
//   parsing /proc/cpuinfo — a filesystem read this server does not do
//   while serving), so `auto` there conservatively reports 1 rather
//   than guessing. An explicit `--workers N` works identically on both.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   x0 — logical CPU count, or 1 if it could not be determined
//
// Clobbered Registers:
//   x0-x5, x9, x16
//
// Stack Usage:
//   32 bytes: the u32 result plus its size_t length, both by-reference
// ─────────────────────────────────────────────────────────────────────
.align 2
detect_cpus:
#ifdef __linux__
    mov x0, #1                  // see the header note above
    ret
#else
    sub sp, sp, #32
    str xzr, [sp]               // result slot (u32, zeroed)
    mov x9, #4
    str x9, [sp, #8]            // oldlenp = sizeof(u32)

    SCWINUM SYS_sysctlbyname
    adr_l x0, hw_logicalcpu
    mov x1, #hw_logicalcpu_len
    add x2, sp, #0              // oldp   -> result slot
    add x3, sp, #8              // oldlenp
    mov x4, #0                  // newp   = NULL
    mov x5, #0                  // newlen = 0
    SCWISVC
    SCERR
    b.cs Ldc_fallback

    ldr w0, [sp]
    cbz w0, Ldc_fallback        // 0 CPUs is not an answer
    add sp, sp, #32
    ret
Ldc_fallback:
    mov x0, #1
    add sp, sp, #32
    ret
#endif

// ─────────────────────────────────────────────────────────────────────
// Function Name: worker_shutdown
//
// Description: SIGTERM/SIGINT handler, installed in the process that
//   forked the accept workers (Plan.md Phase 3, Step 16). Stops
//   accepting by closing the shared listening socket, sends SIGTERM to
//   every forked worker, then exits.
//
//   Only the forking process installs this — it is installed AFTER the
//   spawn loop so the workers keep the default disposition and simply
//   die when signalled, and so `--workers 1` (which forks nothing) is
//   left bit-identical to the pre-Phase-3 server.
//
//   The per-connection children are deliberately NOT signalled: they
//   are not in worker_pids, so an in-flight response finishes. Their
//   parent worker is gone by then, so init reaps them.
//
//   Async-signal-safe by construction: three raw syscalls, no libc, no
//   allocation, no shared state written. It never returns, so the
//   trampoline's sigreturn tail below is unreachable in practice.
//
//   Neither this routine nor sig_tramp ends in `ret`, so abi.py and
//   validate_clobbers.py cannot see where they stop and read on into
//   the code that follows; their "x30 never saved" warning and the
//   extra registers they attribute here belong to that overrun, not to
//   these ten instructions.
//
// Input/Arguments:
//   x0 — signal number (ignored; both signals mean the same thing here)
//
// Output/Returns:
//   (does not return — exits the process with status 0)
//
// Clobbered Registers:
//   x0-x2, x9-x13, x16 (irrelevant — the process is going away)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────
.align 2
.global worker_shutdown
worker_shutdown:
    // stop accepting: close the one shared listening socket. The forked
    // workers hold their own copies of this descriptor; each of those is
    // closed exactly once, by the kernel, as the worker exits below.
    SCWINUM SYS_close
    ldr_l x0, sockfd
    SCWISVC

    mov x11, #0                 // i = 0
Lws_kill:
    ldr_l x12, worker_pid_count
    cmp x11, x12
    b.ge Lws_done
    adr_l x13, worker_pids
    ldr x0, [x13, x11, lsl #3]
    mov x1, #SIGTERM_
#ifndef __linux__
    mov x2, #1                  // macOS kill() takes a third `posix` arg
#endif
    SCWINUM SYS_kill
    SCWISVC
    add x11, x11, #1
    b Lws_kill

Lws_done:
    SCWINUM SYS_exit
    mov x0, #0
    SCWISVC

#ifndef __linux__
// ─────────────────────────────────────────────────────────────────────
// Function Name: sig_tramp
//
// Description: macOS signal trampoline (the `sa_tramp` field of
//   struct __sigaction). The Darwin kernel enters userspace HERE, not
//   at the handler: libc normally supplies _sigtramp, so a program
//   making the sigaction syscall directly has to supply its own.
//   It calls the handler, then sigreturn()s.
//
//   arm64 Linux needs no equivalent — the kernel provides the return
//   trampoline itself and ignores sa_restorer.
//
// Input/Arguments:
//   x0 -> catcher (the handler)
//   x1 — infostyle
//   x2 — signal number
//   x3 -> siginfo
//   x4 -> ucontext
//
// Output/Returns:
//   (does not return)
//
// Clobbered Registers:
//   x0-x7, x16, x30
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────
.align 2
.global sig_tramp
sig_tramp:
    mov x5, x0                  // catcher
    mov x6, x1                  // infostyle, for the sigreturn below
    mov x7, x4                  // ucontext,  ditto
    mov x0, x2                  // handler(sig, siginfo, ucontext)
    mov x1, x3
    mov x2, x4
    blr x5
    // worker_shutdown exits, so this tail is unreachable today; it is
    // here so the trampoline is correct rather than merely sufficient.
    mov x0, x7
    mov x1, x6
    SCWINUM SYS_sigreturn
    SCWISVC
    SCWINUM SYS_exit
    mov x0, #0
    SCWISVC
#endif

#ifdef __linux__
_start:
#endif
_main:
    // ── argument scan (Plan.md Phase 3, Step 14) ──────────────────────
    // Walks argv[1..argc) rather than looking only at argv[1], so the
    // `--workers N` flag can sit alongside the existing positional port.
    // The positional rule itself is unchanged: a token starting below
    // 'A' is a port, any other bare token is the no_fork debug letter.
    // _main never returns, so x19-x22 are used as long-lived scratch
    // without saving them (atoi and streqn both leave x19+ alone).
    //
    //   ./sarm                  1 worker, port 8080   (unchanged)
    //   ./sarm 8081             1 worker, port 8081   (unchanged)
    //   ./sarm d                no_fork debug mode    (unchanged)
    //   ./sarm 8081 --workers 4 4 accept workers
    //   ./sarm 8081 --workers auto   one worker per logical CPU
    mov x19, x0                 // argc
    mov x20, x1                 // argv
    mov x21, #1                 // i = 1
    mov x28, #0

Largv_loop:
    cmp x21, x19
    b.ge skip_argv
    lsl x9, x21, #3
    ldr x22, [x20, x9]          // argv[i]

    // --workers ?  (length includes the NUL, so "--workersXYZ" won't match)
    mov x0, x22
    adr_l x1, opt_workers
    mov x2, #opt_workers_len
    bl streqn
    cbnz x0, Largv_workers

    ldrb w0, [x22]
    cmp w0, #'A'
    b.lt Largv_port

    // a bare letter — the no_fork debug flag
    mov x9, #1
    str_l x9, no_fork
    b Largv_next

Largv_port:
    mov x0, x22
    bl atoi
    b.cs fatal_exit             // not a number, or 0 — neither is a port
    mov x2, #65535
    cmp x0, x2
    b.gt fatal_exit
    rev16 w0, w0                // the port field is big-endian
    adr_l x1, addr
    strh w0, [x1, #2]
    b Largv_next

Largv_workers:
    add x21, x21, #1            // the count is the next argument
    cmp x21, x19
    b.ge fatal_exit             // `--workers` with nothing after it
    lsl x9, x21, #3
    ldr x22, [x20, x9]

    mov x0, x22
    adr_l x1, opt_auto
    mov x2, #opt_auto_len
    bl streqn
    cbnz x0, Largv_workers_auto

    mov x0, x22
    bl atoi
    b.cs fatal_exit             // non-numeric, or an explicit 0 — rejected
    b Largv_workers_set

Largv_workers_auto:
    bl detect_cpus              // x0 = logical CPUs, or 1 if undetectable

Largv_workers_set:
    cbz x0, fatal_exit          // belt and braces — never 0 workers
    mov x2, #MAX_WORKERS
    cmp x0, x2
    csel x0, x2, x0, gt         // clamp rather than reject, so `auto` on a
                                //   very large machine still starts
    str_l x0, worker_count, x9

Largv_next:
    add x21, x21, #1
    b Largv_loop

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

    // ── pre-fork the accept workers (Plan.md Phase 3, Step 15) ────────
    // ONE listening socket, already bound and listening above, shared by
    // every worker: they all block in accept() on the same inherited
    // descriptor and the kernel hands each incoming connection to one of
    // them. This is a deliberate departure from Phase 3's original
    // SO_REUSEPORT design, which Step 13 disproved on macOS — see that
    // step's note in Plan.md. It needs no socket option, no userspace
    // lock, and no per-worker descriptor bookkeeping, and it measured an
    // even spread across workers.
    //
    // The inner per-connection fork below is untouched, so the property
    // it exists for still holds: a persistent HTTP/2 connection is served
    // by a forked child, leaving its worker free to return to accept().
    //
    // The original process becomes the last worker rather than
    // supervising idly, which is what makes `--workers 1` fork nothing at
    // all and stay bit-identical to the pre-Phase-3 server.
    ldr_l x9, worker_count
    cmp x9, #1
    b.le loop                   // one worker — no fork, nothing to track

    ldr_l x9, no_fork
    cbnz x9, loop               // debug mode is single-process by definition

    mov x23, #1                 // this process is worker 1 of worker_count
Lspawn_loop:
    ldr_l x9, worker_count
    cmp x23, x9
    b.ge Linstall_shutdown      // spawned them all; be the last worker

#ifdef __linux__
    SCWINUM SYS_clone
    mov x0, #SIGCHLD_LINUX
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    SCWISVC
    SCERR
    b.cs Linstall_shutdown      // can't spawn more — run with what we have
    cbz x0, loop                // the child is a worker: straight to accept()
#else
    SCWINUM SYS_fork
    SCWISVC
    SCERR
    b.cs Linstall_shutdown      // can't spawn more — run with what we have
    cbnz x1, loop               // x1 == 1 in the child (see the note below)
#endif
    // parent — record the child so Step 16 can signal it, then continue.
    // worker_pids holds only the FORKED workers (0..worker_pid_count-1);
    // this process is a worker too but has no entry, since it never needs
    // to signal itself.
    adr_l x10, worker_pids
    ldr_l x11, worker_pid_count
    lsl x12, x11, #3
    str x0, [x10, x12]
    add x11, x11, #1
    str_l x11, worker_pid_count, x9
    add x23, x23, #1
    b Lspawn_loop

    // ── shutdown handling (Plan.md Phase 3, Step 16) ──────────────────
    // Reached only by the process that forked workers, and only once it
    // has finished forking them: the workers inherit the DEFAULT
    // SIGTERM/SIGINT disposition and die on the signal, while this
    // process catches it and passes it on. Installing before the fork
    // loop would give every worker a handler and a half-filled pid list,
    // and they would all signal each other.
Linstall_shutdown:
#ifdef __linux__
    sub sp, sp, #32
    adr_l x0, worker_shutdown
    str x0, [sp, #0]   // sa_handler
    str xzr, [sp, #8]  // sa_flags = 0
    str xzr, [sp, #16] // sa_restorer = NULL (ignored on arm64)
    str xzr, [sp, #24] // sa_mask = 0

    SCWINUM SYS_rt_sigaction
    mov w0, #SIGTERM_
    mov x1, sp
    mov x2, #0
    mov x3, #8         // sigsetsize
    SCWISVC

    SCWINUM SYS_rt_sigaction
    mov w0, #SIGINT_
    mov x1, sp
    mov x2, #0
    mov x3, #8
    SCWISVC
    add sp, sp, #32
#else
    sub sp, sp, #32
    adr_l x0, worker_shutdown
    str x0, [sp, #0]   // sa_handler
    adr_l x0, sig_tramp
    str x0, [sp, #8]   // sa_tramp — the kernel enters here, not the handler
    str wzr, [sp, #16] // sa_mask = 0
    str wzr, [sp, #20] // sa_flags = 0

    SCWINUM SYS_sigaction
    mov w0, #SIGTERM_
    mov x1, sp
    mov x2, #0
    SCWISVC

    SCWINUM SYS_sigaction
    mov w0, #SIGINT_
    mov x1, sp
    mov x2, #0
    SCWISVC
    add sp, sp, #32
#endif
    // a failure here is not fatal: the server still serves, it just
    // leaves its workers behind on an explicit kill of this process.

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
