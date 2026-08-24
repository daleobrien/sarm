#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: _main
//
// Description: Server entry point and lifecycle. This file also holds
//   the other lifecycle labels: skip_argv (optional argv[1] handling —
//   numeric = port override, letter = debug flag), help_exit (`-help`:
//   print the usage blob and exit 0), loop (the accept()
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

rodata
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

// The three spellings of the help flag. Matched the same way as
// `--workers` — over a length that includes the NUL — so "-helpful" is
// a mismatch rather than a prefix hit.
.align 4
opt_help: .asciz "-help"
.equ opt_help_len, . - opt_help

.align 4
opt_help_long: .asciz "--help"
.equ opt_help_long_len, . - opt_help_long

.align 4
opt_h: .asciz "-h"
.equ opt_h_len, . - opt_h

// usage_text — what `-help` prints, written once to stdout by
// help_exit. Kept as one blob rather than a table of lines so it is a
// single write() with no formatting code behind it: nothing here is
// computed at runtime, so nothing needs to be.
.align 4
usage_text:
    .ascii "sarm \xe2\x80\x94 an HTTP/1.1 and HTTP/2 server in ARM64 assembly\n"
    .ascii "\n"
    .ascii "Usage: sarm [port] [d] [--workers N|auto] [-help]\n"
    .ascii "\n"
    .ascii "Arguments may appear in any order.\n"
    .ascii "\n"
    .ascii "  port            TCP port to listen on, 1-65535. Default 8080.\n"
    .ascii "  d               Debug mode: serve each connection inline in this\n"
    .ascii "                  process instead of forking a child for it, and run\n"
    .ascii "                  a single worker. Any bare token starting with a\n"
    .ascii "                  letter selects it.\n"
    .ascii "  --workers N     Run N pre-forked accept workers, clamped to 64.\n"
    .ascii "                  Default 1, which forks no workers at all.\n"
    .ascii "  --workers auto  One worker per CPU this process may run on, so a\n"
    .ascii "                  taskset or cpuset is respected rather than the\n"
    .ascii "                  machine's full core count.\n"
    .ascii "  -help           Print this message and exit. Also --help, -h.\n"
    .ascii "\n"
#ifdef __linux__
    .ascii "Listens on 0.0.0.0. Set at build time, not by any argument.\n"
#else
    .ascii "Listens on 127.0.0.1. Set at build time, not by any argument.\n"
#endif
    .ascii "\n"
    .ascii "Examples:\n"
    .ascii "  sarm\n"
    .ascii "  sarm 8081\n"
    .ascii "  sarm 8081 --workers auto\n"
    .ascii "  sarm 8081 d\n"
.equ usage_len, . - usage_text

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

// no_core_rlimit — struct rlimit { rlim_cur, rlim_max }, both zero, for
// the RLIMIT_CORE call at the top of the accept path's setup. Two
// 64-bit fields on both platforms, and it is read by the kernel, never
// written, so it lives with the other constants.
.align 4
no_core_rlimit:
    .quad 0              // rlim_cur
    .quad 0              // rlim_max

// conn_deadline — struct itimerval for setitimer(ITIMER_REAL), armed
// once per forked connection child at Lmain_child. it_interval is zero,
// so this is a one-shot: SIGALRM once, CONN_DEADLINE seconds after
// accept(), and its default disposition terminates the child. See
// config.S and docs/SECURITY.md §8 (Step 12).
//
// struct itimerval is two struct timevals. tv_usec is 32-bit on macOS
// and 64-bit on Linux, but a timeval is 16 bytes on both, so .quad pairs
// lay out identically either way — the same trick rcv_timeout uses.
.align 4
conn_deadline:
    .quad 0              // it_interval.tv_sec  — one shot, no rearm
    .quad 0              // it_interval.tv_usec
    .quad CONN_DEADLINE  // it_value.tv_sec
    .quad 0              // it_value.tv_usec

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
#else
#endif

// ─────────────────────────────────────────────────────────────────────
// Function Name: install_sigchld
//
// Description: SIGCHLD -> SIG_IGN with SA_NOCLDWAIT, so the kernel reaps
//   per-connection children and nothing ever has to wait().
//
//   A routine rather than a straight line of _main because **every
//   accept worker has to install this for itself** (Plan.md Phase 3,
//   Step 15). On macOS the effect of SA_NOCLDWAIT is a process flag that
//   fork() does NOT copy to the child, so a worker forked after _main
//   set it inherits SIG_IGN without the auto-reap, and every connection
//   it then serves leaves a zombie behind: 300 connections against a
//   two-worker server left 151 of them, and the server stopped being
//   able to fork at all a few thousand connections later. Found by the
//   Phase 4 stress test; see docs/MULTICORE-BASELINE.md.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   carry clear on success, set on error (x0 = errno)
//
// Clobbered Registers:
//   x0-x3, x16 (x8 on Linux)
//
// Stack Usage:
//   32 bytes for the sigaction struct
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC install_sigchld
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
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: detect_cpus
//
// Description: How many logical CPUs this machine has, for
//   `--workers auto` (Plan.md Phase 3, Step 14). macOS answers via
//   sysctlbyname("hw.logicalcpu"); the raw syscall takes the name
//   length as its second argument, where libc's wrapper computes it.
//
//   Linux has no "how many cores" syscall, so it answers a slightly
//   different question: sched_getaffinity(0, ...) returns the mask of
//   CPUs this process is ALLOWED to run on, and the popcount of that
//   mask is the answer `--workers auto` actually wants. Under taskset,
//   a cgroup cpuset or a container pinned to two CPUs it reports two,
//   where a raw core count would report the host's and over-fork. No
//   filesystem is involved — /proc/cpuinfo and sysconf(3) are exactly
//   what this server must not do — and an explicit `--workers N` still
//   works identically on both platforms.
//
//   The mask buffer is 128 bytes (1024 CPUs). A machine wider than that
//   makes the kernel answer EINVAL rather than truncate, which lands in
//   the same fallback as any other failure: report 1. Overshooting the
//   clamp is not a concern either way — the caller clamps to
//   MAX_WORKERS.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   x0 — logical CPU count, or 1 if it could not be determined
//
// Clobbered Registers:
//   x0-x5, x9-x11, x16 (x8 on Linux); v0 on Linux (the popcount)
//
// Stack Usage:
//   macOS: 32 bytes — the u32 result plus its size_t length, both
//   by-reference. Linux: 128 bytes — the CPU mask.
// ─────────────────────────────────────────────────────────────────────
.align 2
detect_cpus:
#ifdef __linux__
    sub sp, sp, #128
    // Zero the mask first. The kernel reports how many bytes it filled
    // and leaves the rest untouched, so the popcount below is bounded by
    // that count; zeroing means a miscount could only ever be low, never
    // an inherited stack bit read as a CPU.
    mov x9, #0
Ldc_zero:
    add x10, sp, x9
    str xzr, [x10]
    add x9, x9, #8
    cmp x9, #128
    b.lt Ldc_zero

    // sched_getaffinity(0, sizeof mask, &mask)
    SCWINUM SYS_sched_getaffinity
    mov x0, #0                  // pid 0 — this process
    mov x1, #128                // cpusetsize, in bytes
    mov x2, sp
    SCWISVC
    SCERR
    b.cs Ldc_no_mask

    // x0 = bytes of the mask the kernel filled (a multiple of 8). Count
    // the set bits in exactly those bytes: arm64's base ISA has no
    // scalar popcount, so each word goes through NEON's cnt.
    mov x1, x0                  // filled length
    mov x9, #0                  // byte offset
    mov x2, #0                  // CPUs counted so far
Ldc_popcount:
    cmp x9, x1
    b.ge Ldc_popcount_done
    add x10, sp, x9
    ldr x11, [x10]
    fmov d0, x11
    cnt v0.8b, v0.8b            // per-byte popcount
    uaddlv h0, v0.8b            // sum the eight of them
    fmov w11, s0
    add x2, x2, x11
    add x9, x9, #8
    b Ldc_popcount
Ldc_popcount_done:
    mov x0, x2
    cbz x0, Ldc_no_mask         // an empty mask is not an answer
    add sp, sp, #128
    ret
    // Named apart from the macOS arm's Ldc_fallback on purpose: the two
    // arms are never assembled together, but scripts/abi.py does not
    // run the preprocessor, and a label defined twice in the file makes
    // it trace this branch into the other platform's epilogue and report
    // a stack imbalance that does not exist.
Ldc_no_mask:
    mov x0, #1
    add sp, sp, #128
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
ENDFUNC install_sigchld

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
FUNC worker_shutdown
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
ENDFUNC worker_shutdown

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
FUNC sig_tramp
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
ENDFUNC sig_tramp
#endif

#ifdef __linux__
// Linux enters the ELF entry point raw: the kernel does not fill x0/x1,
// it hands over a stack with argc at [sp] and argv immediately after it
// (x0 is undefined here — reading it as argc walks whatever the stack
// happens to hold). Darwin gets here through dyld, which calls this as
// main(argc, argv, ...) with the arguments already in x0/x1, so only
// Linux needs the unpack.
FUNC _start
    ldr x0, [sp]                // argc
    add x1, sp, #8              // argv
ENDFUNC _start
#endif
FUNC _main
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

    // -help / --help / -h — print the usage and exit(0). Checked before
    // the positional rule below, which would otherwise read a token
    // starting with '-' as a port and fail on it.
    mov x0, x22
    adr_l x1, opt_help
    mov x2, #opt_help_len
    bl streqn
    cbnz x0, help_exit

    mov x0, x22
    adr_l x1, opt_help_long
    mov x2, #opt_help_long_len
    bl streqn
    cbnz x0, help_exit

    mov x0, x22
    adr_l x1, opt_h
    mov x2, #opt_h_len
    bl streqn
    cbnz x0, help_exit

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
ENDFUNC _main

FUNC skip_argv
    // ── no core dumps, ever (docs/SECURITY.md §13.2) ───────────
    // A core of this process is a complete memory disclosure: the
    // private scalar, the handshake secrets and every traffic key are
    // all in it. tests/test_leak.sh checked that no core appeared, but
    // it checked it with `ulimit -c 0` in the harness — a property of
    // how the test launched the server, not of the server. This makes
    // it a property of the server: the limit is set before the
    // listening socket exists, and rlimits are inherited across fork(),
    // so every worker and every connection child starts with it too.
    //
    // Lowering a soft limit is always permitted, so a failure here
    // means something is wrong with the kernel interface rather than
    // with the request, and it happens at startup where refusing to
    // serve costs nothing. It is fatal for the same reason bind() is.
    adr_l x9, no_core_rlimit
#ifdef __linux__
    // arm64 Linux has no setrlimit: prlimit64(0, RLIMIT_CORE, &new, NULL)
    SCWINUM SYS_prlimit64
    mov x0, #0                  // pid 0 — this process
    mov x1, #RLIMIT_CORE
    mov x2, x9
    mov x3, #0                  // don't want the old limit back
#else
    // setrlimit(RLIMIT_CORE, &rlimit)
    SCWINUM SYS_setrlimit
    mov x0, #RLIMIT_CORE
    mov x1, x9
#endif
    SCWISVC
    SCERR
    b.cs fatal_exit

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

    // SIGCHLD -> SIG_IGN with SA_NOCLDWAIT so the kernel auto-reaps the
    // per-connection children. Every forked worker re-installs this for
    // itself (see install_sigchld) -- fork does not carry the flag.
    bl install_sigchld
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
    cbz x0, Lworker_child       // the child is a worker
#else
    SCWINUM SYS_fork
    SCWISVC
    SCERR
    b.cs Linstall_shutdown      // can't spawn more — run with what we have
    cbnz x1, Lworker_child      // x1 == 1 in the child (see the note below)
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

Lworker_child:
    // A forked worker has to install SIGCHLD/SA_NOCLDWAIT for itself:
    // macOS does not carry the auto-reap flag across fork(), so without
    // this every connection this worker serves leaves a zombie and the
    // server runs out of processes within a few thousand connections.
    // Ignoring the result is deliberate — a worker that cannot set it is
    // still better than one fewer worker, and _main already exited if
    // the very same call failed there.
    bl install_sigchld
    b loop

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
ENDFUNC skip_argv

FUNC loop
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

    // ── the connection deadline (docs/SECURITY.md Step 12) ──────────
    // setitimer(ITIMER_REAL, &conn_deadline, NULL): one SIGALRM,
    // CONN_DEADLINE seconds from now, default disposition, no handler.
    // This child dies when it fires.
    //
    // SO_RCVTIMEO below bounds how long one read() waits; nothing bounds
    // how many times a client may restart it. One byte every
    // RECV_TIMEOUT-1 seconds holds this process, its descriptor and its
    // resident image indefinitely — as does a TLS handshake delivered a
    // record at a time, or the unbounded run of change_cipher_spec
    // records RFC 8446 Appendix D.4 says to tolerate. All three are the
    // same shape of attack and this is the one bound that ends them.
    //
    // It is armed here rather than in Lmain_serve deliberately:
    // Lmain_serve is also how `no_fork` debug mode serves inline, and
    // there the alarm would kill the server rather than a connection.
    // Here, one process is one connection, so an expiry costs exactly
    // the connection that earned it.
    //
    // A failure is not fatal — the connection is still served, just
    // without its ceiling — so nothing branches on the result.
    SCWINUM SYS_setitimer
    mov x0, #ITIMER_REAL
    adr_l x1, conn_deadline
    mov x2, #0                  // no interest in the previous value
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

    // ── protocol detection (real read, not a peek,
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
    // time per process) — reset it before the
    // next accept, which may well be a plaintext connection.
    adr_l x9, transport_mode
    str xzr, [x9]               // TRANSPORT_PLAIN == 0
    b child_end
ENDFUNC loop


FUNC exit
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

// help_exit — `-help`: one write of the usage blob to stdout, then
// exit(0). Reached only from the argument scan, before any socket
// exists, so there is nothing to shut down on the way out. A failed
// write is not worth reporting to a stdout that could not take it, so
// the result is ignored.
help_exit:
    SCWINUM SYS_write
    mov x0, #1                  // stdout
    adr_l x1, usage_text
    mov x2, #usage_len
    SCWISVC

    SCWINUM SYS_exit
    mov x0, #0
    SCWISVC
ENDFUNC exit

