// This file is part of ymawky.
// Copyright (C) 2026 imtomt
//
// ymawky is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// ymawky is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ymawky. If not, see <https://www.gnu.org/licenses/>.

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: _main
//
// Description: Server entry point and lifecycle. This file also holds
//   the other lifecycle labels: skip_argv (optional argv[1] handling —
//   numeric = port override, letter = debug flag), loop (the accept()
//   loop that hands each connection to child), exit (shutdown banner +
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
//   x0, x1, x2, x3, x4, x9, x28, sp (transient syscall/stack use)
//
// Stack Usage:
//   none (sp scratch only for the sigaction struct blocks)
// ─────────────────────────────────────────────────────────────────────

.data
.align 3
addr:
    .byte 0x02, 0x00             // AF_INET (2) + padding byte
    .byte 0x1f, 0x90             // Port 8080, big-endian
#ifdef __linux__
    .byte 0x00, 0x00, 0x00, 0x00 // 0.0.0.0 (container needs all interfaces)
#else
    .byte 0x7F, 0x00, 0x00, 0x01 // 127.0.0.1
#endif
    .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // padding

get_req:
    .ascii "GET "
.equ get_req_len, . - get_req

head_req:
    .ascii "HEAD "
.equ head_req_len, . - head_req

options_req:
    .ascii "OPTIONS "
.equ options_req_len, . - options_req

brew_req:
    .ascii "BREW "
.equ brew_req_len, . - brew_req

// other data definitions...

http_: .ascii "HTTP/"
.equ http_len, . - http_

http_1_0: .ascii "HTTP/1.0"
.equ http_1_0_len, . - http_1_0

http_1_1: .ascii "HTTP/1.1"
.equ http_1_1_len, . - http_1_1

ymawky_connecting: .asciz "ymawky is connecting... "
.equ ymawky_connecting_len, . - ymawky_connecting

ymawky_connected: .asciz "connected!\n"
.equ ymawky_connected_len, . - ymawky_connected

ymawky_shutdown: .asciz "ymawky is shutting down :(\n"
.equ ymawky_shutdown_len, . - ymawky_shutdown


.bss
.align 3
sockfd:             .skip 8

.text
.align 2

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
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, ymawky_connecting
    mov x2, ymawky_connecting_len
    SCWISVC
    SCERR

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

    // listen(sockfd, 5)
    SCWINUM SYS_listen
    ldr_l x0, sockfd
    mov x1, #5
    SCWISVC
    SCERR
    b.cs exit

    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, ymawky_connected
    mov x2, ymawky_connected_len
    SCWISVC
    SCERR

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

    // handle the request inline (no fork — connection-per-loop cycle)
    b child


exit:
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, ymawky_shutdown
    mov x2, ymawky_shutdown_len
    SCWISVC
    SCERR

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
