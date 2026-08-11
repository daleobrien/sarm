// ymawky.S -- Web server in ARM64 assembly
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#include "defs.S"

#ifdef __linux__
.global _start
#else
.global _main
#endif
.global child_end

.data
.align 3

rcv_timeout:
    .quad RECV_TIMEOUT // tv_sec
    .quad 0            // tv_usec

// timer for total header -- prevent slowloris-like attackers from opening a
// connection and sending <1 byte/min or something, hogging resources.
// configured in config.S, HEADER_REQ_TIMEOUT_SECS.
read_timer:
    .quad 0   // it_interval.tv_sec
    .long 0   // it_interval.tv_usec
    .long 0   // -- padding --

    .quad 0   // it_value.tv_sec
    .long 0   // it_value.tv_usec
    .long 0   // -- padding --

.align 2 // one is a .word (4 bytes)
one: .word 1

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

host_str: .ascii "Host"
.equ host_str_len, . - host_str

arrows_in: .ascii "\n\n<<<\n"
.equ arrows_in_len, . - arrows_in

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

    // we check if x28 is set, indicated "d" was passed to cli. if it was, skip
    // fork -- it's much easier to debug with lldb if there's no forking :(
    cbnz x28, child

#ifdef __linux__
    // On Linux, skip the proc_info pid-count check.  We just fork.
    b 8f
#else
    SCWINUM SYS_getpid
    SCWISVC
    SCERR
    // x0 now contains pid

    // gotta check if number of processes is > MAX_PROCS. luckily, apple has an
    // undocumented syscall, "proc_info", that allows us to get all children of
    // this process into a buffer. in the buffer, each child pid is stored as a
    // 32-bit integers.
    sub sp, sp, #2048 // allocate a bit of stack space for the proc_info buf
    SCWINUM SYS_proc_info
    mov x2, x0 // our pid. wondering why we called gitpid() a minute ago? ;)
    mov x0, PROC_INFO_CALL_LISTPIDS
    mov x1, PROC_PPID_ONLY
    mov x3, #0
    mov x4, sp
    mov x5, #2048
    SCWISVC
    SCERR

    // proc_info returns the number of bytes written to the stack. if we divide
    // by 4, it tells us the total number of procs.
    lsr x0, x0, #2
    add sp, sp, #2048 // now we can free up the stack space

    // is the nuymber of procs > MAX_PROCS? 503 if so.
    cmp x0, #MAX_PROCS
    b.ls 8f

    // uh-oh, we're at the max processes. let's give a nice, kind, smart, cute,
    // lil, friendly 503 :3
    mov x0, #503
    mov x1, #1 // we DO want to return here!
    bl reply_status
    b 2f // close n loop!
#endif

8:
    // fork()
#ifdef __linux__
    SCWINUM SYS_clone
    mov x0, #SIGCHLD_       // child exit signal
    mov x1, #0              // child stack (NULL = share parent's)
    mov x2, #0              // parent_tidptr
    mov x3, #0              // child_tidptr
    mov x4, #0              // tls
    SCWISVC
    SCERR
    b.cs 2f // fork failed :( fuck :( close and loop again :(

    // On Linux, clone returns 0 in x0 for child, pid for parent.
    cbz x0, child
#else
    SCWINUM SYS_fork
    SCWISVC
    SCERR
    b.cs 2f // fork failed :( fuck :( close and loop again :(

    // On macOS, fork returns child pid in x0 (parent) or sets x1=1 (child).
    cmp x1, #1
    b.eq child
#endif
2:
    // otherwise close clientfd and loop
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR

    b loop


child:
    // close sockfd
    SCWINUM SYS_close
    ldr_l x0, sockfd
    SCWISVC
    SCERR

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
    b.cs child_end

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
    b.cs child_end
#endif

    // arm timer before reading
    SCWINUM SYS_setitimer
    mov x0, #0 // ITIMER_REAL
    adr_l x1, read_timer
    mov x2, #HEADER_REQ_TIMEOUT_SECS
    str x2, [x1, #16] // offset 16 = it_value.tv_sec
    mov x2, #0
    SCWISVC
    SCERR

    // set a signal handler for SIGALRM, so we can respond with 408 if the
    // connection times out during the header.
#ifdef __linux__
    sub sp, sp, #32
    adr_l x0, L408
    str x0, [sp, #0]  // sa_handler
    str xzr, [sp, #8]  // sa_flags = 0
    str xzr, [sp, #16] // sa_restorer = NULL
    str xzr, [sp, #24] // sa_mask = 0

    SCWINUM SYS_rt_sigaction
    mov w0, #SIGALRM
    mov x1, sp
    mov x2, #0 // old action = NULL
    mov x3, #8 // sigsetsize
    SCWISVC
    SCERR
    add sp, sp, #32
#else
    sub sp, sp, #32
    adr_l x0, L408
    str x0, [sp, #0]  // sa_handler
    str x0, [sp, #8]   // sp_tramp = 408 handler. see bigass comment above.
    str wzr, [sp, #16] // sa_mask = 0
    str wzr, [sp, #20] // sa_flags = 0

    SCWINUM SYS_sigaction
    mov w0, #SIGALRM
    mov x1, sp
    mov x2, #0 // old action = NULL
    SCWISVC
    SCERR
    add sp, sp, #32
#endif
    b.cs L500

    // read(client_fd, buffer, buffer_size)
    mov x7, #0
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
    str_l x24, header_len
    b 2f // break from the hell of reading

Lno_header:
    cmp x22, #0 // x22 is number of bytes from read() now
    b.ne 1f // if nonzero, check buffer fill state
    cmp x7, #0 // if we read nothing,
    b.eq child_end // go to child_end and silently exit

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
    // check if errno is ECONNRESET, ECONNABORTED, ETIMEDOUT, then just
    // silently exit if so. otherwise, return server error.
    cb eq, x0, #ECONNRESET, child_end
    cb eq, x0, #ETIMEDOUT, child_end
    cb eq, x0, #ECONNABORTED, child_end
    cb eq, x0, #EPIPE, child_end
    cb eq, x0, #ENETDOWN, child_end
    cb eq, x0, #ENETUNREACH, child_end
    cb eq, x0, #ENETRESET, child_end
    cb eq, x0, #EHOSTDOWN, child_end
    cb eq, x0, #EHOSTUNREACH, child_end

    b L500

2:
    // disarm timer
    SCWINUM SYS_setitimer
    mov x0, #0
    adr_l x1, read_timer
    str xzr, [x1, #16] // offset 16 = it_value.tv_sec
    mov x2, #0
    SCWISVC
    SCERR

    // let's make sure buf is NULL terminated
    adr_l x1, buf
    strb wzr, [x1, x24] // x24 -> length of bytes read

    // write \n\n<<<\n to stdout to mark a header we're receiving
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, arrows_in
    mov x2, arrows_in_len
    SCWISVC
    SCERR

    // this just writes the request to stdout
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, buf
    mov x2, x23
    SCWISVC
    SCERR

    adr_l x0, buf
    mov x1, x23
    bl verify_http_version

    // check if we got a GET request. if so, jump to get!
    adr_l x0, buf
    adr_l x1, get_req
    mov x2, get_req_len
    bl streqn
    cmp x0, #1
    b.eq Lget_method

    // check if maybe we got a HEAD request instead.
    adr_l x0, buf
    adr_l x1, head_req
    mov x2, head_req_len
    bl streqn
    cmp x0, #1
    b.eq Lhead_method

    // hm. maybe it was an OPTIONS request?
    adr_l x0, buf
    adr_l x1, options_req
    mov x2, options_req_len
    bl streqn
    cmp x0, #1
    b.eq Loptions_method

    // oh god. it's probably BREW. unfortunately, I'm a teapot, so we can't
    // support that method.
    adr_l x0, buf
    adr_l x1, brew_req
    mov x2, brew_req_len
    bl streqn
    cmp x0, #1
    b.eq L418

    // if it was none of the above, reply 501
    b L501

Lget_method:
    mov x0, GET_ID
    str_l x0, request_id

    adr_l x0, buf
    mov x1, x23
    b get

Lhead_method:
    mov x0, HEAD_ID
    str_l x0, request_id
    b head

Loptions_method:
    mov x0, OPTIONS_ID
    str_l x0, request_id
    b options

child_end:
    // close(clientfd)
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR

    ldr_l x0, file_des
    cmn x0, #1
    b.eq 1f
    SCWINUM SYS_close
    // x0 is set
    SCWISVC
    SCERR
1:
    // This is always for children, so let's exit. the parent will loop
    SCWINUM SYS_exit
    mov x0, #0
    SCWISVC
    SCERR


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


// verify the header has an HTTP version and that it's 1.1 or 1.0
// if it's 1.1, ensure we have a Host: field.
// input
// x0 -> header buffer
// x1 -> header length
//
// returns
// nothing, kills process on failure
verify_http_version:
    stp x29, x30, [sp, #-32]!
    stp x20, x21, [sp, #16]

    mov x20, x0
    mov x21, x1

    mov x0, #0
1:
    ldrb w1, [x20, x0]
    cmp w1, #'\r'
    b.ne 2f

    add x0, x0, #1
    cmp x0, x21
    b.ge L400

    ldrb w1, [x20, x0]
    cmp w1, #'\n'
    b.eq 3f

2:
    add x0, x0, #1
    cmp x0, x21
    b.ge L400
    b 1b

3:
    // gotta have at least 9 bytes to hold HTTP/1.1\r
    cmp x0, #9
    b.lt L400

    // x0 points to the index of the \n in \r\n.
    sub x9, x0, #9
    // now it should point to where the "H" would be.

    // HTTP/1.1
    add x0, x20, x9
    adr_l x1, http_1_1
    mov x2, http_1_1_len
    bl streqn
    cmp x0, #1
    b.eq Lhttp11

    // HTTP/1.0
    add x0, x20, x9
    adr_l x1, http_1_0
    mov x2, http_1_0_len
    bl streqn
    cmp x0, #1
    b.eq Lhttp10

    // some other http version?
    add x0, x20, x9
    adr_l x1, http_
    mov x2, http_len
    bl streqn
    cmp x0, #1
    b.eq L505

    // oops. none.
    b L400

Lhttp11:
    // if it's 1.1, we need a Host: field.
    mov x0, x20
    mov x1, x21
    adr_l x2, host_str
    mov x3, host_str_len
    bl get_header_field
    b.cs L400

    b vh_epilogue

Lhttp10:
    // HTTP/1.0 doesn't need Host:
    b vh_epilogue

vh_epilogue:
    ldp x20, x21, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

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
L505:
    mov x0, #505
    mov x1, #0
    b reply_status
