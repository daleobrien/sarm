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

#include "defs.S"

.global write_all
.global itoa
.global atoi
.global atoi_n
.global strlen
.global memcpy
.global streqn_i
.global streqn
.global fnv1a_64

.bss
// itoa_buf is byte-addressed (strb/ldrb), so no special alignment needed.
itoa_buf: .skip 20

.text
.align 2 // instructions need 4-byte alignment

// write content to a file descriptor, retrying in case of partial-writes.
// input (same as write() syscall)
// x0 -> file descriptor
// x1 -> buffer
// x2 -> nbytes
//
// output
// x0 -> number of bytes written, total.
write_all:
    stp x25, x26, [sp, #-16]!
    mov x25, x0 // save x0 into x20
    mov x26, #0
1:
    // carry = 0, in case we exit with cbz without ever calling write().
    cmn xzr, xzr
    cbz x2, 2f

    SCWINUM SYS_write
    mov x0, x25
    // x1 is set by caller
    // x2 is also set by caller
    SCWISVC
    SCERR
    b.cs Lwrite_fail

    sub x2, x2, x0 // subtract written bytes
    add x26, x26, x0 // increment total bytes written
    add x1, x1, x0 // increment pointer
    b 1b

2:
    mov x0, x26 // return total bytes written

3:
    ldp x25, x26, [sp], #16
    ret

Lwrite_fail:
    cmp x0, #EINTR
    b.eq 1b
    cb eq, x0, #EPIPE, 3b    // treat as clean exit (client disconnected)

    cmp xzr, xzr // set C=1 so we can b.cs
    // x0 is already errno
    b 3b


// convert integer into non-NULL-terminated string.
// input
// x0 -> number to convert
//
// returns
// x0 -> pointer to start of string
// x1 -> length of string
//
// clobbers x0, x1, x2, x3, x4, x5
itoa:
    adr_l x1, itoa_buf
    add x1, x1, #20 // Start at the END of the buffer and write backwards
    mov x2, #0      // length counter
    mov x3, #10     // divisor
1:
    udiv x4, x0, x3     // x4 = x0 / 10
    msub x5, x4, x3, x0 // x5 = x0 - (x4 * x10) = remainder
    add x5, x5, #'0'    // converts to ascii
    sub x1, x1, #1      // move pointer back
    strb w5, [x1]       // stores the digit
    add x2, x2, #1      // length++
    mov x0, x4          // quotient becomes new number
    cbnz x0, 1b         // jump back to 1 if not 0

    mov x0, x1 // x0 = pointer to start
    mov x1, x2 // x1 = length
    ret


// convert NULL-terminated string to integer
// input
// x0 -> pointer to string
//
// returns
// x0 -> integer representation of string
atoi:
    mov x1, #0
    mov x3, #10
    mov x4, #0
1:
    // bounds check so we don't try to atoi a massive integer and overflow the
    // register.
    cmp x4, #19
    b.hs Latoi_error

    ldrb w2, [x0]
    cbz w2, 2f

    // make sure we actually have a number
    cmp w2, #'0'
    b.lo Latoi_error
    cmp w2, #'9'
    b.hi Latoi_error

    mul x1, x1, x3
    sub w2, w2, #'0'
    add x1, x1, x2
    add x0, x0, #1
    add x4, x4, #1 // increment counter for bounds check

    b 1b
2:
    cmn xzr, xzr
    mov x0, x1
    ret

Latoi_error:
    cmp xzr, xzr
    mov x0, #0
    ret


// convert string representation of number into an integer. read up to N bytes
// from string, does not need to be NULL terminated.
// input
// x0 -> pointer to string
// x1 -> length of string
//
// returns
// x0 -> integer representation of string
atoi_n:
    // try to protect against overflowers. a 19+ digit number will overflow
    // the register.
    cmp x1, #19
    b.hs Latoi_n_error

    mov x2, #0
    mov x4, #10
2:
    cbz x1, 3f

    ldrb w3, [x0]

    // make sure we actually have a number
    cmp w3, #'0'
    b.lo Latoi_n_error
    cmp w3, #'9'
    b.hi Latoi_n_error

    mul x2, x2, x4
    sub w3, w3, #'0'
    add x2, x2, x3
    add x0, x0, #1

    sub x1, x1, #1
    b 2b
3:
    cmn xzr, xzr
    mov x0, x2
    ret

Latoi_n_error:
    cmp xzr, xzr
    mov x0, #0
    ret


// copies N bytes from x1 into x0
// input
// x0 -> destination
// x1 -> source
// x2 -> length
// 
// clobbers x0, x1, and x3
memcpy:
    cbz x2, 1f
    cmp x2, #16
    b.lo 3f
2:
    ldp x3, x4, [x1], #16
    stp x3, x4, [x0], #16
    sub x2, x2, #16
    cmp x2, #16
    b.hs 2b
3:
    cbz x2, 1f
    ldrb w3, [x1], #1
    strb w3, [x0], #1
    sub x2, x2, #1
    b 3b
1:
    ret


// gets the length of a NULL-terminated string.
// input
// x1 -> string whose length to check
//
// return
// x0 -> length of string
strlen:
    mov x0, #0
1:
    ldrb w3, [x1, x0]
    cbz w3, 2f
    add x0, x0, #1
    b 1b

2:
    ret


// case insensitive streqn
// input
// x0 -> str1
// x1 -> str2
// x2 -> max length
//
// returns
// x0 -> 1 if match, 0 if doesn't match
streqn_i:
    cbz x2, Lstreqn_i_match
1:
    // load bytes
    ldrb w3, [x0]
    ldrb w4, [x1]

    cmp w3, #0
    ccmp w4, #0, #0, eq  // if w3 == NULL, check if w4 is also NULL
    b.eq Lstreqn_i_match // if they're both NULL, it's a match!
    // if we're here, they're not *both* NULL. but if *ONE* is NULL, we should
    // exit - not a match :(
    cbz w3, Lstreqn_i_no_match
    cbz w4, Lstreqn_i_no_match

    // make them both lowercase by only modifying A-Z range
    cmp w3, #'A'
    b.lo 1f
    cmp w3, #'Z'
    b.hi 1f
    add w3, w3, #0x20
1:
    cmp w4, #'A'
    b.lo 2f
    cmp w4, #'Z'
    b.hi 2f
    add w4, w4, #0x20
2:
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    // if we've reached the end, it's a match yeah? fuck yeah.
    subs x2, x2, #1
    b.eq Lstreqn_i_match

    add x0, x0, #1
    add x1, x1, #1
    b 1b

Lstreqn_i_match:
    mov x0, #1
    ret

Lstreqn_i_no_match:
    mov x0, #0
    ret


// input
// x0 -> str1
// x1 -> str2
// x2 -> max length
//
// returns
// x0 -> 1 if match, 0 if doesn't match
streqn:
1:
    ldrb w3, [x0]
    ldrb w4, [x1]
    cmp w3, w4
    b.ne Lstreqn_no_match

    cbz w3, Lstreqn_match // both equal and both NULL = end of string = match

    // if we've reached the end, it's a match yeah?
    subs x2, x2, #1
    b.eq Lstreqn_match

    add x0, x0, #1
    add x1, x1, #1
    b 1b

Lstreqn_match:
    mov x0, #1
    ret

Lstreqn_no_match:
    mov x0, #0
    ret


// FNV-1a 64-bit hash
// input:  x0 -> buffer, x1 -> length
// output: x0 -> 64-bit hash
// clobbers x1, x2, x3, x4
fnv1a_64:
    // FNV offset basis: 0xcbf29ce484222325
    movz x3, #0x2325
    movk x3, #0x8422, lsl #16
    movk x3, #0x9ce4, lsl #32
    movk x3, #0xcbf2, lsl #48

    mov x2, x1    // remaining length
    cbz x2, 2f

1:
    ldrb w1, [x0], #1
    eor x3, x3, x1     // h ^= byte

    // h = (h * 0x100000001b3) & 0xffffffffffffffff
    // 0x100000001b3 = h + (h<<1) + (h<<4) + (h<<5) + (h<<7) + (h<<8) + (h<<40)
    mov x4, x3
    add x4, x4, x3, lsl #1
    add x4, x4, x3, lsl #4
    add x4, x4, x3, lsl #5
    add x4, x4, x3, lsl #7
    add x4, x4, x3, lsl #8
    add x4, x4, x3, lsl #40
    mov x3, x4

    sub x2, x2, #1
    cbnz x2, 1b

2:
    mov x0, x3
    ret
