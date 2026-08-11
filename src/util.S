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


// case insensitive streqn — optimized with 4-byte wide loads
// input
// x0 -> str1
// x1 -> str2
// x2 -> max length
//
// returns
// x0 -> 1 if match, 0 if doesn't match
streqn_i:
    cbz x2, Lstreqn_i_match

    // Preload constants for the 4-byte case-fold fast path.
    // Use w11-w17 to avoid clobbering w5-w10 used by callers (get_filetype etc).
    // w11 = 0x80808080 (used in haszero and as byte-range stopper)
    movz w11, #0x8080
    movk w11, #0x8080, lsl #16
    // w12 = 0x41414141  (ASCII 'A' repeated)
    movz w12, #0x4141
    movk w12, #0x4141, lsl #16
    // w13 = 0x1A1A1A1A  (26 = 'Z'+1 - 'A')
    movz w13, #0x1A1A
    movk w13, #0x1A1A, lsl #16
    // w14 = 0x01010101  (used in haszero)
    movz w14, #0x0101
    movk w14, #0x0101, lsl #16

1:
    cmp x2, #4
    b.lo 4f                    // fewer than 4 bytes left — byte loop

    // Load and fold str1 (4 bytes) to lowercase
    ldr w3, [x0]
    orr w15, w3, w11           // w15 = word | 0x80 per byte
    sub w15, w15, w12          // mask_ge_A  (bit 7 set where byte >= 'A')
    sub w16, w15, w13          // mask_gt_Z  (bit 7 set where byte >  'Z')
    bic w16, w15, w16          // mask_AZ = mask_ge_A & ~mask_gt_Z
    and w16, w16, w11          // isolate bit 7 per byte
    lsr w16, w16, #2           // 0x80 → 0x20
    orr w3, w3, w16            // w3 = str1 lowercased

    // Load and fold str2 (4 bytes) to lowercase
    ldr w4, [x1]
    orr w15, w4, w11
    sub w15, w15, w12
    sub w17, w15, w13
    bic w17, w15, w17
    and w17, w17, w11
    lsr w17, w17, #2
    orr w4, w4, w17            // w4 = str2 lowercased

    // Check for null bytes in either word (would mean string ends inside these 4 bytes)
    sub w15, w3, w14           // haszero(w3)
    bic w15, w15, w3
    tst w15, w11
    b.ne 4f                    // str1 has zero — fall to byte loop

    sub w15, w4, w14           // haszero(w4)
    bic w15, w15, w4
    tst w15, w11
    b.ne 4f                    // str2 has zero — fall to byte loop

    // No null bytes — 4-byte word compare is safe
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    sub x2, x2, #4
    add x0, x0, #4
    add x1, x1, #4
    cbz x2, Lstreqn_i_match
    b 1b

4:  // byte-at-a-time fallback (same semantics as original)
    ldrb w3, [x0]
    ldrb w4, [x1]

    cmp w3, #0
    ccmp w4, #0, #0, eq
    b.eq Lstreqn_i_match
    cbz w3, Lstreqn_i_no_match
    cbz w4, Lstreqn_i_no_match

    cmp w3, #'A'
    b.lo 5f
    cmp w3, #'Z'
    b.hi 5f
    add w3, w3, #0x20
5:
    cmp w4, #'A'
    b.lo 6f
    cmp w4, #'Z'
    b.hi 6f
    add w4, w4, #0x20
6:
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    subs x2, x2, #1
    b.eq Lstreqn_i_match

    add x0, x0, #1
    add x1, x1, #1
    b 4b

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
    // Preload constants for null-byte detection via haszero.
    // Use x11-x13 to avoid clobbering x5-x6 used by callers (lookup_embedded).
    // x11 = 0x0101010101010101
    movz x11, #0x0101
    movk x11, #0x0101, lsl #16
    movk x11, #0x0101, lsl #32
    movk x11, #0x0101, lsl #48
    // x12 = 0x8080808080808080
    movz x12, #0x8080
    movk x12, #0x8080, lsl #16
    movk x12, #0x8080, lsl #32
    movk x12, #0x8080, lsl #48

1:
    cmp x2, #8
    b.lo 4f                    // fewer than 8 bytes → byte loop

    ldr x3, [x0]
    ldr x4, [x1]
    cmp x3, x4
    b.ne 4f                    // 8-byte words differ → byte loop to find exact pos

    // Words match — check for null bytes via haszero(x3)
    sub x13, x3, x11           // x3 - 0x0101...
    bic x13, x13, x3           // ~x3 & (x3 - 0x0101...)
    tst x13, x12               // & 0x8080... — non-zero means null byte present
    b.ne 4f                    // null byte → byte loop for correct termination

    // No nulls, perfect 8-byte match — advance
    sub x2, x2, #8
    add x0, x0, #8
    add x1, x1, #8
    cbz x2, Lstreqn_match
    b 1b

4:  // byte-at-a-time fallback
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
    b 4b

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
