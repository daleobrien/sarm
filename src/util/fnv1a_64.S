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
// Function Name: fnv1a_64
//
// Description: FNV-1a 64-bit hash of a byte buffer.
//
// Input/Arguments:
//   x0 -> buffer
//   x1 -> length
//
// Output/Returns:
//   x0 -> 64-bit hash
//
// Clobbered Registers:
//   x1, x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global fnv1a_64
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
