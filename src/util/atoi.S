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
// Function Name: atoi
//
// Description: Convert a NULL-terminated string to an integer (decimal).
//   Non-digit characters are rejected. A 19+ digit number overflows the
//   register and returns 0.
//
// Input/Arguments:
//   x0 -> pointer to string
//
// Output/Returns:
//   x0 -> integer representation of string
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global atoi
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
