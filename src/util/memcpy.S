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
// Function Name: memcpy
//
// Description: Copy N bytes from x1 into x0. Copies in 16-byte chunks
//   when possible, falling back to a byte loop.
//
// Input/Arguments:
//   x0 -> destination
//   x1 -> source
//   x2 -> length
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0, x1, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global memcpy
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
