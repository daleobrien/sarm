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
// Function Name: streqn
//
// Description: Case-sensitive string compare of up to `max length`
//   bytes. Uses an 8-byte word fast path with null-byte detection,
//   falling back to a byte loop. Uses x11-x13 as scratch so x5-x6 used
//   by callers (lookup_embedded) are preserved.
//
// Input/Arguments:
//   x0 -> str1
//   x1 -> str2
//   x2 -> max length
//
// Output/Returns:
//   x0 -> 1 if match, 0 if doesn't match
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x11, x12, x13
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global streqn
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
