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
// Function Name: check_path_traversal
//
// Description: Check a filename for path traversal (e.g. GET /../../file.txt).
//   Does nothing else: a single dot is fine, three or more dots are fine, and
//   ".." inside a name like "foo..txt" is fine. Only a path segment that is
//   exactly ".." is rejected.
//
// Input/Arguments:
//   x0 -> filename string
//   x1 -> filename length
//
// Output/Returns:
//   x0 -> 1 if safe, 0 if unsafe
//
// Clobbered Registers:
//   x0, x2, x3, x4, w5
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global check_path_traversal
check_path_traversal:
    mov x2, #0
    mov x3, #0
    mov x4, #0

Lloop:
    cmp x2, x1
    b.ge Lcheck_segment

    ldrb w5, [x0, x2]

    cmp w5, #'/'
    b.eq Lcheck_segment

    cmp w5, #0
    b.eq Lcheck_segment

    add x2, x2, #1
    add x4, x4, #1

    cmp w5, #'.'
    b.eq 2f

    b Lloop

2:
    add x3, x3, #1
    b Lloop

Lcheck_segment:
    cmp x3, x4
    b.eq Lequal_length

3:
    mov x3, #0
    mov x4, #0

    cmp x2, x1
    b.ge Lno_path_traversal

    add x2, x2, #1
    b Lloop

Lequal_length:
    cmp x3, #2
    b.eq Lpath_traversal

    b 3b

Lno_path_traversal:
    mov x0, #1
    ret

Lpath_traversal:
    mov x0, #0
    ret
