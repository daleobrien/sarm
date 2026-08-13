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
// Function Name: write_all
//
// Description: Write content to a file descriptor, retrying in case of
//   partial writes until all nbytes are written. EINTR is retried;
//   EPIPE is treated as a clean exit (client disconnected).
//
// Input/Arguments:
//   x0 -> file descriptor (same as write() syscall)
//   x1 -> buffer
//   x2 -> nbytes
//
// Output/Returns:
//   x0 -> total number of bytes written
//   carry clear = success, carry set = error (x0 = errno)
//
// Clobbered Registers:
//   x0, x1, x2, x25, x26 (x25/x26 saved and restored)
//
// Stack Usage:
//   16 bytes: stp x25, x26, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global write_all
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
