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
// Function Name: h2_read_exact
//
// Description: Read exactly len bytes from the fd into buf. Loops over
//   short reads; EINTR is retried; EOF or any other error returns with
//   carry set. The frame loop relies on this so a frame is never
//   partially buffered.
//
// Input/Arguments:
//   x0 — fd, x1 — buffer, x2 — length
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 — errno on failure (carry set); 0 on EOF
//
// Clobbered Registers:
//   x0-x4, x19-x21, x30 (x19-x21 saved/restored)
//
// Stack Usage:
//   32 bytes: stp x19, x20, [sp, #-32]!; stp x21, x30, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_read_exact
h2_read_exact:
    stp x19, x20, [sp, #-32]!
    stp x21, x30, [sp, #16]
    mov x19, x0             // fd
    mov x20, x1             // buffer
    mov x21, x2             // bytes remaining
.Lh2rex_loop:
    cbz x21, .Lh2rex_done
    SCWINUM SYS_read
    mov x0, x19
    mov x1, x20
    mov x2, x21
    SCWISVC
    SCERR
    b.cs .Lh2rex_fail
    cbz x0, .Lh2rex_eof
    add x20, x20, x0
    sub x21, x21, x0
    b .Lh2rex_loop
.Lh2rex_done:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.Lh2rex_fail:
    cmp x0, #EINTR
    b.eq .Lh2rex_loop       // interrupted — nothing was consumed, retry
    cmp xzr, xzr            // failure — carry set
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret                     // x0 = errno
.Lh2rex_eof:
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
