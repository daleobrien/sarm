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
// Function Name: strlen
//
// Description: Get the length of a NULL-terminated string. NOTE: this
//   is a non-standard ABI — the string argument is passed in x1, not x0.
//
// Input/Arguments:
//   x1 -> string whose length to check
//
// Output/Returns:
//   x0 -> length of string
//
// Clobbered Registers:
//   x0, x3
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global strlen
strlen:
    mov x0, #0
1:
    ldrb w3, [x1, x0]
    cbz w3, 2f
    add x0, x0, #1
    b 1b

2:
    ret
