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
