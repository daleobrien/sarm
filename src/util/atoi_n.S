#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: atoi_n
//
// Description: Convert the string representation of a number into an
//   integer, reading up to N bytes. The string does not need to be NULL
//   terminated. A 19+ digit number overflows the register and returns 0.
//
// Input/Arguments:
//   x0 -> pointer to string
//   x1 -> length of string
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
.global atoi_n
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
