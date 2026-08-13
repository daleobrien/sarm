#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: itoa
//
// Description: Convert an integer into a non-NULL-terminated string
//   (decimal). The digits are written backwards into itoa_buf starting
//   at its end, so the result is not NUL-terminated.
//
// Input/Arguments:
//   x0 -> number to convert
//
// Output/Returns:
//   x0 -> pointer to the start of the string
//   x1 -> length of the string
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x5
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.bss
// itoa_buf is byte-addressed (strb/ldrb), so no special alignment needed.
itoa_buf: .skip 20

.text
.align 2
.global itoa
itoa:
    adr_l x1, itoa_buf
    add x1, x1, #20 // Start at the END of the buffer and write backwards
    mov x2, #0      // length counter
    mov x3, #10     // divisor
1:
    udiv x4, x0, x3     // x4 = x0 / 10
    msub x5, x4, x3, x0 // x5 = x0 - (x4 * x10) = remainder
    add x5, x5, #'0'    // converts to ascii
    sub x1, x1, #1      // move pointer back
    strb w5, [x1]       // stores the digit
    add x2, x2, #1      // length++
    mov x0, x4          // quotient becomes new number
    cbnz x0, 1b         // jump back to 1 if not 0

    mov x0, x1 // x0 = pointer to start
    mov x1, x2 // x1 = length
    ret
