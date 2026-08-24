#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: itoa
//
// Description: Convert an integer into a non-NULL-terminated string
//   (decimal). The digits are written backwards into a caller-supplied
//   buffer starting at its end, so the result is not NUL-terminated and
//   does not start at the buffer's base — x0 points at the first digit.
//
//   The buffer used to be `itoa_buf`, a single process-global 20-byte
//   scratch shared by every response path that formats a number
//   (docs/MULTICORE-BASELINE.md, Step 3, category D). Under
//   fork-per-connection that was invisible, because the child's copy is
//   private; under any threaded worker model it is the one global whose
//   call sites give no hint that it carries connection-owned data. The
//   buffer is now the caller's, so the question does not arise: every
//   caller passes stack space it already owns.
//
// Input/Arguments:
//   x0 -> number to convert
//   x1 -> scratch buffer, at least ITOA_BUF_SIZE (20) bytes, writable
//         for its whole length. The result lives inside it until the
//         caller overwrites it or the frame holding it goes away.
//
// Output/Returns:
//   x0 -> pointer to the start of the string (inside the caller's buffer)
//   x1 -> length of the string
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x5
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC itoa
    add x1, x1, #ITOA_BUF_SIZE // Start at the END of the buffer and write backwards
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
ENDFUNC itoa
