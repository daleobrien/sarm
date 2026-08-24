
#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: atoi (NEON Vector Optimized)
//
// Description: Convert a NULL-terminated string to an integer (decimal).
//   Utilizes a 16-byte wide NEON vector pathway to validate digit
//   boundaries and filter non-digit characters in parallel. A 19+
//   digit number overflows the register and returns 0.
//
// Input/Arguments:
//   x0 -> pointer to string
//
// Output/Returns:
//   x0 -> integer representation of string
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, v0, v1, v16, v17
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 4                        // 16-byte instruction alignment (2^4)
FUNC atoi
    // Load 16 bytes from the string instantly
    ldr q0, [x0]

    // Setup vector constants for parallel digit validation
    mov w1, #'0'
    dup v16.16b, w1            // Vector filled with '0' (0x30)
    mov w1, #10
    dup v17.16b, w1            // Vector filled with 10

    // Subtract '0' from all 16 bytes simultaneously
    sub v0.16b, v0.16b, v16.16b

    // Unsigned comparison: flag any lane where byte >= 10
    // (This automatically flags non-digits, higher symbols, and the '\0' terminator)
    cmhs v1.16b, v0.16b, v17.16b

    // Extract the vector halves to locate the first non-digit/termination point
    umov x1, v1.d[0]
    cbnz x1, Llower_half

    umov x1, v1.d[1]
    cbnz x1, Lupper_half

    // Edge Case: All first 16 bytes are valid digits. Check up to the 19-digit limit.
    mov x2, #16
Lextend_check:
    ldrb w1, [x0, x2]
    cbz w1, Lvalid_length
    sub w3, w1, #'0'
    cmp w3, #10
    b.hs Latoi_error           // Non-digit encountered
    add x2, x2, #1
    cmp x2, #19
    b.hs Latoi_error           // Register overflow condition (19+ digits)
    b Lextend_check

Llower_half:
    rbit x1, x1
    clz x1, x1
    lsr x2, x1, #3              // x2 = index of the first stop byte (0-7)
    b Lcheck_termination

Lupper_half:
    rbit x1, x1
    clz x1, x1
    lsr x2, x1, #3
    add x2, x2, #8              // x2 = index of the first stop byte (8-15)

Lcheck_termination:
    ldrb w1, [x0, x2]
    cbnz w1, Latoi_error       // If the stop character isn't a NULL terminator, it's an error

Lvalid_length:
    // x2 now contains the exact count of valid digits (0 to 18)
    cbz x2, Lzero_return

    mov x1, #0                  // Clear accumulator
    mov x3, #10                 // Base-10 multiplier
Lconversion_loop:
    ldrb w4, [x0], #1
    sub w4, w4, #'0'
    madd x1, x1, x3, x4        // x1 = (x1 * 10) + x4
    subs x2, x2, #1
    b.ne Lconversion_loop

    cmn xzr, xzr                // Set status flags to preserve original semantics
    mov x0, x1
    ret

Lzero_return:
Latoi_error:
    cmp xzr, xzr
    mov x0, #0
    ret
ENDFUNC atoi
