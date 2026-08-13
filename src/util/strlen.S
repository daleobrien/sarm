#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: strlen
//
// Description: Get the length of a NULL-terminated string, scanning 16
//   bytes at a time with NEON (cmeq NUL mask, umaxv reduction) and
//   pinpointing the exact NUL byte position with rbit/clz. NOTE: this
//   is a non-standard ABI — the string argument is passed in x1, not x0.
//
// Input/Arguments:
//   x1 -> NULL-terminated string whose length to check
//
// Output/Returns:
//   x0 -> length of string
//
// Clobbered Registers:
//   x0, x2, x3, v0, v1, v2
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 4
.global strlen
strlen:
    mov x0, x1                  // Copy start address to track progress

Lneon_loop:
    ldr q0, [x0]                // Load 16 bytes from current string position
    cmeq v1.16b, v0.16b, #0     // Set lane bytes to 0xFF where a null byte is found
    umaxv b2, v1.16b            // Collapse vector: get max byte value across all 16 lanes
    umov w3, v2.b[0]            // CORRECTED: Extract lane 0 from vector to GPR
    cbnz w3, Lfound             // If non-zero, at least one null terminator was found
    add x0, x0, #16             // Advance pointer by 16 bytes
    b Lneon_loop                // Continue loop

Lfound:
    // Pinpoint the exact null byte position within the 16-byte block
    umov x2, v1.d[0]            // CORRECTED: Extract lower 8 bytes (lanes 0-7)
    cbnz x2, Llower_half        // If non-zero, null byte is within first 8 bytes

    umov x2, v1.d[1]            // CORRECTED: Extract upper 8 bytes (lanes 8-15)
    rbit x2, x2                 // Reverse bits to find trailing zeros
    clz x2, x2                  // Count leading zeros
    lsr x2, x2, #3              // Convert bit count to byte index (divide by 8)
    add x0, x0, #8              // Offset by 8 bytes for upper half
    add x0, x0, x2              // Add exact byte index within upper half
    sub x0, x0, x1              // Compute total length
    ret

Llower_half:
    rbit x2, x2                 // Reverse bits to find trailing zeros
    clz x2, x2                  // Count leading zeros
    lsr x2, x2, #3              // Convert bit count to byte index
    add x0, x0, x2              // Add exact byte index within lower half
    sub x0, x0, x1              // Compute total length
    ret
