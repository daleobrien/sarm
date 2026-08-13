#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: streqn
//
// Description: Case-sensitive streqn. Compares up to `max length`
//   bytes of str1 and str2, stopping early when both strings hit a NUL
//   terminator at the same position (equivalent to strncmp(str1, str2,
//   max_len) == 0). A 16-byte-wide NEON fast path handles the bulk of
//   the comparison (cmeq equality mask, NUL detection on str1 — a NUL
//   only in str2 surfaces as a mismatch — combined mismatch/NUL exit
//   mask, umaxv reduction to detect a stop), falling back to a
//   byte-at-a-time loop for the tail (< 16 bytes) and to resolve the
//   exact position of a NUL or mismatch.
//
//   Uses x11 (w11) as scratch; NEON v0-v4 are clobbered but only when
//   the 16-byte path actually runs (x2 >= 16).
//
// Input/Arguments:
//   x0 -> str1
//   x1 -> str2
//   x2 -> max length
//
// Output/Returns:
//   x0 -> 1 if match, 0 if doesn't match
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x11
//   NEON (only on the x2 >= 16 path): v0-v4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────
.text
.align 4                        // 16-byte instruction alignment (2^4)
.global streqn
streqn:
    cbz x2, Lstreqn_match

Lneon_loop:
    cmp x2, #16
    b.lo Lbyte_loop            // Fewer than 16 bytes left -> finish with byte loop

    // Load 16 bytes from each string simultaneously
    ldr q0, [x0]               // q0 = 16 bytes from str1
    ldr q1, [x1]               // q1 = 16 bytes from str2

    // Check for byte matches and null terminators
    cmeq v2.16b, v0.16b, v1.16b
    cmeq v3.16b, v0.16b, #0

    // Invert the match vector to find mismatches
    mvn v2.16b, v2.16b          // v2 lanes = 0xFF where bytes mismatch
    orr v2.16b, v2.16b, v3.16b  // Combine conditions: 0xFF where mismatch OR null terminator

    // Vector reduction to check if any lane triggered an exit condition
    umaxv b4, v2.16b            // Accumulate maximum byte value across all lanes
    umov w11, v4.b[0]           // Extract lane 0 to general purpose register
    cbnz w11, Lbyte_loop        // If non-zero, a mismatch or null was hit -> resolve in byte loop

    // Perfect 16-byte match with no nulls -> advance pointers and counter
    add x0, x0, #16
    add x1, x1, #16
    sub x2, x2, #16
    cbz x2, Lstreqn_match
    b Lneon_loop

Lbyte_loop:
    // Safe byte-at-a-time fallback (identical to original semantics)
    ldrb w3, [x0]
    ldrb w4, [x1]
    cmp w3, w4
    b.ne Lstreqn_no_match

    cbz w3, Lstreqn_match      // Both equal and both NULL -> string match end

    subs x2, x2, #1
    b.eq Lstreqn_match

    add x0, x0, #1
    add x1, x1, #1
    b Lbyte_loop

Lstreqn_match:
    mov x0, #1
    ret

Lstreqn_no_match:
    mov x0, #0
    ret
