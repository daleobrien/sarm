#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: atoi_n (NEON Vector Optimized)
//
// Description: Convert the string representation of a number into an
//   integer, reading up to N bytes. Utilizes a 16-byte wide NEON vector
//   pathway to validate digit boundaries in parallel when length >= 16.
//   The string does not need to be NULL terminated. A 19+ digit number
//   overflows the register and returns 0. If any of the first N bytes is
//   not a digit, the conversion fails and returns 0 (carry flag set).
//
// Input/Arguments:
//   x0 -> pointer to string
//   x1 -> length of string
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
.global atoi_n
atoi_n:
    // Protect against overflow: 19+ digits is an immediate error
    cmp x1, #19
    b.hs Latoi_n_error

    // If length is less than 16, a 16-byte vector load is unsafe (could page fault).
    // Go straight to the fast scalar loop.
    cmp x1, #16
    b.lo Lscalar_prepare

    // --- NEON Path (For lengths 16, 17, or 18) ---
    // Load the first 16 bytes into a vector register
    ldr q0, [x0]

    // Setup vector constants for parallel digit validation
    mov w2, #'0'
    dup v16.16b, w2            // Vector filled with '0' (0x30)
    mov w2, #10
    dup v17.16b, w2            // Vector filled with 10

    // Subtract '0' from all 16 bytes simultaneously
    sub v0.16b, v0.16b, v16.16b

    // Unsigned comparison: flag any lane where byte >= 10 (non-digits)
    cmhs v1.16b, v0.16b, v17.16b

    // Collapse and check if any of the first 16 bytes are invalid
    umov x2, v1.d[0]           // CORRECTED: Added explicit lane index [0]
    cbnz x2, Latoi_n_error
    umov x2, v1.d[1]           // CORRECTED: Added explicit lane index [1]
    cbnz x2, Latoi_n_error

    // First 16 bytes are perfectly valid. Check remaining bytes (if length is 17 or 18)
    cmp x1, #16
    b.eq Lscalar_prepare       // Only 16 bytes total, skip extra checks

    // Check 17th byte
    ldrb w2, [x0, #16]
    sub w2, w2, #'0'
    cmp w2, #10
    b.hs Latoi_n_error

    cmp x1, #17
    b.eq Lscalar_prepare       // Only 17 bytes total, skip 18th check

    // Check 18th byte
    ldrb w2, [x0, #17]
    sub w2, w2, #'0'
    cmp w2, #10
    b.hs Latoi_n_error

Lscalar_prepare:
    // x1 contains the exact number of digits to parse (0 to 18)
    cbz x1, Lzero_return

    mov x2, #0                  // Clear accumulator
    mov x4, #10                 // Base-10 multiplier
Lconversion_loop:
    ldrb w3, [x0], #1
    sub w3, w3, #'0'
    cmp w3, #10
    b.hs Latoi_n_error         // Non-digit encountered (catches < '0' too: wraps to >= 10)
    madd x2, x2, x4, x3        // Match register sizes (all 64-bit GPRs)
    subs x1, x1, #1
    b.ne Lconversion_loop

    cmn xzr, xzr                // Set status flags to preserve original semantics
    mov x0, x2
    ret

Lzero_return:
Latoi_n_error:
    cmp xzr, xzr
    mov x0, #0
    ret
