// Decode big-endian bytes to field element

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_frombytes
//
// Description: Decode 32 big-endian bytes (the SEC1 / X9.62 integer
//   encoding P-256 coordinates and scalars use on the wire) into a
//   field element (4 little-endian 64-bit limbs). Input must already
//   be < p; this does no reduction.
//
// Input/Arguments:
//   x0 — out fe pointer (4 limbs)
//   x1 — in pointer (32 big-endian bytes)
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_fe_frombytes
    ldr     x2, [x1, #0]
    rev     x2, x2                  // most significant 8 bytes -> limb3
    ldr     x3, [x1, #8]
    rev     x3, x3                  // limb2
    ldr     x4, [x1, #16]
    rev     x4, x4                  // limb1
    ldr     x5, [x1, #24]
    rev     x5, x5                  // least significant 8 bytes -> limb0
    str     x5, [x0, #0]
    str     x4, [x0, #8]
    str     x3, [x0, #16]
    str     x2, [x0, #24]
    ret
ENDFUNC p256_fe_frombytes
