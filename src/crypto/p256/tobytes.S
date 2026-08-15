// Encode field element to big-endian bytes

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_tobytes
//
// Description: Encode a field element to 32 big-endian bytes (SEC1 /
//   X9.62 integer encoding). Inverse of p256_fe_frombytes.
//
// Input/Arguments:
//   x0 — out pointer (32 big-endian bytes)
//   x1 — in fe pointer (4 limbs)
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_tobytes
p256_fe_tobytes:
    ldr     x2, [x1, #0]            // limb0
    ldr     x3, [x1, #8]            // limb1
    ldr     x4, [x1, #16]           // limb2
    ldr     x5, [x1, #24]           // limb3
    rev     x2, x2
    rev     x3, x3
    rev     x4, x4
    rev     x5, x5
    str     x5, [x0, #0]            // limb3 (most significant) first
    str     x4, [x0, #8]
    str     x3, [x0, #16]
    str     x2, [x0, #24]
    ret
