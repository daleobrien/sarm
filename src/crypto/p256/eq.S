// Constant-time equality test

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_eq
//
// Description: Constant-time equality test of two canonical (< p)
//   field elements: exact limb comparison (safe since fe_add/sub/mul
//   always produce canonical output, so two field elements are equal
//   iff their limbs are identical).
//
// Input/Arguments:
//   x0 — a fe pointer, x1 — b fe pointer
//
// Output/Returns:
//   x0 — 1 if equal, 0 otherwise
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_eq
p256_fe_eq:
    ldr     x2, [x0, #0]
    ldr     x3, [x1, #0]
    eor     x2, x2, x3
    ldr     x3, [x0, #8]
    ldr     x4, [x1, #8]
    eor     x3, x3, x4
    orr     x2, x2, x3
    ldr     x3, [x0, #16]
    ldr     x4, [x1, #16]
    eor     x3, x3, x4
    orr     x2, x2, x3
    ldr     x3, [x0, #24]
    ldr     x4, [x1, #24]
    eor     x3, x3, x4
    orr     x2, x2, x3
    cmp     x2, #0
    cset    x0, eq
    ret
