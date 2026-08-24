// Field subtraction mod p

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_sub
//
// Description: out = (a - b) mod p, constant-time (branchless
//   conditional add via CSEL).
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer, x2 — b fe pointer
//   (out may alias a and/or b)
//
// Clobbered Registers:
//   x3-x13
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_fe_sub
    ldr     x3, [x1, #0]
    ldr     x4, [x1, #8]
    ldr     x5, [x1, #16]
    ldr     x6, [x1, #24]
    ldr     x7, [x2, #0]
    ldr     x8, [x2, #8]
    ldr     x9, [x2, #16]
    ldr     x10, [x2, #24]

    subs    x3, x3, x7
    sbcs    x4, x4, x8
    sbcs    x5, x5, x9
    sbcs    x6, x6, x10
    cset    x11, cc                 // 1 if a < b (the subtract borrowed)

    adr_l   x12, p256_p
    ldr     x13, [x12, #0]
    adds    x13, x3, x13
    str     x13, [x0, #0]           // stash a-b+p limb0 temporarily
    ldr     x13, [x12, #8]
    adcs    x13, x4, x13
    str     x13, [x0, #8]
    ldr     x13, [x12, #16]
    adcs    x13, x5, x13
    str     x13, [x0, #16]
    ldr     x13, [x12, #24]
    adcs    x13, x6, x13
    // x13 now holds a-b+p limb3; the other three limbs are in [x0]

    cmp     x11, #1
    ldr     x7, [x0, #0]
    csel    x3, x7, x3, eq
    ldr     x7, [x0, #8]
    csel    x4, x7, x4, eq
    ldr     x7, [x0, #16]
    csel    x5, x7, x5, eq
    csel    x6, x13, x6, eq

    str     x3, [x0, #0]
    str     x4, [x0, #8]
    str     x5, [x0, #16]
    str     x6, [x0, #24]
    ret
ENDFUNC p256_fe_sub
