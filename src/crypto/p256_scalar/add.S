// P-256 scalar addition mod n

#include "../../defs.S"

.text
.align 2
FUNC p256_scalar_add
    ldr     x3, [x1, #0]
    ldr     x4, [x1, #8]
    ldr     x5, [x1, #16]
    ldr     x6, [x1, #24]
    ldr     x7, [x2, #0]
    ldr     x8, [x2, #8]
    ldr     x9, [x2, #16]
    ldr     x10, [x2, #24]

    adds    x3, x3, x7
    adcs    x4, x4, x8
    adcs    x5, x5, x9
    adcs    x6, x6, x10
    cset    x11, cs

    adr_l   x12, p256_n
    ldr     x13, [x12, #0]
    ldr     x14, [x12, #8]
    subs    x13, x3, x13
    sbcs    x14, x4, x14
    ldr     x9, [x12, #16]
    ldr     x10, [x12, #24]
    sbcs    x9, x5, x9
    sbcs    x10, x6, x10
    cset    x12, cs

    orr     x11, x11, x12
    cmp     x11, #1
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x9, x5, eq
    csel    x6, x10, x6, eq

    str     x3, [x0, #0]
    str     x4, [x0, #8]
    str     x5, [x0, #16]
    str     x6, [x0, #24]
    ret
ENDFUNC p256_scalar_add
