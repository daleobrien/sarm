// P-256 scalar reduction mod n

#include "../../defs.S"

.text
.align 2
.global p256_scalar_reduce
p256_scalar_reduce:
    ldr     x2, [x1, #0]
    ldr     x3, [x1, #8]
    ldr     x4, [x1, #16]
    ldr     x5, [x1, #24]

    .irp round, 1, 2
    adr_l   x6, p256_n
    ldr     x7, [x6, #0]
    ldr     x8, [x6, #8]
    ldr     x9, [x6, #16]
    ldr     x10, [x6, #24]
    subs    x7, x2, x7
    sbcs    x8, x3, x8
    sbcs    x9, x4, x9
    sbcs    x10, x5, x10
    cset    x6, cs
    cmp     x6, #1
    csel    x2, x7, x2, eq
    csel    x3, x8, x3, eq
    csel    x4, x9, x4, eq
    csel    x5, x10, x5, eq
    .endr

    str     x2, [x0, #0]
    str     x3, [x0, #8]
    str     x4, [x0, #16]
    str     x5, [x0, #24]
    ret
