// P-256 scalar multiplication mod n

#include "../../defs.S"

.extern p256_bn_mul

.text
.align 2
FUNC p256_scalar_mul
    sub     sp, sp, #96
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    mov     x19, x0
    mov     x20, x2

    add     x0, sp, #32
    mov     x2, #4
    mov     x3, x20
    mov     x4, #4
    bl      p256_bn_mul

    mov     x0, x19
    add     x1, sp, #32
    bl      p256_scalar_reduce_wide

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #96
    ret

p256_scalar_reduce_wide:
    sub     sp, sp, #192
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    mov     x19, x0
    mov     x20, x1

    add     x0, sp, #32
    add     x1, x20, #24
    mov     x2, #5
    adr_l   x3, p256_mu_n
    mov     x4, #5
    bl      p256_bn_mul

    add     x0, sp, #112
    add     x1, sp, #32 + 40
    mov     x2, #5
    adr_l   x3, p256_n
    mov     x4, #4
    bl      p256_bn_mul

    ldr     x2, [x20, #0]
    ldr     x3, [x20, #8]
    ldr     x4, [x20, #16]
    ldr     x5, [x20, #24]
    ldr     x6, [x20, #32]
    ldr     x7, [x20, #40]
    ldr     x8, [x20, #48]
    ldr     x9, [x20, #56]

    add     x11, sp, #112
    ldr     x12, [x11, #0]
    ldr     x13, [x11, #8]
    ldr     x14, [x11, #16]
    ldr     x15, [x11, #24]
    ldr     x16, [x11, #32]
    ldr     x17, [x11, #40]
    subs    x2, x2, x12
    sbcs    x3, x3, x13
    sbcs    x4, x4, x14
    sbcs    x5, x5, x15
    sbcs    x6, x6, x16
    sbcs    x7, x7, x17
    ldr     x12, [x11, #48]
    ldr     x13, [x11, #56]
    ldr     x14, [x11, #64]
    sbcs    x8, x8, x12
    sbcs    x9, x9, x13
    subs    x10, xzr, x14
    cset    x16, cc

    adr_l   x11, p256_n
    ldr     x12, [x11, #0]
    ldr     x13, [x11, #8]
    ldr     x14, [x11, #16]
    ldr     x15, [x11, #24]
    adds    x12, x2, x12
    adcs    x13, x3, x13
    adcs    x14, x4, x14
    adcs    x15, x5, x15
    adcs    x17, x6, xzr
    cmp     x16, #1
    csel    x2, x12, x2, eq
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x15, x5, eq
    csel    x6, x17, x6, eq

    .irp round, 1, 2
    adr_l   x11, p256_n
    ldr     x12, [x11, #0]
    ldr     x13, [x11, #8]
    ldr     x14, [x11, #16]
    ldr     x15, [x11, #24]
    subs    x12, x2, x12
    sbcs    x13, x3, x13
    sbcs    x14, x4, x14
    sbcs    x15, x5, x15
    sbcs    x17, x6, xzr
    cset    x16, cs
    cmp     x16, #1
    csel    x2, x12, x2, eq
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x15, x5, eq
    csel    x6, x17, x6, eq
    .endr

    str     x2, [x19, #0]
    str     x3, [x19, #8]
    str     x4, [x19, #16]
    str     x5, [x19, #24]

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #192
    ret
ENDFUNC p256_scalar_mul
