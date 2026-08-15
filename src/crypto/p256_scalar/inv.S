// P-256 scalar inversion mod n

#include "../../defs.S"

.text
.align 2
.global p256_scalar_inv
p256_scalar_inv:
    sub     sp, sp, #80
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]

    mov     x19, x0
    mov     x20, x1

    mov     x9, #1
    str     x9, [sp, #48]
    str     xzr, [sp, #56]
    str     xzr, [sp, #64]
    str     xzr, [sp, #72]

    mov     x22, #255
.Lscalar_inv_loop:
    lsr     x9, x22, #6
    and     x10, x22, #63
    adr_l   x11, p256_n_minus_2
    ldr     x12, [x11, x9, lsl #3]
    lsr     x12, x12, x10
    and     x21, x12, #1

    add     x0, sp, #48
    add     x1, sp, #48
    mov     x2, x0
    bl      p256_scalar_mul

    cmp     x21, #0
    b.eq    .Lscalar_inv_skip_mul
    add     x0, sp, #48
    add     x1, sp, #48
    mov     x2, x20
    bl      p256_scalar_mul
.Lscalar_inv_skip_mul:
    subs    x22, x22, #1
    b.ge    .Lscalar_inv_loop

    ldr     x9, [sp, #48]
    str     x9, [x19, #0]
    ldr     x9, [sp, #56]
    str     x9, [x19, #8]
    ldr     x9, [sp, #64]
    str     x9, [x19, #16]
    ldr     x9, [sp, #72]
    str     x9, [x19, #24]

    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #80
    ret
