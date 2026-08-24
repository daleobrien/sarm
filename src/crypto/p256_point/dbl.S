// P-256 Jacobian point doubling

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_dbl
//
// Description: out = 2*in (Jacobian doubling). See the file header
//   for why this needs no special-casing for infinity/Y=0 inputs. Safe
//   for out aliasing in (e.g. the in-place "R = dbl(R)" the ladder
//   uses) — every result is computed into scratch and only copied to
//   out at the very end, after every read of in has already happened.
//
// Input/Arguments:
//   x0 — out Jacobian point pointer (96 bytes)
//   x1 — in Jacobian point pointer (96 bytes)
//
// Stack Usage:
//   672 bytes: saved x29/x30, saved x19/x20, 20 4-limb scratch slots
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_point_dbl
    sub     sp, sp, #672
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    // scratch slots start at sp+32, 32 bytes each:
    //  0 delta  1 gamma  2 beta   3 t1(X1-delta)  4 t2(X1+delta)
    //  5 alpha0 6 alpha  7 t3(alpha^2)  8 t4(8*beta)  9 X3
    // 10 t5(Y1+Z1)  11 t6(t5^2)  12 t7(t6-gamma)  13 Z3
    // 14 t8(4*beta) 15 t9(t8-X3) 16 t10(alpha*t9) 17 t11(gamma^2)
    // 18 t12(8*t11) 19 Y3

    mov     x19, x0                 // out
    mov     x20, x1                 // in

#define DSLOT(i) (32 + 32*(i))

    // delta = Z1^2
    add     x0, sp, #DSLOT(0)
    add     x1, x20, #64
    bl      p256_fe_sqr

    // gamma = Y1^2
    add     x0, sp, #DSLOT(1)
    add     x1, x20, #32
    bl      p256_fe_sqr

    // beta = X1 * gamma
    add     x0, sp, #DSLOT(2)
    add     x1, x20, #0
    add     x2, sp, #DSLOT(1)
    bl      p256_fe_mul

    // t1 = X1 - delta
    add     x0, sp, #DSLOT(3)
    add     x1, x20, #0
    add     x2, sp, #DSLOT(0)
    bl      p256_fe_sub

    // t2 = X1 + delta
    add     x0, sp, #DSLOT(4)
    add     x1, x20, #0
    add     x2, sp, #DSLOT(0)
    bl      p256_fe_add

    // alpha0 = t1 * t2
    add     x0, sp, #DSLOT(5)
    add     x1, sp, #DSLOT(3)
    add     x2, sp, #DSLOT(4)
    bl      p256_fe_mul

    // alpha = 3*alpha0 = alpha0+alpha0+alpha0
    add     x0, sp, #DSLOT(6)
    add     x1, sp, #DSLOT(5)
    add     x2, sp, #DSLOT(5)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(6)
    add     x1, sp, #DSLOT(6)
    add     x2, sp, #DSLOT(5)
    bl      p256_fe_add

    // t3 = alpha^2
    add     x0, sp, #DSLOT(7)
    add     x1, sp, #DSLOT(6)
    bl      p256_fe_sqr

    // t4 = 8*beta
    add     x0, sp, #DSLOT(8)
    add     x1, sp, #DSLOT(2)
    add     x2, sp, #DSLOT(2)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(8)
    add     x1, sp, #DSLOT(8)
    add     x2, sp, #DSLOT(8)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(8)
    add     x1, sp, #DSLOT(8)
    add     x2, sp, #DSLOT(8)
    bl      p256_fe_add

    // X3 = t3 - t4
    add     x0, sp, #DSLOT(9)
    add     x1, sp, #DSLOT(7)
    add     x2, sp, #DSLOT(8)
    bl      p256_fe_sub

    // t5 = Y1 + Z1
    add     x0, sp, #DSLOT(10)
    add     x1, x20, #32
    add     x2, x20, #64
    bl      p256_fe_add

    // t6 = t5^2
    add     x0, sp, #DSLOT(11)
    add     x1, sp, #DSLOT(10)
    bl      p256_fe_sqr

    // t7 = t6 - gamma
    add     x0, sp, #DSLOT(12)
    add     x1, sp, #DSLOT(11)
    add     x2, sp, #DSLOT(1)
    bl      p256_fe_sub

    // Z3 = t7 - delta
    add     x0, sp, #DSLOT(13)
    add     x1, sp, #DSLOT(12)
    add     x2, sp, #DSLOT(0)
    bl      p256_fe_sub

    // t8 = 4*beta
    add     x0, sp, #DSLOT(14)
    add     x1, sp, #DSLOT(2)
    add     x2, sp, #DSLOT(2)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(14)
    add     x1, sp, #DSLOT(14)
    add     x2, sp, #DSLOT(14)
    bl      p256_fe_add

    // t9 = t8 - X3
    add     x0, sp, #DSLOT(15)
    add     x1, sp, #DSLOT(14)
    add     x2, sp, #DSLOT(9)
    bl      p256_fe_sub

    // t10 = alpha * t9
    add     x0, sp, #DSLOT(16)
    add     x1, sp, #DSLOT(6)
    add     x2, sp, #DSLOT(15)
    bl      p256_fe_mul

    // t11 = gamma^2
    add     x0, sp, #DSLOT(17)
    add     x1, sp, #DSLOT(1)
    bl      p256_fe_sqr

    // t12 = 8*t11
    add     x0, sp, #DSLOT(18)
    add     x1, sp, #DSLOT(17)
    add     x2, sp, #DSLOT(17)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(18)
    add     x1, sp, #DSLOT(18)
    add     x2, sp, #DSLOT(18)
    bl      p256_fe_add
    add     x0, sp, #DSLOT(18)
    add     x1, sp, #DSLOT(18)
    add     x2, sp, #DSLOT(18)
    bl      p256_fe_add

    // Y3 = t10 - t12
    add     x0, sp, #DSLOT(19)
    add     x1, sp, #DSLOT(16)
    add     x2, sp, #DSLOT(18)
    bl      p256_fe_sub

    // out = (X3, Y3, Z3) — copied now, after every read of "in" is done.
    add     x9, sp, #DSLOT(9)
    ldr     x10, [x9, #0]
    ldr     x11, [x9, #8]
    ldr     x12, [x9, #16]
    ldr     x13, [x9, #24]
    str     x10, [x19, #0]
    str     x11, [x19, #8]
    str     x12, [x19, #16]
    str     x13, [x19, #24]

    add     x9, sp, #DSLOT(19)
    ldr     x10, [x9, #0]
    ldr     x11, [x9, #8]
    ldr     x12, [x9, #16]
    ldr     x13, [x9, #24]
    str     x10, [x19, #32]
    str     x11, [x19, #40]
    str     x12, [x19, #48]
    str     x13, [x19, #56]

    add     x9, sp, #DSLOT(13)
    ldr     x10, [x9, #0]
    ldr     x11, [x9, #8]
    ldr     x12, [x9, #16]
    ldr     x13, [x9, #24]
    str     x10, [x19, #64]
    str     x11, [x19, #72]
    str     x12, [x19, #80]
    str     x13, [x19, #88]

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #672
    ret

#undef DSLOT
ENDFUNC p256_point_dbl
