// P-256 Jacobian point addition

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_add
//
// Description: out = P1 + P2 (Jacobian addition), correct for
//   coincident/negated/infinity inputs too. See the file header for
//   the algorithm. Safe for out aliasing P1 and/or P2 (result is fully
//   assembled in scratch before the single copy to out at the end).
//
// Input/Arguments:
//   x0 — out, x1 — P1, x2 — P2 (96-byte Jacobian point pointers)
//
// Stack Usage:
//   880 bytes: saved x29/x30, 4 pairs of saved x19-x26, 23 4-limb
//   scratch slots plus a 96-byte dbl-result buffer (slot 22..24)
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_point_add
    sub     sp, sp, #880
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    // scratch slots start at sp+80, 32 bytes each:
    //  0 Z1Z1  1 Z2Z2  2 U1  3 U2  4 Z2cubed  5 S1  6 Z1cubed  7 S2
    //  8 H  9 r  10 HH  11 HHH  12 V  13 rr  14 t_a  15 twoV
    //  16 t_b/scratch  17 t_c  18 t_d
    // 19..21 result (X,Y,Z contiguous) — add_generic's output, then
    //         corrected in place by the CSEL steps below
    // 22..24 dbl_result (X,Y,Z contiguous)

    mov     x19, x0                 // out
    mov     x20, x1                 // P1
    mov     x21, x2                 // P2

#define ASLOT(i) (80 + 32*(i))

    // Z1Z1 = Z1^2, Z2Z2 = Z2^2
    add     x0, sp, #ASLOT(0)
    add     x1, x20, #64
    bl      p256_fe_sqr
    add     x0, sp, #ASLOT(1)
    add     x1, x21, #64
    bl      p256_fe_sqr

    // U1 = X1*Z2Z2, U2 = X2*Z1Z1
    add     x0, sp, #ASLOT(2)
    add     x1, x20, #0
    add     x2, sp, #ASLOT(1)
    bl      p256_fe_mul
    add     x0, sp, #ASLOT(3)
    add     x1, x21, #0
    add     x2, sp, #ASLOT(0)
    bl      p256_fe_mul

    // Z2cubed = Z2*Z2Z2, S1 = Y1*Z2cubed
    add     x0, sp, #ASLOT(4)
    add     x1, x21, #64
    add     x2, sp, #ASLOT(1)
    bl      p256_fe_mul
    add     x0, sp, #ASLOT(5)
    add     x1, x20, #32
    add     x2, sp, #ASLOT(4)
    bl      p256_fe_mul

    // Z1cubed = Z1*Z1Z1, S2 = Y2*Z1cubed
    add     x0, sp, #ASLOT(6)
    add     x1, x20, #64
    add     x2, sp, #ASLOT(0)
    bl      p256_fe_mul
    add     x0, sp, #ASLOT(7)
    add     x1, x21, #32
    add     x2, sp, #ASLOT(6)
    bl      p256_fe_mul

    // H = U2-U1, r = S2-S1
    add     x0, sp, #ASLOT(8)
    add     x1, sp, #ASLOT(3)
    add     x2, sp, #ASLOT(2)
    bl      p256_fe_sub
    add     x0, sp, #ASLOT(9)
    add     x1, sp, #ASLOT(7)
    add     x2, sp, #ASLOT(5)
    bl      p256_fe_sub

    // HH = H^2, HHH = H*HH, V = U1*HH
    add     x0, sp, #ASLOT(10)
    add     x1, sp, #ASLOT(8)
    bl      p256_fe_sqr
    add     x0, sp, #ASLOT(11)
    add     x1, sp, #ASLOT(8)
    add     x2, sp, #ASLOT(10)
    bl      p256_fe_mul
    add     x0, sp, #ASLOT(12)
    add     x1, sp, #ASLOT(2)
    add     x2, sp, #ASLOT(10)
    bl      p256_fe_mul

    // rr = r^2, t_a = rr - HHH, twoV = V+V, X3 = t_a - twoV
    add     x0, sp, #ASLOT(13)
    add     x1, sp, #ASLOT(9)
    bl      p256_fe_sqr
    add     x0, sp, #ASLOT(14)
    add     x1, sp, #ASLOT(13)
    add     x2, sp, #ASLOT(11)
    bl      p256_fe_sub
    add     x0, sp, #ASLOT(15)
    add     x1, sp, #ASLOT(12)
    add     x2, sp, #ASLOT(12)
    bl      p256_fe_add
    add     x0, sp, #ASLOT(19)
    add     x1, sp, #ASLOT(14)
    add     x2, sp, #ASLOT(15)
    bl      p256_fe_sub

    // t_b = V - X3, t_c = r*t_b, t_d = S1*HHH, Y3 = t_c - t_d
    add     x0, sp, #ASLOT(16)
    add     x1, sp, #ASLOT(12)
    add     x2, sp, #ASLOT(19)
    bl      p256_fe_sub
    add     x0, sp, #ASLOT(17)
    add     x1, sp, #ASLOT(9)
    add     x2, sp, #ASLOT(16)
    bl      p256_fe_mul
    add     x0, sp, #ASLOT(18)
    add     x1, sp, #ASLOT(5)
    add     x2, sp, #ASLOT(11)
    bl      p256_fe_mul
    add     x0, sp, #(ASLOT(19) + 32)
    add     x1, sp, #ASLOT(17)
    add     x2, sp, #ASLOT(18)
    bl      p256_fe_sub

    // Z3 = H*Z1*Z2 (SLOT(16) is free again by now)
    add     x0, sp, #ASLOT(16)
    add     x1, sp, #ASLOT(8)
    add     x2, x20, #64
    bl      p256_fe_mul
    add     x0, sp, #(ASLOT(19) + 64)
    add     x1, sp, #ASLOT(16)
    add     x2, x21, #64
    bl      p256_fe_mul

    // dbl_result = dbl(P1)
    add     x0, sp, #ASLOT(22)
    mov     x1, x20
    bl      p256_point_dbl

    // eq_u = (U1 == U2), eq_s = (S1 == S2)
    add     x0, sp, #ASLOT(2)
    add     x1, sp, #ASLOT(3)
    bl      p256_fe_eq
    mov     x22, x0
    add     x0, sp, #ASLOT(5)
    add     x1, sp, #ASLOT(7)
    bl      p256_fe_eq
    mov     x23, x0

    // is_z1_zero, is_z2_zero (P2 (x21) is no longer needed after this)
    ldr     x9, [x20, #64]
    ldr     x10, [x20, #72]
    orr     x9, x9, x10
    ldr     x10, [x20, #80]
    orr     x9, x9, x10
    ldr     x10, [x20, #88]
    orr     x9, x9, x10
    cmp     x9, #0
    cset    x24, eq                 // is_z1_zero

    ldr     x9, [x21, #64]
    ldr     x10, [x21, #72]
    orr     x9, x9, x10
    ldr     x10, [x21, #80]
    orr     x9, x9, x10
    ldr     x10, [x21, #88]
    orr     x9, x9, x10
    cmp     x9, #0
    cset    x25, eq                 // is_z2_zero

    // if (eq_u && eq_s): result = dbl_result
    and     x9, x22, x23
    add     x0, sp, #(ASLOT(19) + 0)
    add     x1, sp, #(ASLOT(22) + 0)
    mov     x2, x9
    bl      p256_fe_cmov
    and     x9, x22, x23
    add     x0, sp, #(ASLOT(19) + 32)
    add     x1, sp, #(ASLOT(22) + 32)
    mov     x2, x9
    bl      p256_fe_cmov
    and     x9, x22, x23
    add     x0, sp, #(ASLOT(19) + 64)
    add     x1, sp, #(ASLOT(22) + 64)
    mov     x2, x9
    bl      p256_fe_cmov

    // if (eq_u && !eq_s): result = infinity (zero the dbl_result
    // scratch buffer, now unused, and cmov from it)
    str     xzr, [sp, #(ASLOT(22) + 0)]
    str     xzr, [sp, #(ASLOT(22) + 8)]
    str     xzr, [sp, #(ASLOT(22) + 16)]
    str     xzr, [sp, #(ASLOT(22) + 24)]
    str     xzr, [sp, #(ASLOT(22) + 32)]
    str     xzr, [sp, #(ASLOT(22) + 40)]
    str     xzr, [sp, #(ASLOT(22) + 48)]
    str     xzr, [sp, #(ASLOT(22) + 56)]
    str     xzr, [sp, #(ASLOT(22) + 64)]
    str     xzr, [sp, #(ASLOT(22) + 72)]
    str     xzr, [sp, #(ASLOT(22) + 80)]
    str     xzr, [sp, #(ASLOT(22) + 88)]
    eor     x10, x23, #1
    and     x9, x22, x10
    add     x0, sp, #(ASLOT(19) + 0)
    add     x1, sp, #(ASLOT(22) + 0)
    mov     x2, x9
    bl      p256_fe_cmov
    eor     x10, x23, #1
    and     x9, x22, x10
    add     x0, sp, #(ASLOT(19) + 32)
    add     x1, sp, #(ASLOT(22) + 32)
    mov     x2, x9
    bl      p256_fe_cmov
    eor     x10, x23, #1
    and     x9, x22, x10
    add     x0, sp, #(ASLOT(19) + 64)
    add     x1, sp, #(ASLOT(22) + 64)
    mov     x2, x9
    bl      p256_fe_cmov

    // if Z2==0: result = P1
    add     x0, sp, #(ASLOT(19) + 0)
    add     x1, x20, #0
    mov     x2, x25
    bl      p256_fe_cmov
    add     x0, sp, #(ASLOT(19) + 32)
    add     x1, x20, #32
    mov     x2, x25
    bl      p256_fe_cmov
    add     x0, sp, #(ASLOT(19) + 64)
    add     x1, x20, #64
    mov     x2, x25
    bl      p256_fe_cmov

    // if Z1==0: result = P2 (applied last, wins over everything above)
    add     x0, sp, #(ASLOT(19) + 0)
    add     x1, x21, #0
    mov     x2, x24
    bl      p256_fe_cmov
    add     x0, sp, #(ASLOT(19) + 32)
    add     x1, x21, #32
    mov     x2, x24
    bl      p256_fe_cmov
    add     x0, sp, #(ASLOT(19) + 64)
    add     x1, x21, #64
    mov     x2, x24
    bl      p256_fe_cmov

    // out = result
    add     x9, sp, #ASLOT(19)
    mov     x10, #0
.Lpadd_copy:
    cmp     x10, #96
    b.ge    .Lpadd_copy_done
    ldr     x11, [x9, x10]
    str     x11, [x19, x10]
    add     x10, x10, #8
    b       .Lpadd_copy
.Lpadd_copy_done:

    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #880
    ret

#undef ASLOT
ENDFUNC p256_point_add
