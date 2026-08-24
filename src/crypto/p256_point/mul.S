// P-256 scalar multiplication

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_mul
//
// Description: (outX,outY) = k * (inX,inY), constant-time scalar
//   multiplication (Jacobian double-and-add, no scalar-dependent
//   branches — see the file header). k is treated as a raw 256-bit
//   value in 4 little-endian limbs; the caller (p256_ecdsa.S) is
//   responsible for reducing it mod n first when that matters.
//
// Input/Arguments:
//   x0 — outX, x1 — outY (4-limb fe pointers)
//   x2 — k (4-limb scalar pointer)
//   x3 — inX, x4 — inY (4-limb fe pointers)
//
// Stack Usage:
//   352 bytes: saved x29/x30, 3 pairs of saved x19-x24, a 96-byte R
//   buffer, a 96-byte P buffer, a 96-byte cand buffer
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_point_mul
    sub     sp, sp, #352
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    // sp+64  R    (96 bytes) -- the accumulator, starts at infinity
    // sp+160 P    (96 bytes) -- (inX, inY, 1)
    // sp+256 cand (96 bytes) -- scratch for R+P each iteration

    mov     x19, x0                 // outX
    mov     x20, x1                 // outY
    mov     x21, x2                 // k

    // R = infinity (all-zero Jacobian point)
    add     x12, sp, #64
    mov     x9, #0
.Lpmul_zero_r:
    cmp     x9, #96
    b.ge    .Lpmul_zero_r_done
    str     xzr, [x12, x9]
    add     x9, x9, #8
    b       .Lpmul_zero_r
.Lpmul_zero_r_done:

    // P = (inX, inY, 1)
    ldr     x9, [x3, #0]
    ldr     x10, [x3, #8]
    ldr     x11, [x3, #16]
    ldr     x12, [x3, #24]
    str     x9, [sp, #160]
    str     x10, [sp, #168]
    str     x11, [sp, #176]
    str     x12, [sp, #184]
    ldr     x9, [x4, #0]
    ldr     x10, [x4, #8]
    ldr     x11, [x4, #16]
    ldr     x12, [x4, #24]
    str     x9, [sp, #192]
    str     x10, [sp, #200]
    str     x11, [sp, #208]
    str     x12, [sp, #216]
    mov     x9, #1
    str     x9, [sp, #224]
    str     xzr, [sp, #232]
    str     xzr, [sp, #240]
    str     xzr, [sp, #248]

    mov     x22, #255               // i = 255 .. 0
.Lpmul_loop:
    // R = dbl(R)
    add     x0, sp, #64
    add     x1, sp, #64
    bl      p256_point_dbl

    // cand = R + P
    add     x0, sp, #256
    add     x1, sp, #64
    add     x2, sp, #160
    bl      p256_point_add

    // bit = (k[i/64] >> (i%64)) & 1
    lsr     x9, x22, #6
    and     x10, x22, #63
    ldr     x11, [x21, x9, lsl #3]
    lsr     x11, x11, x10
    and     x23, x11, #1

    // R = cond ? cand : R
    add     x0, sp, #64
    add     x1, sp, #256
    mov     x2, x23
    bl      p256_fe_cmov
    add     x0, sp, #96
    add     x1, sp, #288
    mov     x2, x23
    bl      p256_fe_cmov
    add     x0, sp, #128
    add     x1, sp, #320
    mov     x2, x23
    bl      p256_fe_cmov

    subs    x22, x22, #1
    b.ge    .Lpmul_loop

    mov     x0, x19
    mov     x1, x20
    add     x2, sp, #64
    bl      p256_point_to_affine

    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #352
    ret
ENDFUNC p256_point_mul
