// P-256 Jacobian to affine conversion

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_to_affine
//
// Description: (outX, outY) = (X/Z^2, Y/Z^3), converting a Jacobian
//   point to affine. The caller is responsible for knowing the point
//   isn't infinity (Z=0) — p256_point_mul never returns infinity for
//   the scalar ranges ECDSA sign/verify use it for (see p256_ecdsa.S).
//   fe_inv(0) is well-defined here (produces 0, since 0^(p-2) mod p =
//   0) but the resulting "affine point" (0,0) is meaningless.
//
// Input/Arguments:
//   x0 — outX, x1 — outY (4-limb fe pointers)
//   x2 — in Jacobian point pointer (96 bytes)
//
// Stack Usage:
//   144 bytes: saved x29/x30, saved x19-x21 (+ pad), 3 4-limb scratch
//   slots (zi, zi2, zi3)
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_point_to_affine
    sub     sp, sp, #144
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    str     x21, [sp, #32]
    // sp+48 zi, sp+80 zi2, sp+112 zi3

    mov     x19, x0                 // outX
    mov     x20, x1                 // outY
    mov     x21, x2                 // in (Jacobian)

    add     x0, sp, #48
    add     x1, x21, #64
    bl      p256_fe_inv             // zi = Z^-1

    add     x0, sp, #80
    add     x1, sp, #48
    bl      p256_fe_sqr             // zi2 = zi^2

    add     x0, sp, #112
    add     x1, sp, #80
    add     x2, sp, #48
    bl      p256_fe_mul             // zi3 = zi2*zi

    mov     x0, x19
    add     x1, x21, #0
    add     x2, sp, #80
    bl      p256_fe_mul             // outX = X*zi2

    mov     x0, x20
    add     x1, x21, #32
    add     x2, sp, #112
    bl      p256_fe_mul             // outY = Y*zi3

    ldr     x21, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #144
    ret
ENDFUNC p256_point_to_affine
