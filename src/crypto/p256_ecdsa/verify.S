// P-256 ECDSA verification

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_ecdsa_verify
//
// Description: Verify an ECDSA signature (r,s) over a 32-byte hash
//   against a public key (Qx,Qy), all as big-endian byte arrays.
//
// Algorithm:
//   reject if r or s not in [1, n-1]
//   reject if Q isn't on the curve (y^2 = x^3 - 3x + b mod p)
//   z = hash mod n
//   w = s^-1 mod n
//   u1 = z*w mod n, u2 = r*w mod n
//   (vx,vy) = u1*G + u2*Q        -- reject if this is infinity
//   accept iff vx mod n == r
//
// This function operates entirely on public data (signature, message
// hash, public key), so unlike the lower layers it uses plain branches
// for early rejects rather than constant-time operations.
//
// Input/Arguments:
//   x0 — hash (32 bytes), x1 — sig_r (32 bytes), x2 — sig_s (32 bytes)
//   x3 — Qx (32 bytes), x4 — Qy (32 bytes)
//
// Output/Returns:
//   x0 — 1 if the signature is valid, 0 otherwise
//
// Stack Usage:
//   992 bytes: saved x29/x30, 3 pairs of saved x19-x24, 29 4-limb
//   scratch slots (Jacobian points need 3 slots each; the largest
//   users are the two Jacobian operands and their sum for the final
//   u1*G + u2*Q combination)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global p256_ecdsa_verify

p256_ecdsa_verify:
    sub     sp, sp, #992
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    // scratch slots start at sp+64, 32 bytes each:
    //  0 hash   1 r    2 s    3 Qx    4 Qy    5 z     6 w
    //  7 u1     8 u2   9 p1x  10 p1y  11 p2x  12 p2y
    // 13..15 jac1 (X,Y,Z)   16..18 jac2 (X,Y,Z)   19..21 jacsum
    // 22 vx  23 vy(unused)  24 v(final, reduced mod n)
    // 25 t_a  26 t_b  27 t_c  28 rhs   (curve-equation scratch)

    mov     x19, x0                 // hash ptr
    mov     x20, x1                 // sig_r ptr
    mov     x21, x2                 // sig_s ptr
    mov     x22, x3                 // Qx ptr
    mov     x23, x4                 // Qy ptr

#define VSLOT(i) (64 + 32*(i))

    add     x0, sp, #VSLOT(0)
    mov     x1, x19
    bl      p256_fe_frombytes       // hash_limbs
    add     x0, sp, #VSLOT(1)
    mov     x1, x20
    bl      p256_fe_frombytes       // r_limbs
    add     x0, sp, #VSLOT(2)
    mov     x1, x21
    bl      p256_fe_frombytes       // s_limbs
    add     x0, sp, #VSLOT(3)
    mov     x1, x22
    bl      p256_fe_frombytes       // Qx_limbs
    add     x0, sp, #VSLOT(4)
    mov     x1, x23
    bl      p256_fe_frombytes       // Qy_limbs

    // reject if r or s not in [1, n-1]
    add     x1, sp, #VSLOT(1)
    bl      .Lverify_in_range
    cbz     x0, .Lverify_reject
    add     x1, sp, #VSLOT(2)
    bl      .Lverify_in_range
    cbz     x0, .Lverify_reject

    // reject if Q is not on the curve: Qy^2 == Qx^3 - 3*Qx + b (mod p)
    add     x0, sp, #VSLOT(25)
    add     x1, sp, #VSLOT(4)
    bl      p256_fe_sqr             // t_a = Qy^2
    add     x0, sp, #VSLOT(26)
    add     x1, sp, #VSLOT(3)
    bl      p256_fe_sqr             // t_b = Qx^2
    add     x0, sp, #VSLOT(26)
    add     x1, sp, #VSLOT(26)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_mul             // t_b = Qx^3
    add     x0, sp, #VSLOT(27)
    add     x1, sp, #VSLOT(3)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_add             // t_c = 2*Qx
    add     x0, sp, #VSLOT(27)
    add     x1, sp, #VSLOT(27)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_add             // t_c = 3*Qx
    add     x0, sp, #VSLOT(28)
    add     x1, sp, #VSLOT(26)
    add     x2, sp, #VSLOT(27)
    bl      p256_fe_sub             // rhs = Qx^3 - 3*Qx
    adr_l   x2, p256_b
    add     x0, sp, #VSLOT(28)
    add     x1, sp, #VSLOT(28)
    bl      p256_fe_add             // rhs = Qx^3 - 3*Qx + b
    add     x0, sp, #VSLOT(25)
    add     x1, sp, #VSLOT(28)
    bl      p256_fe_eq              // Qy^2 == rhs ?
    cbz     x0, .Lverify_reject

    // z = hash mod n, w = s^-1 mod n
    add     x0, sp, #VSLOT(5)
    add     x1, sp, #VSLOT(0)
    bl      p256_scalar_reduce
    add     x0, sp, #VSLOT(6)
    add     x1, sp, #VSLOT(2)
    bl      p256_scalar_inv

    // u1 = z*w mod n, u2 = r*w mod n
    add     x0, sp, #VSLOT(7)
    add     x1, sp, #VSLOT(5)
    add     x2, sp, #VSLOT(6)
    bl      p256_scalar_mul
    add     x0, sp, #VSLOT(8)
    add     x1, sp, #VSLOT(1)
    add     x2, sp, #VSLOT(6)
    bl      p256_scalar_mul

    // (p1x,p1y) = u1*G
    add     x0, sp, #VSLOT(9)
    add     x1, sp, #VSLOT(10)
    add     x2, sp, #VSLOT(7)
    adr_l   x3, p256_gx
    adr_l   x4, p256_gy
    bl      p256_point_mul

    // (p2x,p2y) = u2*Q
    add     x0, sp, #VSLOT(11)
    add     x1, sp, #VSLOT(12)
    add     x2, sp, #VSLOT(8)
    add     x3, sp, #VSLOT(3)
    add     x4, sp, #VSLOT(4)
    bl      p256_point_mul

    // jac1 = (p1x,p1y,1), jac2 = (p2x,p2y,1)
    add     x9, sp, #VSLOT(13)
    add     x10, sp, #VSLOT(9)
    ldr     x11, [x10, #0]
    ldr     x12, [x10, #8]
    ldr     x13, [x10, #16]
    ldr     x14, [x10, #24]
    str     x11, [x9, #0]
    str     x12, [x9, #8]
    str     x13, [x9, #16]
    str     x14, [x9, #24]
    ldr     x11, [x10, #32]
    ldr     x12, [x10, #40]
    ldr     x13, [x10, #48]
    ldr     x14, [x10, #56]
    str     x11, [x9, #32]
    str     x12, [x9, #40]
    str     x13, [x9, #48]
    str     x14, [x9, #56]
    mov     x11, #1
    str     x11, [x9, #64]
    str     xzr, [x9, #72]
    str     xzr, [x9, #80]
    str     xzr, [x9, #88]

    add     x9, sp, #VSLOT(16)
    add     x10, sp, #VSLOT(11)
    ldr     x11, [x10, #0]
    ldr     x12, [x10, #8]
    ldr     x13, [x10, #16]
    ldr     x14, [x10, #24]
    str     x11, [x9, #0]
    str     x12, [x9, #8]
    str     x13, [x9, #16]
    str     x14, [x9, #24]
    ldr     x11, [x10, #32]
    ldr     x12, [x10, #40]
    ldr     x13, [x10, #48]
    ldr     x14, [x10, #56]
    str     x11, [x9, #32]
    str     x12, [x9, #40]
    str     x13, [x9, #48]
    str     x14, [x9, #56]
    mov     x11, #1
    str     x11, [x9, #64]
    str     xzr, [x9, #72]
    str     xzr, [x9, #80]
    str     xzr, [x9, #88]

    // jacsum = jac1 + jac2
    add     x0, sp, #VSLOT(19)
    add     x1, sp, #VSLOT(13)
    add     x2, sp, #VSLOT(16)
    bl      p256_point_add

    // reject if the combination is infinity
    ldr     x9, [sp, #VSLOT(21) + 0]
    ldr     x10, [sp, #VSLOT(21) + 8]
    orr     x9, x9, x10
    ldr     x10, [sp, #VSLOT(21) + 16]
    orr     x9, x9, x10
    ldr     x10, [sp, #VSLOT(21) + 24]
    orr     x9, x9, x10
    cbz     x9, .Lverify_reject

    // v = vx mod n; accept iff v == r
    add     x0, sp, #VSLOT(22)
    add     x1, sp, #VSLOT(23)
    add     x2, sp, #VSLOT(19)
    bl      p256_point_to_affine
    add     x0, sp, #VSLOT(24)
    add     x1, sp, #VSLOT(22)
    bl      p256_scalar_reduce
    add     x0, sp, #VSLOT(24)
    add     x1, sp, #VSLOT(1)
    bl      p256_fe_eq

    b       .Lverify_done

.Lverify_in_range:
    // x1 -> a 4-limb scalar; returns x0 = 1 if 1 <= *x1 < n
    ldr     x2, [x1, #0]
    ldr     x3, [x1, #8]
    ldr     x4, [x1, #16]
    ldr     x5, [x1, #24]
    orr     x6, x2, x3
    orr     x6, x6, x4
    orr     x6, x6, x5
    cmp     x6, #0
    b.eq    .Lverify_in_range_no
    adr_l   x9, p256_n
    ldr     x6, [x9, #0]
    ldr     x7, [x9, #8]
    ldr     x10, [x9, #16]
    ldr     x11, [x9, #24]
    subs    x6, x2, x6
    sbcs    x7, x3, x7
    sbcs    x10, x4, x10
    sbcs    x11, x5, x11
    cset    x0, cc                  // 1 if borrowed, i.e. value < n
    ret
.Lverify_in_range_no:
    mov     x0, #0
    ret

.Lverify_reject:
    mov     x0, #0
    b       .Lverify_return

.Lverify_done:
    // x0 already holds the fe_eq result (0/1)

.Lverify_return:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #992
    ret

#undef VSLOT
