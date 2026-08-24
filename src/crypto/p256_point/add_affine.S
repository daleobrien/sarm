// P-256 mixed (Jacobian + affine) point addition

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_add_affine
//
// Description: out = P1 + (ax, ay), where P1 is a Jacobian point and
//   (ax, ay) is an affine one. This is p256_point_add with Z2 = 1
//   substituted throughout: Z2Z2 and Z2cubed collapse to 1, so
//   U1 = X1, S1 = Y1, and Z3 = H*Z1 rather than H*Z1*Z2.
//
//   Algorithm (8 multiplies + 3 squarings, against the generic
//   addition's ~26 field multiplies — the generic one pays for a full
//   p256_point_dbl and twelve p256_fe_cmov calls to handle the
//   coincident/negated/infinity cases this function's preconditions
//   rule out):
//
//     Z1Z1 = Z1^2            U2 = ax*Z1Z1       Z1cubed = Z1*Z1Z1
//     S2   = ay*Z1cubed      H  = U2 - X1       r       = S2 - Y1
//     HH   = H^2             HHH = H*HH         V       = X1*HH
//     X3   = r^2 - HHH - 2V
//     Y3   = r*(V - X3) - Y1*HHH
//     Z3   = H*Z1
//
// PRECONDITIONS — this function does NOT check them, and silently
//   returns a wrong point if they are violated. It is deliberately not
//   a general-purpose addition; p256_point_add is:
//
//   1. (ax, ay) is a finite curve point — never the point at infinity.
//   2. P1 != +-(ax, ay). Equivalently H != 0. If the two points share
//      an x-coordinate this formula produces H = 0 and hence Z3 = 0
//      (i.e. "infinity"), which is right only for P1 == -(ax,ay) and
//      wrong for P1 == +(ax,ay), where the answer is the doubling.
//   3. P1 may be infinity (Z1 = 0), and then the output is also
//      Z3 = 0 with meaningless X3/Y3 — the caller must substitute the
//      real answer. p256_point_mul_base does exactly that, with a
//      p256_fe_cmov on a flag derived from Z1, not a branch.
//
//   p256_point_mul_base is the only caller and it satisfies (1) and
//   (2) structurally, for every 256-bit scalar; see the proof in
//   scripts/p256_comb_derivation.py (`prove`), which also asserts
//   H != 0 on every contributing addition over adversarial scalars.
//
// Constant time: straight-line, no branches at all, no data-dependent
//   addressing. Every callee (p256_fe_mul/sqr/sub/add) is itself
//   branchless.
//
// Input/Arguments:
//   x0 — out (96-byte Jacobian point), may alias P1
//   x1 — P1 (96-byte Jacobian point)
//   x2 — aff (64 bytes: x at +0, y at +32), the layout
//        p256_comb_table stores
//
// Clobbered Registers:
//   x0-x17 (callee-saved x19-x21 are saved and restored)
//
// Stack Usage:
//   496 bytes: saved x29/x30 (16) + saved x19-x21 and 8 bytes of pad
//   (32) + 14 4-limb scratch slots (448). The result is assembled in
//   slots 11..13 and copied out at the very end, so out may alias P1.
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_point_add_affine
    sub     sp, sp, #496
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    str     x21, [sp, #32]
    // scratch slots start at sp+48, 32 bytes each:
    //  0 Z1Z1  1 U2  2 Z1cubed  3 S2  4 H  5 r  6 HH  7 HHH  8 V
    //  9 t (rr, then rr-HHH, then V-X3)  10 twoV, then r*(V-X3)
    // 11..13 result (X,Y,Z contiguous)

    mov     x19, x0                 // out
    mov     x20, x1                 // P1
    mov     x21, x2                 // aff

#define MSLOT(i) (48 + 32*(i))

    // Z1Z1 = Z1^2
    add     x0, sp, #MSLOT(0)
    add     x1, x20, #64
    bl      p256_fe_sqr

    // U2 = ax*Z1Z1, Z1cubed = Z1*Z1Z1, S2 = ay*Z1cubed
    add     x0, sp, #MSLOT(1)
    add     x1, x21, #0
    add     x2, sp, #MSLOT(0)
    bl      p256_fe_mul
    add     x0, sp, #MSLOT(2)
    add     x1, x20, #64
    add     x2, sp, #MSLOT(0)
    bl      p256_fe_mul
    add     x0, sp, #MSLOT(3)
    add     x1, x21, #32
    add     x2, sp, #MSLOT(2)
    bl      p256_fe_mul

    // H = U2 - X1, r = S2 - Y1  (U1 == X1 and S1 == Y1 because Z2 == 1)
    add     x0, sp, #MSLOT(4)
    add     x1, sp, #MSLOT(1)
    add     x2, x20, #0
    bl      p256_fe_sub
    add     x0, sp, #MSLOT(5)
    add     x1, sp, #MSLOT(3)
    add     x2, x20, #32
    bl      p256_fe_sub

    // HH = H^2, HHH = H*HH, V = X1*HH
    add     x0, sp, #MSLOT(6)
    add     x1, sp, #MSLOT(4)
    bl      p256_fe_sqr
    add     x0, sp, #MSLOT(7)
    add     x1, sp, #MSLOT(4)
    add     x2, sp, #MSLOT(6)
    bl      p256_fe_mul
    add     x0, sp, #MSLOT(8)
    add     x1, x20, #0
    add     x2, sp, #MSLOT(6)
    bl      p256_fe_mul

    // t = r^2 - HHH, twoV = V+V, X3 = t - twoV
    add     x0, sp, #MSLOT(9)
    add     x1, sp, #MSLOT(5)
    bl      p256_fe_sqr
    add     x0, sp, #MSLOT(9)
    add     x1, sp, #MSLOT(9)
    add     x2, sp, #MSLOT(7)
    bl      p256_fe_sub             // p256_fe_sub documents out may alias a
    add     x0, sp, #MSLOT(10)
    add     x1, sp, #MSLOT(8)
    add     x2, sp, #MSLOT(8)
    bl      p256_fe_add
    add     x0, sp, #MSLOT(11)
    add     x1, sp, #MSLOT(9)
    add     x2, sp, #MSLOT(10)
    bl      p256_fe_sub

    // Y3 = r*(V - X3) - Y1*HHH  (slot 9's rr and slot 10's twoV are
    // both dead once X3 exists, so they are reused here; slot 0's Z1Z1
    // died with Z1cubed)
    add     x0, sp, #MSLOT(9)
    add     x1, sp, #MSLOT(8)
    add     x2, sp, #MSLOT(11)
    bl      p256_fe_sub
    add     x0, sp, #MSLOT(10)
    add     x1, sp, #MSLOT(5)
    add     x2, sp, #MSLOT(9)
    bl      p256_fe_mul
    add     x0, sp, #MSLOT(0)
    add     x1, x20, #32
    add     x2, sp, #MSLOT(7)
    bl      p256_fe_mul
    add     x0, sp, #MSLOT(12)
    add     x1, sp, #MSLOT(10)
    add     x2, sp, #MSLOT(0)
    bl      p256_fe_sub

    // Z3 = H*Z1
    add     x0, sp, #MSLOT(13)
    add     x1, sp, #MSLOT(4)
    add     x2, x20, #64
    bl      p256_fe_mul

    // out = result (single copy at the end, so out may alias P1)
    add     x9, sp, #MSLOT(11)
    mov     x10, #0
.Lmadd_copy:
    cmp     x10, #96
    b.ge    .Lmadd_copy_done
    ldr     x11, [x9, x10]
    str     x11, [x19, x10]
    add     x10, x10, #8
    b       .Lmadd_copy
.Lmadd_copy_done:

    ldr     x21, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #496
    ret

#undef MSLOT
ENDFUNC p256_point_add_affine
