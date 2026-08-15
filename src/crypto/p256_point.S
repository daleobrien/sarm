// ====================================================================
// ARM64 (AArch64) P-256 point arithmetic for ymawky
// (PLAN.MD Phase 16.2/16.3/16.4)
// File: p256_point.S
//
//   p256_point_dbl       — Jacobian point doubling (PLAN.MD 16.3)
//   p256_point_add       — Jacobian point addition, handles doubling
//                           and infinity inputs too (PLAN.MD 16.2)
//   p256_point_to_affine — Jacobian -> affine conversion
//   p256_point_mul       — constant-time scalar multiplication
//                           (PLAN.MD 16.4)
//
// ── Point representation ────────────────────────────────────────────
// A Jacobian point is 96 bytes: X (32B, offset 0), Y (32B, offset 32),
// Z (32B, offset 64), each a p256.S-style 4-limb field element.
// (X:Y:Z) represents the affine point (X/Z^2, Y/Z^3); Z=0 represents
// the point at infinity.
//
// ── Doubling is unconditional ───────────────────────────────────────
// p256_point_dbl uses the standard a=-3 Jacobian doubling formula
// (delta/gamma/beta/alpha, "dbl-2001-b") with NO special-casing for
// Z1=0 or Y1=0. That's deliberate, not an oversight: every term in
// that formula is a polynomial in Z1 with no constant term, so Z1=0
// forces Z3=0 through the arithmetic alone (Z3 = (Y1+Z1)^2-gamma-delta
// = Y1^2-Y1^2-0 = 0 when Z1=0) — infinity in stays infinity out, for
// any X1/Y1 "garbage" in an infinity-representing input. This was
// checked against a Python prototype before porting: see the
// commit that introduced this file. (P-256's group order is prime and
// odd, so Y1=0 for a genuine on-curve point can't happen either — but
// the formula handles it regardless, for free.)
//
// ── Addition needs help ─────────────────────────────────────────────
// The generic Jacobian addition formula ("add-2007-bl") is NOT
// complete: if either input is infinity (Z=0), U1/U2/S1/S2 all
// collapse to 0, so it produces infinity instead of the other operand
// — wrong. And if the two points coincide (or are negatives of each
// other), the generic formula divides through by an effective zero
// and produces garbage. p256_point_add handles all of this with
// branchless CSEL correction on top of the generic formula:
//   1. base   = add_generic(P1, P2)
//   2. if U1==U2 && S1==S2 (P1==P2): result = dbl(P1)
//   3. if U1==U2 && S1!=S2 (P1==-P2): result = infinity
//   4. if Z2==0: result = P1
//   5. if Z1==0: result = P2        (checked/applied last, so it
//                                     wins even over steps 2-3, which
//                                     both produce a "doubling" or
//                                     "negation" answer when Z1=0 --
//                                     since Z1=0 forces U1=U2=S1=S2=0
//                                     as well, which is the *wrong*
//                                     answer for "P1 is infinity")
// This is deliberately not the fastest possible complete formula
// (e.g. Renes-Costello-Batina) — it's three ordinary formulas
// (generic add, double, infinity) combined with CSEL, which is easier
// to derive correctly by hand and to cross-check against a plain
// Python reference. See the commit that introduced this file for that
// Python prototype and its cross-checks against a real ECC library.
//
// ── Scalar multiplication needs no padding trick ────────────────────
// Because p256_point_dbl is unconditionally correct on an infinity
// input, and p256_point_add's Z1==0 case returns the other operand,
// the ladder can simply start its accumulator at infinity (a
// zeroed 96-byte buffer) and always double-then-conditionally-add for
// a fixed 256 iterations — no scalar padding/blinding needed to dodge
// "add to infinity" as a special first iteration. All 256 iterations
// run through the exact same double + add-or-double + CSEL-select
// sequence, and the CSEL select on the scalar bit (p256_fe_cmov,
// backed by CSEL not a branch) keeps the whole ladder free of
// scalar-dependent branches.
//
// Exported Symbols:
//   p256_point_dbl       — doc block below
//   p256_point_add       — doc block below
//   p256_point_to_affine — doc block below
//   p256_point_mul       — doc block below
//
// ====================================================================

#include "../defs.S"

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
.global p256_point_dbl
p256_point_dbl:
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
.global p256_point_add
p256_point_add:
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
.global p256_point_to_affine
p256_point_to_affine:
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
.global p256_point_mul
p256_point_mul:
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
