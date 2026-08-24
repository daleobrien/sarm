// P-256 Montgomery multiplication mod n

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_mont_mul
//
// Description: out = a * b * R^-1 mod n, R = 2^256 — Montgomery
//   multiplication in the P-256 scalar ring. This exists for
//   p256_scalar_inv, which spends 300 modular multiplications on
//   a^(n-2) and is the most expensive single thing an ECDSA signature
//   does; p256_scalar_mul keeps the plain-domain contract and its
//   Barrett reduction, and is unchanged.
//
//   Algorithm — separated operand scanning:
//
//     1. T = a*b, a full 4x4 schoolbook product into eight limbs. Each
//        row adds a*b[i] at offset i using two carry chains: the low
//        halves into T[i..i+3], then the high halves into T[i+1..i+4].
//        T[i+4] is untouched before row i (the partial product
//        a * (b mod 2^(64i)) is < 2^(256+64i)), so the first chain may
//        write it rather than accumulate into it, and the second chain
//        provably cannot carry past it: T[i..i+3] < 2^256 and
//        a*b[i] <= (2^256-1)(2^64-1), so their sum is < 2^320.
//
//     2. Four Montgomery rounds. Round i picks m = T[i] * n0inv so
//        that T[i] + m*n[0] == 0 mod 2^64, adds m*n at offset i, and
//        propagates the one word that lands at T[i+4] up through T[7]
//        and into a 9th word `ext`. After four rounds T is divisible
//        by R and T/R is T[4..7] with ext on top.
//
//     3. T/R < 2n (T < n^2 + R*n < 2*R*n), so exactly one conditional
//        subtraction of n canonicalizes it, decided by the borrow out
//        of ext.
//
//   Every bound above is a proof obligation rather than an
//   assumption, and each is asserted on every call of the word-level
//   Python model in scripts/p256_scalar_inv_derivation.py (`prove`) —
//   including that each round really does zero its own limb and that
//   ext never exceeds 1.
//
//   20 limb products reduce here, against Barrett's 45 (a 5x5 and a
//   5x4 p256_bn_mul), and nothing is called, so three function calls
//   and p256_bn_mul's generic index-driven loop go away as well. The
//   measured result is 11.6 ns against p256_scalar_mul's 107 ns.
//
// Constant time: straight-line, no branches, no data-dependent
//   addressing. The conditional subtraction is CSEL, not a branch.
//
// Input/Arguments:
//   x0 — out (4 limbs), may alias a and/or b
//   x1 — a (4 limbs), x2 — b (4 limbs); both must be < n
//
// Output/Returns:
//   out[0..3] = a*b*R^-1 mod n, canonical (< n)
//
// Clobbered Registers:
//   x1-x17 (x0 holds the out pointer throughout and is written only by
//   the final stores; x19-x24 are saved and restored)
//
// Stack Usage:
//   48 bytes: three saved callee-saved pairs (x19-x24). Leaf function —
//   nothing is called, so x29/x30 are not saved, and there is no
//   scratch area: the eight product limbs stay in registers.
//
//   regpressure.py reports peak live at 21 GPRs — eight product limbs,
//   four modulus limbs, four scratch, n0inv, m, a carry word, ext and
//   the out pointer — against the 18 caller-saved registers available,
//   so some callee-saved use is unavoidable here and its "never held
//   across a call" flag is a leaf-function blind spot rather than
//   slack. Six rather than the bare minimum: freeing the last three
//   would mean reloading the modulus limbs inside every round.
//
//   Holding eight scratch registers instead of four (all eight
//   mul/umulh results live at once, rather than the four low halves
//   and then the four high halves) was measured on the real chain and
//   made no difference — 5485/5493/5720 ns against 5293/5518/5500 —
//   so this keeps the cheaper frame.
// ─────────────────────────────────────────────────────────────────────

// Row i of the schoolbook product: T[i..i+4] += a * \b, where a is in
// x4-x7. \t4 is written, not accumulated. Scratch: x21-x24.
.macro P256_SMM_PRODROW b, t0, t1, t2, t3, t4
    mul     x21, x4, \b
    mul     x22, x5, \b
    mul     x23, x6, \b
    mul     x24, x7, \b
    adds    \t0, \t0, x21
    adcs    \t1, \t1, x22
    adcs    \t2, \t2, x23
    adcs    \t3, \t3, x24
    adc     \t4, xzr, xzr
    umulh   x21, x4, \b
    umulh   x22, x5, \b
    umulh   x23, x6, \b
    umulh   x24, x7, \b
    adds    \t1, \t1, x21
    adcs    \t2, \t2, x22
    adcs    \t3, \t3, x23
    adc     \t4, \t4, x24
.endm

// Montgomery round i: T[i..i+3] += m*n, leaving \t0 == 0 and the
// two-word carry (x2:x1) still to be deposited at T[i+4] — the only
// part that differs between rounds, since how far it has to propagate
// shrinks as i grows. n is in x8-x11 and n0inv in x4. Scratch: x5,
// x21-x24.
.macro P256_SMM_REDROUND t0, t1, t2, t3
    mul     x5,  \t0, x4            // m = T[i] * n0inv mod 2^64
    mul     x21, x5, x8
    mul     x22, x5, x9
    mul     x23, x5, x10
    mul     x24, x5, x11
    adds    \t0, \t0, x21           // == 0 by the choice of m
    adcs    \t1, \t1, x22
    adcs    \t2, \t2, x23
    adcs    \t3, \t3, x24
    adc     x1, xzr, xzr
    umulh   x21, x5, x8
    umulh   x22, x5, x9
    umulh   x23, x5, x10
    umulh   x24, x5, x11
    adds    \t1, \t1, x21
    adcs    \t2, \t2, x22
    adcs    \t3, \t3, x23
    adcs    x1, x1, x24
    adc     x2, xzr, xzr
.endm

.align 2
FUNC p256_scalar_mont_mul
    sub     sp, sp, #48
    stp     x19, x20, [sp, #0]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]

    // Both operands reach registers before anything is stored, which is
    // what lets out alias either of them.
    ldp     x4, x5, [x1, #0]        // a0, a1
    ldp     x6, x7, [x1, #16]       // a2, a3
    ldp     x8, x9, [x2, #0]        // b0, b1
    ldp     x10, x11, [x2, #16]     // b2, b3

    // ── phase 1: T (x12-x17, x19, x20) = a * b ──
    // Row 0 has nothing to accumulate into, so it writes T directly:
    // a*b0 = lo0 + (hi0+lo1)*2^64 + (hi1+lo2)*2^128 + (hi2+lo3)*2^192
    //        + hi3*2^256, and hi3 <= 2^64-2 so the final adc cannot
    //        overflow.
    mul     x12, x4, x8
    umulh   x13, x4, x8
    mul     x21, x5, x8
    umulh   x14, x5, x8
    mul     x22, x6, x8
    umulh   x15, x6, x8
    mul     x23, x7, x8
    umulh   x16, x7, x8
    adds    x13, x13, x21
    adcs    x14, x14, x22
    adcs    x15, x15, x23
    adc     x16, x16, xzr
    mov     x17, xzr
    mov     x19, xzr
    mov     x20, xzr

    P256_SMM_PRODROW x9,  x13, x14, x15, x16, x17
    P256_SMM_PRODROW x10, x14, x15, x16, x17, x19
    P256_SMM_PRODROW x11, x15, x16, x17, x19, x20

    // ── phase 2: Montgomery reduction ──
    // b is dead, so x8-x11 take n; a is dead, so x4 takes n0inv.
    adr_l   x3, p256_n
    ldp     x8, x9, [x3, #0]
    ldp     x10, x11, [x3, #16]
    adr_l   x3, p256_scalar_n0inv
    ldr     x4, [x3]
    mov     x3, xzr                 // ext, the 9th word

    P256_SMM_REDROUND x12, x13, x14, x15
    adds    x16, x16, x1
    adcs    x17, x17, x2
    adcs    x19, x19, xzr
    adcs    x20, x20, xzr
    adc     x3, x3, xzr

    P256_SMM_REDROUND x13, x14, x15, x16
    adds    x17, x17, x1
    adcs    x19, x19, x2
    adcs    x20, x20, xzr
    adc     x3, x3, xzr

    P256_SMM_REDROUND x14, x15, x16, x17
    adds    x19, x19, x1
    adcs    x20, x20, x2
    adc     x3, x3, xzr

    P256_SMM_REDROUND x15, x16, x17, x19
    adds    x20, x20, x1
    adc     x3, x3, x2

    // ── phase 3: the single conditional subtraction ──
    // The result is x16:x17:x19:x20 with x3 as a 5th word, and is < 2n,
    // so one subtraction of n is enough. CS (no borrow out of the 5th
    // word) means the result was >= n and the subtracted value is the
    // canonical one.
    subs    x21, x16, x8
    sbcs    x22, x17, x9
    sbcs    x23, x19, x10
    sbcs    x24, x20, x11
    sbcs    x5,  x3, xzr            // x5 held m and is dead; only NZCV matters
    csel    x16, x21, x16, cs
    csel    x17, x22, x17, cs
    csel    x19, x23, x19, cs
    csel    x20, x24, x20, cs

    stp     x16, x17, [x0, #0]
    stp     x19, x20, [x0, #16]

    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp, #0]
    add     sp, sp, #48
    ret
ENDFUNC p256_scalar_mont_mul
