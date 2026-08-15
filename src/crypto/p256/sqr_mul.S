// Field squaring and multiplication mod p

#include "../../defs.S"

.extern p256_bn_mul

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_reduce (file-local)
//
// Description: Barrett reduction of a 512-bit product (8 limbs) mod p,
//   producing a canonical 4-limb result. See the file header for the
//   algorithm: q1 = T >> 192 (a pointer offset, 5 limbs), q2 = q1*mu
//   (10 limbs), q3 = q2 >> 320 (a pointer offset, 5 limbs), q3p = q3*p
//   (9 limbs), r = T - q3p computed over 9 limbs (T zero-extended).
//   r is already < p for every input this was tested against; a
//   branchless defensive +p (in case the borrow flag says otherwise)
//   plus two branchless conditional -p rounds guarantee a canonical
//   result regardless.
//
// Input/Arguments:
//   x0 — out pointer (4 limbs)
//   x1 — T pointer (8 limbs, the product to reduce)
//
// Output/Returns:
//   out[0..3] = T mod p, canonical (< p)
//
// Clobbered Registers:
//   x0-x17 (plus x19, x20 saved/restored on the stack)
//
// Stack Usage:
//   192 bytes: saved x29/x30, saved x19/x20, a 10-limb q2 buffer, and a
//   9-limb q3p buffer
// ─────────────────────────────────────────────────────────────────────
.align 2
p256_reduce:
    sub     sp, sp, #192
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    // sp+32 .. sp+111  : q2[10]
    // sp+112 .. sp+183 : q3p[9]

    mov     x19, x0                 // out
    mov     x20, x1                 // T

    // q2 = q1 * mu, where q1 = T >> 192 (== T+24, 5 limbs)
    add     x0, sp, #32
    add     x1, x20, #24
    mov     x2, #5
    adr_l   x3, p256_mu
    mov     x4, #5
    bl      p256_bn_mul

    // q3p = q3 * p, where q3 = q2 >> 320 (== q2+40, 5 limbs)
    add     x0, sp, #112
    add     x1, sp, #32 + 40
    mov     x2, #5
    adr_l   x3, p256_p
    mov     x4, #4
    bl      p256_bn_mul

    // r = T (zero-extended to 9 limbs) - q3p (9 limbs)
    ldr     x2, [x20, #0]
    ldr     x3, [x20, #8]
    ldr     x4, [x20, #16]
    ldr     x5, [x20, #24]
    ldr     x6, [x20, #32]
    ldr     x7, [x20, #40]
    ldr     x8, [x20, #48]
    ldr     x9, [x20, #56]
    // x10 = T's synthetic 9th limb = 0

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
    subs    x10, xzr, x14           // synthetic T limb (0) - q3p[8]
    cset    x16, cc                 // x16 = 1 if the subtract borrowed
    // x2..x6 now hold r's low 5 limbs (320 bits). r itself is only
    // guaranteed to fit in ~257 bits (p is close enough to 2^256 that
    // a single +/-p correction can cross the 256-bit boundary), so the
    // correction rounds below carry that 5th limb (x6) through instead
    // of truncating to 4 limbs before correcting — truncating first
    // and correcting after silently drops the 257th bit and produces a
    // wrong result on exactly the inputs that need a real correction.

    // Defensive: if it borrowed (r "went negative"), add p back once.
    adr_l   x11, p256_p
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

    // Two branchless conditional-subtract-p rounds (against p
    // zero-extended to 5 limbs) to guarantee a canonical (< p) result.
    .irp round, 1, 2
    adr_l   x11, p256_p
    ldr     x12, [x11, #0]
    ldr     x13, [x11, #8]
    ldr     x14, [x11, #16]
    ldr     x15, [x11, #24]
    subs    x12, x2, x12
    sbcs    x13, x3, x13
    sbcs    x14, x4, x14
    sbcs    x15, x5, x15
    sbcs    x17, x6, xzr
    cset    x16, cs                 // 1 if r >= p (no borrow)
    cmp     x16, #1
    csel    x2, x12, x2, eq
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x15, x5, eq
    csel    x6, x17, x6, eq
    .endr
    // x6 is guaranteed 0 here (r is now canonical, < p < 2^256).

    str     x2, [x19, #0]
    str     x3, [x19, #8]
    str     x4, [x19, #16]
    str     x5, [x19, #24]

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #192
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_sqr
//
// Description: out = a^2 mod p. Thin trampoline into p256_fe_mul(out,
//   a, a) — see p256_fe_mul below.
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_sqr
p256_fe_sqr:
    mov     x2, x1

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_mul
//
// Description: out = (a * b) mod p — a 4x4-limb schoolbook multiply
//   (p256_bn_mul) producing an 8-limb product, followed by Barrett
//   reduction (p256_reduce). See the file header for the algorithm.
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer, x2 — b fe pointer
//   (out may alias a and/or b — the product is fully computed into a
//   stack scratch buffer before anything is written to out)
//
// Clobbered Registers:
//   x0-x17, x19-x20 (saved/restored)
//
// Stack Usage:
//   96 bytes: saved x29/x30, saved x19/x20, an 8-limb product buffer
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_mul
p256_fe_mul:
    sub     sp, sp, #96
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    // sp+32 .. sp+95: T[8], the 512-bit product

    mov     x19, x0                 // out
    mov     x20, x2                 // b

    add     x0, sp, #32
    // x1 already holds a
    mov     x2, #4
    mov     x3, x20
    mov     x4, #4
    bl      p256_bn_mul

    mov     x0, x19
    add     x1, sp, #32
    bl      p256_reduce

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #96
    ret
