// Field inversion mod p via Fermat

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_inv
//
// Description: out = a^-1 mod p, via Fermat's little theorem
//   (a^(p-2) mod p) and square-and-multiply against p256_p_minus_2.
//   The exponent is a public curve parameter, not secret data, so
//   branching on its bits (unlike branching on a or the result) is
//   not a timing side channel — this is the same reasoning x25519.S
//   uses for its own recip.
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer
//
// Clobbered Registers:
//   x0-x17, x19-x22 (saved/restored)
//
// Stack Usage:
//   80 bytes: saved x29/x30, saved x19/x20, saved x21/x22, a 4-limb
//   accumulator
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_inv
p256_fe_inv:
    sub     sp, sp, #80
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    // sp+48 .. sp+79: result[4]

    mov     x19, x0                 // out
    mov     x20, x1                 // a

    mov     x9, #1
    str     x9, [sp, #48]
    str     xzr, [sp, #56]
    str     xzr, [sp, #64]
    str     xzr, [sp, #72]

    mov     x22, #255               // i = 255 .. 0
.Lfe_inv_loop:
    lsr     x9, x22, #6              // limb = i / 64
    and     x10, x22, #63            // shift = i % 64
    adr_l   x11, p256_p_minus_2
    ldr     x12, [x11, x9, lsl #3]
    lsr     x12, x12, x10
    and     x21, x12, #1             // x21 = bit i of (p-2)

    add     x0, sp, #48
    add     x1, sp, #48
    bl      p256_fe_sqr

    cmp     x21, #0
    b.eq    .Lfe_inv_skip_mul
    add     x0, sp, #48
    add     x1, sp, #48
    mov     x2, x20
    bl      p256_fe_mul
.Lfe_inv_skip_mul:
    subs    x22, x22, #1
    b.ge    .Lfe_inv_loop

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
