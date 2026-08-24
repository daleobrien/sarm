// ====================================================================
// ARM64 (AArch64) X25519 Implementation for sarm
// File: x25519.S
//
//   x25519_fe_frombytes   — decode 32 little-endian bytes to a field
//                           element ("expand")
//   x25519_fe_tobytes     — encode a field element to 32 bytes,
//                           canonical mod p ("contract")
//   x25519_fe_add         — field addition
//   x25519_fe_sub         — field subtraction
//   x25519_fe_mul         — field multiplication
//   x25519_fe_sqr         — field squaring
//   x25519_fe_sqr_times   — repeated field squaring
//   x25519_fe_scalar_product — field element times a small scalar
//   x25519_fe_recip       — inversion, z^(p-2)
//   x25519_swap_conditional — constant-time conditional swap
//   x25519                — X25519 scalar multiplication
//
// ── Field representation ──────────────────────────────────────────────
// An "fe" is 5 x 64-bit limbs of 51 bits each, little-endian limb order
// (limb 0 is the least significant 51 bits), stored in a 40-byte buffer:
//
//     value = sum_i limb[i] * 2^(51*i)   mod p = 2^255 - 19
//
// This is the classic 5x51 "radix 2^51" representation. The arithmetic
// follows the public-domain curve25519-donna implementation by Andrew
// Moon (floodyberry): additions/subtractions are carry-free (limbs may
// grow to ~2^52, or ~2^55 for sub which adds a multiple of p to stay
// non-negative), while multiplication/squaring accumulate the 25
// products in 128-bit registers, fold the 2^255 == 19 relation into the
// low limbs, and run a single carry chain. Every function reads ALL of
// its input limbs before writing anything to the output, so `out` may
// alias `a` and/or `b` (the Montgomery ladder relies on in-place
// semantics like sub(nqz, nqx, nqz)).
//
// Scalar multiplication is the RFC 7748 §5 Montgomery
// ladder with the constant-time conditional-swap trick, using a24 =
// (486662 - 2) / 4 = 121665 and the bit-254 pre-swap optimisation from
// curve25519-donna. The ladder runs a fixed sequence of field
// operations (no branches on secret data), and the cswap is branch-free.
//
// All scratch state lives on the stack: the functions are re-entrant and
// use no mutable globals. Read-only constants are materialised as
// immediates.
//
// Exported Symbols:
//   x25519                  — one-shot X25519 (doc block below)
//   x25519_fe_frombytes     — expand (doc block below)
//   x25519_fe_tobytes       — contract (doc block below)
//   x25519_fe_add           — a + b mod p (doc block below)
//   x25519_fe_sub           — a - b mod p (doc block below)
//   x25519_fe_mul           — a * b mod p (doc block below)
//   x25519_fe_sqr           — a^2 mod p (doc block below)
//   x25519_fe_sqr_times     — a^(2^count) mod p (doc block below)
//   x25519_fe_scalar_product— a * scalar mod p (doc block below)
//   x25519_fe_recip         — a^(p-2) mod p (doc block below)
//   x25519_swap_conditional — constant-time conditional swap (below)
//
// ====================================================================

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Macro: carry51
//
// Description: One 51-bit carry pass over a 64-bit 5-limb value held in
//   registers. For each limb: shift the carry out of limb i, add it to
//   limb i+1, and mask limb i to 51 bits. The final limb is left
//   unmasked (the caller decides what to do with it).
//
// Input/Arguments:
//   \t0..\t4 — X registers holding the 5 limbs
//   \m       — X register holding the 51-bit mask 0x7FFFFFFFFFFFF
//   \s       — X scratch register
//
// Clobbered Registers:
//   \s
// ─────────────────────────────────────────────────────────────────────
.macro carry51 t0, t1, t2, t3, t4, m, s
    lsr     \s, \t0, #51
    add     \t1, \t1, \s
    and     \t0, \t0, \m
    lsr     \s, \t1, #51
    add     \t2, \t2, \s
    and     \t1, \t1, \m
    lsr     \s, \t2, #51
    add     \t3, \t3, \s
    and     \t2, \t2, \m
    lsr     \s, \t3, #51
    add     \t4, \t4, \s
    and     \t3, \t3, \m
.endm

// ─────────────────────────────────────────────────────────────────────
// Macro: carry51_full
//
// Description: carry51 plus the 2^255 == 19 fold: the carry out of the
//   top limb is multiplied by 19 and added back into limb 0, then the
//   top limb is masked.
//
// Input/Arguments:
//   \t0..\t4 — X registers holding the 5 limbs
//   \m       — X register holding the 51-bit mask
//   \s, \s2  — X scratch registers
//   \nineteen— X register holding 19
//
// Clobbered Registers:
//   \s, \s2
// ─────────────────────────────────────────────────────────────────────
.macro carry51_full t0, t1, t2, t3, t4, m, s, s2, nineteen
    carry51 \t0, \t1, \t2, \t3, \t4, \m, \s
    lsr     \s2, \t4, #51
    mul     \s2, \s2, \nineteen
    add     \t0, \t0, \s2
    and     \t4, \t4, \m
.endm

// ─────────────────────────────────────────────────────────────────────
// Macro: carry51_final
//
// Description: carry51 followed by masking the final limb (used by
//   x25519_fe_tobytes to canonicalise the 2^255-offset trick).
//
// Input/Arguments:
//   \t0..\t4 — X registers holding the 5 limbs
//   \m       — X register holding the 51-bit mask
//   \s       — X scratch register
//
// Clobbered Registers:
//   \s
// ─────────────────────────────────────────────────────────────────────
.macro carry51_final t0, t1, t2, t3, t4, m, s
    carry51 \t0, \t1, \t2, \t3, \t4, \m, \s
    and     \t4, \t4, \m
.endm

// ─────────────────────────────────────────────────────────────────────
// Macro: x25519_m51
//
// Description: Materialise the 51-bit limb mask 0x7FFFFFFFFFFFF
//   (2^51 - 1) into \reg. movz/movk can only write 16 bits at a time,
//   so this needs four instructions: bits 0-47 are all ones and bits
//   48-51 are 0x7.
//
// Input/Arguments:
//   \reg — X register to receive the mask
//
// Clobbered Registers:
//   \reg
// ─────────────────────────────────────────────────────────────────────
.macro x25519_m51 reg
    movz    \reg, #0xFFFF               // 51-bit mask 0x7FFFFFFFFFFFF
    movk    \reg, #0xFFFF, lsl #16
    movk    \reg, #0xFFFF, lsl #32
    movk    \reg, #0x7, lsl #48
.endm

// ─────────────────────────────────────────────────────────────────────
// Macro: carry128_out
//
// Description: Propagate one carry step out of a 128-bit accumulator
//   pair: c = t >> 51 (the 128-bit shift), mask the low limb, and add
//   the carry into the next accumulator pair. t is guaranteed < 2^113
//   for the inputs used here, so the carry always fits in one register.
//
// Input/Arguments:
//   \lo, \hi — X registers: the 128-bit accumulator being reduced
//   \nlo, \nhi — X registers: the next accumulator pair (c is added)
//   \m       — X register holding the 51-bit mask
//   \s1, \s2 — X scratch registers (shift results)
//   \s3      — X scratch register (carry)
//
// Clobbered Registers:
//   \s1, \s2, \s3, NZCV
// ─────────────────────────────────────────────────────────────────────
.macro carry128_out lo, hi, nlo, nhi, m, s1, s2, s3
    lsr     \s1, \lo, #51
    lsl     \s2, \hi, #13
    orr     \s3, \s1, \s2
    and     \lo, \lo, \m
    adds    \nlo, \nlo, \s3
    adcs    \nhi, \nhi, xzr
.endm

.text

FUNC x25519_fe_sqr_times
    // count == 0 — a^(2^0) = a (Step 5, docs/SECURITY.md §3.5).
    // The squaring loop is a do-while (subs/b.ne), so a zero count would
    // fall in and run 2^64 times: a hang, not a wrong answer. Every call
    // site in the tree passes a compile-time constant >= 1, so this is a
    // precondition made explicit, not a bug being fixed — but a
    // precondition whose violation never returns is one worth spending
    // three instructions on.
    cbz     x2, .Lx25519_sqr_zero
    sub     sp, sp, #32
    str     x0, [sp]                   // save out pointer
    str     x2, [sp, #8]               // save count
    str     x19, [sp, #16]             // save callee-saved x19 (M51 mask)
    ldp     x3, x4, [x1]               // r0, r1
    ldp     x5, x6, [x1, #16]          // r2, r3
    ldr     x7, [x1, #32]              // r4
    mov     x2, #19
    x25519_m51 x19

.Lx25519_sqr_loop:
    // t[0] = r0*r0 + d4*r1 + d2*r3
    mul     x0, x3, x3
    umulh   x1, x3, x3
    mov     x8, x0
    mov     x9, x1
    mul     x0, x7, x2                 // d4 = 2*19*r4
    lsl     x0, x0, #1
    mul     x1, x0, x4
    umulh   x0, x0, x4
    adds    x8, x8, x1
    adcs    x9, x9, x0
    mul     x0, x5, x2                 // d2 = 2*19*r2
    lsl     x0, x0, #1
    mul     x1, x0, x6
    umulh   x0, x0, x6
    adds    x8, x8, x1
    adcs    x9, x9, x0
    // t[1] = d0*r1 + d4*r2 + r3*(19*r3)
    lsl     x0, x3, #1                 // d0 = 2r0
    mul     x1, x0, x4
    umulh   x0, x0, x4
    mov     x10, x1
    mov     x11, x0
    mul     x0, x7, x2                 // d4
    lsl     x0, x0, #1
    mul     x1, x0, x5
    umulh   x0, x0, x5
    adds    x10, x10, x1
    adcs    x11, x11, x0
    mul     x0, x6, x2                 // 19*r3
    mul     x1, x6, x0
    umulh   x0, x6, x0
    adds    x10, x10, x1
    adcs    x11, x11, x0
    // t[2] = d0*r2 + r1*r1 + d4*r3
    lsl     x0, x3, #1
    mul     x1, x0, x5
    umulh   x0, x0, x5
    mov     x12, x1
    mov     x13, x0
    mul     x1, x4, x4
    umulh   x0, x4, x4
    adds    x12, x12, x1
    adcs    x13, x13, x0
    mul     x0, x7, x2                 // d4
    lsl     x0, x0, #1
    mul     x1, x0, x6
    umulh   x0, x0, x6
    adds    x12, x12, x1
    adcs    x13, x13, x0
    // t[3] = d0*r3 + d1*r2 + r4*d419
    lsl     x0, x3, #1
    mul     x1, x0, x6
    umulh   x0, x0, x6
    mov     x14, x1
    mov     x15, x0
    lsl     x0, x4, #1                 // d1 = 2r1
    mul     x1, x0, x5
    umulh   x0, x0, x5
    adds    x14, x14, x1
    adcs    x15, x15, x0
    mul     x0, x7, x2                 // d419 = 19*r4
    mul     x1, x7, x0
    umulh   x0, x7, x0
    adds    x14, x14, x1
    adcs    x15, x15, x0
    // t[4] = d0*r4 + d1*r3 + r2*r2
    lsl     x0, x3, #1
    mul     x1, x0, x7
    umulh   x0, x0, x7
    mov     x16, x1
    mov     x17, x0
    lsl     x0, x4, #1
    mul     x1, x0, x6
    umulh   x0, x0, x6
    adds    x16, x16, x1
    adcs    x17, x17, x0
    mul     x1, x5, x5
    umulh   x0, x5, x5
    adds    x16, x16, x1
    adcs    x17, x17, x0

    // carry chain: t0..t4 are (x8,x9)..(x16,x17); M51 = x19, 19 = x2
    lsr     x0, x8, #51
    lsl     x1, x9, #13
    orr     x0, x0, x1                 // c = t0 >> 51
    and     x8, x8, x19
    adds    x10, x10, x0
    adcs    x11, x11, xzr
    lsr     x0, x10, #51
    lsl     x1, x11, #13
    orr     x0, x0, x1
    and     x10, x10, x19
    adds    x12, x12, x0
    adcs    x13, x13, xzr
    lsr     x0, x12, #51
    lsl     x1, x13, #13
    orr     x0, x0, x1
    and     x12, x12, x19
    adds    x14, x14, x0
    adcs    x15, x15, xzr
    lsr     x0, x14, #51
    lsl     x1, x15, #13
    orr     x0, x0, x1
    and     x14, x14, x19
    adds    x16, x16, x0
    adcs    x17, x17, xzr
    // final step: t0 was already masked by the first chain step;
    // fold t4's carry into r0 as c*19 (NOT added to t0 first)
    lsr     x0, x16, #51
    lsl     x1, x17, #13
    orr     x0, x0, x1                 // c = t4 >> 51
    and     x16, x16, x19              // r4 = t4 & M51
    mul     x0, x0, x2                 // c * 19
    add     x8, x8, x0                 // r0 += c*19
    lsr     x0, x8, #51
    and     x8, x8, x19
    add     x10, x10, x0               // r1 keeps the slack, unmasked

    mov     x3, x8                    // keep the result in r0..r4
    mov     x4, x10
    mov     x5, x12
    mov     x6, x14
    mov     x7, x16

    ldr     x8, [sp, #8]              // loop count (in the frame)
    subs    x8, x8, #1
    str     x8, [sp, #8]
    b.ne    .Lx25519_sqr_loop

    ldr     x0, [sp]                  // restore the out pointer
    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ldr     x19, [sp, #16]            // restore callee-saved x19
    add     sp, sp, #32
    ret

.Lx25519_sqr_zero:
    // No frame has been set up yet — copy in to out and return. out may
    // alias in, which is why all five limbs are read before any is
    // written.
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]
    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ret
ENDFUNC x25519_fe_sqr_times

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_sqr
//
// Description: out = a^2 mod p. One squaring — the
//   single-iteration case of x25519_fe_sqr_times, reached by tail call.
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input field element
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias in
//
// Clobbered Registers:
//   x1-x7, x9-x17
//
// Stack Usage:
//   none (x25519_fe_sqr_times allocates 32 bytes)
// ─────────────────────────────────────────────────────────────────────
