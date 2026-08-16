// ====================================================================
// ARM64 (AArch64) X25519 Implementation for sarm
// File: x25519.S
//
//   x25519_fe_frombytes   — decode 32 little-endian bytes to a field
//                           element ("expand", PLAN.MD 8.1)
//   x25519_fe_tobytes     — encode a field element to 32 bytes,
//                           canonical mod p ("contract", PLAN.MD 8.1)
//   x25519_fe_add         — field addition (PLAN.MD 8.2)
//   x25519_fe_sub         — field subtraction (PLAN.MD 8.2)
//   x25519_fe_mul         — field multiplication (PLAN.MD 8.3)
//   x25519_fe_sqr         — field squaring (PLAN.MD 8.4)
//   x25519_fe_sqr_times   — repeated field squaring (PLAN.MD 8.4)
//   x25519_fe_scalar_product — field element times a small scalar
//   x25519_fe_recip       — inversion, z^(p-2) (PLAN.MD 8.5)
//   x25519_swap_conditional — constant-time conditional swap
//   x25519                — X25519 scalar multiplication (PLAN.MD 8.7)
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
// Scalar multiplication (PLAN.MD 8.6-8.7) is the RFC 7748 §5 Montgomery
// ladder with the constant-time conditional-swap trick, using a24 =
// (486662 - 2) / 4 = 121665 and the bit-254 pre-swap optimisation from
// curve25519-donna. The ladder runs a fixed sequence of field
// operations (no branches on secret data), and the cswap is branch-free.
//
// All scratch state lives on the stack: the functions are re-entrant and
// use no mutable globals. Read-only constants are materialised as
// immediates. As per PLAN.MD 8.7 this is NOT yet connected to TLS.
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

.global x25519_fe_mul
x25519_fe_mul:
    sub     sp, sp, #96
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]

    ldp     x3, x4, [x1]               // s0, s1 (a)
    ldp     x5, x6, [x1, #16]          // s2, s3
    ldr     x7, [x1, #32]              // s4
    ldp     x8, x9, [x2]               // r0, r1 (b)
    ldp     x10, x11, [x2, #16]        // r2, r3
    ldr     x12, [x2, #32]             // r4

    mov     x26, #19
    x25519_m51 x27

    // t[0] = r0*s0
    mul     x23, x8, x3
    umulh   x24, x8, x3
    mov     x13, x23
    mov     x14, x24
    // t[1] = r0*s1 + r1*s0
    mul     x23, x8, x4
    umulh   x24, x8, x4
    mov     x15, x23
    mov     x16, x24
    mul     x23, x9, x3
    umulh   x24, x9, x3
    adds    x15, x15, x23
    adcs    x16, x16, x24
    // t[2] = r0*s2 + r2*s0 + r1*s1
    mul     x23, x8, x5
    umulh   x24, x8, x5
    mov     x17, x23
    mov     x28, x24
    mul     x23, x10, x3
    umulh   x24, x10, x3
    adds    x17, x17, x23
    adcs    x28, x28, x24
    mul     x23, x9, x4
    umulh   x24, x9, x4
    adds    x17, x17, x23
    adcs    x28, x28, x24
    // t[3] = r0*s3 + r3*s0 + r1*s2 + r2*s1
    mul     x23, x8, x6
    umulh   x24, x8, x6
    mov     x19, x23
    mov     x20, x24
    mul     x23, x11, x3
    umulh   x24, x11, x3
    adds    x19, x19, x23
    adcs    x20, x20, x24
    mul     x23, x9, x5
    umulh   x24, x9, x5
    adds    x19, x19, x23
    adcs    x20, x20, x24
    mul     x23, x10, x4
    umulh   x24, x10, x4
    adds    x19, x19, x23
    adcs    x20, x20, x24
    // t[4] = r0*s4 + r4*s0 + r3*s1 + r1*s3 + r2*s2
    mul     x23, x8, x7
    umulh   x24, x8, x7
    mov     x21, x23
    mov     x22, x24
    mul     x23, x12, x3
    umulh   x24, x12, x3
    adds    x21, x21, x23
    adcs    x22, x22, x24
    mul     x23, x11, x4
    umulh   x24, x11, x4
    adds    x21, x21, x23
    adcs    x22, x22, x24
    mul     x23, x9, x6
    umulh   x24, x9, x6
    adds    x21, x21, x23
    adcs    x22, x22, x24
    mul     x23, x10, x5
    umulh   x24, x10, x5
    adds    x21, x21, x23
    adcs    x22, x22, x24

    // fold the off-diagonal limbs: r1..r4 *= 19
    mul     x9, x9, x26
    mul     x10, x10, x26
    mul     x11, x11, x26
    mul     x12, x12, x26

    // t[0] += r4*s1 + r1*s4 + r2*s3 + r3*s2
    mul     x23, x12, x4
    umulh   x24, x12, x4
    adds    x13, x13, x23
    adcs    x14, x14, x24
    mul     x23, x9, x7
    umulh   x24, x9, x7
    adds    x13, x13, x23
    adcs    x14, x14, x24
    mul     x23, x10, x6
    umulh   x24, x10, x6
    adds    x13, x13, x23
    adcs    x14, x14, x24
    mul     x23, x11, x5
    umulh   x24, x11, x5
    adds    x13, x13, x23
    adcs    x14, x14, x24
    // t[1] += r4*s2 + r2*s4 + r3*s3
    mul     x23, x12, x5
    umulh   x24, x12, x5
    adds    x15, x15, x23
    adcs    x16, x16, x24
    mul     x23, x10, x7
    umulh   x24, x10, x7
    adds    x15, x15, x23
    adcs    x16, x16, x24
    mul     x23, x11, x6
    umulh   x24, x11, x6
    adds    x15, x15, x23
    adcs    x16, x16, x24
    // t[2] += r4*s3 + r3*s4
    mul     x23, x12, x6
    umulh   x24, x12, x6
    adds    x17, x17, x23
    adcs    x28, x28, x24
    mul     x23, x11, x7
    umulh   x24, x11, x7
    adds    x17, x17, x23
    adcs    x28, x28, x24
    // t[3] += r4*s4
    mul     x23, x12, x7
    umulh   x24, x12, x7
    adds    x19, x19, x23
    adcs    x20, x20, x24

    // carry chain: reduce t[0..4] to 5x51, folding the top carry *19
    carry128_out x13, x14, x15, x16, x27, x23, x24, x25
    carry128_out x15, x16, x17, x28, x27, x23, x24, x25
    carry128_out x17, x28, x19, x20, x27, x23, x24, x25
    carry128_out x19, x20, x21, x22, x27, x23, x24, x25
    // final step: t0 was already masked by the first carry128_out;
    // fold t4's carry into r0 as c*19 (NOT added to t0 first)
    lsr     x23, x21, #51
    lsl     x24, x22, #13
    orr     x25, x23, x24               // c = t4 >> 51
    and     x21, x21, x27               // r4 = t4 & M51
    mul     x25, x25, x26               // c * 19
    add     x13, x13, x25               // r0 += c*19
    lsr     x25, x13, #51
    and     x13, x13, x27
    add     x15, x15, x25               // r1 keeps the slack, unmasked

    stp     x13, x15, [x0]
    stp     x17, x19, [x0, #16]
    str     x21, [x0, #32]

    ldp     x19, x20, [sp]
    ldp     x21, x22, [sp, #16]
    ldp     x23, x24, [sp, #32]
    ldp     x25, x26, [sp, #48]
    ldp     x27, x28, [sp, #64]
    add     sp, sp, #96
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_sqr_times
//
// Description: out = in^(2^count) mod p (PLAN.MD 8.4). curve25519-
//   donna's curve25519_square_times: the special squaring that folds
//   the 2^255 == 19 reduction into the product columns via the doubled
//   forms d0 = 2r0, d1 = 2r1, d2 = 38r2, d419 = 19r4, d4 = 2*19*r4.
//   The limbs stay in registers across the do-while loop, exactly like
//   the reference; the same carry chain as x25519_fe_mul finishes each
//   pass. (The loop always runs at least once, matching the C.)
//
//   The 51-bit mask is held in x19 across the whole loop. x19 is
//   callee-saved, so it is pushed on entry and popped on exit; keeping
//   the mask in a callee-saved register (rather than x18, which macOS
//   uses as the platform/TLS register and clobbers on every page fault,
//   syscall and context switch) guarantees the mask survives the whole
//   loop even if the thread is preempted or takes a page fault in the
//   middle of a squaring.
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input field element
//   x2 — number of squarings (count >= 1 in practice)
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias in
//
// Clobbered Registers:
//   x0-x18, NZCV (x19 is saved/restored)
//
// Stack Usage:
//   32 bytes (out pointer, loop count, saved x19)
// ─────────────────────────────────────────────────────────────────────
