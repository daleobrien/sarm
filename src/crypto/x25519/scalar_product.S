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

FUNC x25519_fe_scalar_product
    sub     sp, sp, #32
    stp     x19, x28, [sp]

    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]

    x25519_m51 x9
    mov     x10, #19

    mul     x11, x3, x2                // t = in[0]*scalar
    umulh   x12, x3, x2
    and     x13, x11, x9               // out[0] = t & M51
    lsr     x14, x11, #51              // c = t >> 51
    lsl     x15, x12, #13
    orr     x14, x14, x15

    mul     x11, x4, x2
    umulh   x12, x4, x2
    adds    x11, x11, x14
    adcs    x12, x12, xzr
    and     x16, x11, x9               // out[1]
    lsr     x14, x11, #51
    lsl     x15, x12, #13
    orr     x14, x14, x15

    mul     x11, x5, x2
    umulh   x12, x5, x2
    adds    x11, x11, x14
    adcs    x12, x12, xzr
    and     x17, x11, x9               // out[2]
    lsr     x14, x11, #51
    lsl     x15, x12, #13
    orr     x14, x14, x15

    mul     x11, x6, x2
    umulh   x12, x6, x2
    adds    x11, x11, x14
    adcs    x12, x12, xzr
    and     x28, x11, x9               // out[3]
    lsr     x14, x11, #51
    lsl     x15, x12, #13
    orr     x14, x14, x15

    mul     x11, x7, x2
    umulh   x12, x7, x2
    adds    x11, x11, x14
    adcs    x12, x12, xzr
    and     x19, x11, x9               // out[4]
    lsr     x14, x11, #51
    lsl     x15, x12, #13
    orr     x14, x14, x15

    mul     x14, x14, x10              // out[0] += c*19 (no re-carry)
    add     x13, x13, x14

    stp     x13, x16, [x0]
    stp     x17, x28, [x0, #16]
    str     x19, [x0, #32]

    ldp     x19, x28, [sp]
    add     sp, sp, #32
    ret
ENDFUNC x25519_fe_scalar_product

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_swap_conditional
//
// Description: Constant-time conditional swap of two field elements:
//   if iswap is non-zero, x and qpx exchange their 5 limbs, otherwise
//   they are unchanged. The mask -(int64)iswap is all-ones or all-zero
//   and the swap is pure XOR, so the branch pattern is independent of
//   the swap bit (RFC 7748 §5 cswap).
//
// Input/Arguments:
//   x0 — pointer to the 40-byte field element x (read-write)
//   x1 — pointer to the 40-byte field element qpx (read-write)
//   x2 — swap flag (0 or 1)
//
// Output/Returns:
//   none (void) - [x0] and [x1] hold the (possibly swapped) values
//
// Clobbered Registers:
//   x3-x7, x9-x15, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
