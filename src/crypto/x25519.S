// ====================================================================
// ARM64 (AArch64) X25519 Implementation for ymawky (PLAN.MD Phase 8)
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

#include "../defs.S"

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
.align 4

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_frombytes
//
// Description: Expand 32 little-endian bytes into a 5x51 field element
//   (PLAN.MD 8.1). This is curve25519-donna's curve25519_expand: four
//   native 64-bit loads are spliced into five 51-bit limbs, ignoring
//   the unused bit 255 (the input is masked, as RFC 7748 requires for
//   u-coordinates).
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element (5 x u64)
//   x1 — pointer to the 32-byte little-endian input
//
// Output/Returns:
//   none (void) - the 5 limbs are written to [x0]
//
// Clobbered Registers:
//   x2-x15, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_frombytes
x25519_fe_frombytes:
    ldr     x2, [x1]
    ldr     x3, [x1, #8]
    ldr     x4, [x1, #16]
    ldr     x5, [x1, #24]

    x25519_m51 x9

    and     x6, x2, x9                 // out[0] = x0 & M51
    lsr     x2, x2, #51
    lsl     x7, x3, #13
    orr     x2, x2, x7                 // x0 = (x0 >> 51) | (x1 << 13)
    and     x10, x2, x9                // out[1] = x0 & M51
    lsr     x3, x3, #38
    lsl     x11, x4, #26
    orr     x3, x3, x11                // x1 = (x1 >> 38) | (x2 << 26)
    and     x12, x3, x9                // out[2] = x1 & M51
    lsr     x4, x4, #25
    lsl     x13, x5, #39
    orr     x4, x4, x13                // x2 = (x2 >> 25) | (x3 << 39)
    and     x14, x4, x9                // out[3] = x2 & M51
    lsr     x5, x5, #12                // x3 = (x3 >> 12)
    and     x15, x5, x9                // out[4] = x3 & M51

    stp     x6, x10, [x0]
    stp     x12, x14, [x0, #16]
    str     x15, [x0, #32]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_tobytes
//
// Description: Contract a field element into 32 little-endian bytes,
//   canonicalised to [0, p) (PLAN.MD 8.1). This is curve25519-donna's
//   curve25519_contract: two full carry passes, a +19 offset, another
//   full pass, then the 2^255-offset trick (adding a value congruent
//   to 0 mod p so a single final carry pass yields the canonical
//   residue), then the 4 x 8-byte pack.
//
// Input/Arguments:
//   x0 — pointer to the 32-byte output
//   x1 — pointer to the 40-byte input field element (5 x u64)
//
// Output/Returns:
//   none (void) - the 32 bytes are written to [x0]
//
// Clobbered Registers:
//   x2-x12, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_tobytes
x25519_fe_tobytes:
    ldp     x2, x3, [x1]
    ldp     x4, x5, [x1, #16]
    ldr     x6, [x1, #32]

    x25519_m51 x9
    mov     x10, #19
    mov     x11, #0xFFED               // 2^51 - 19 = 0x7FFFFFFFFFFFFED
    movk    x11, #0xFFFF, lsl #16
    movk    x11, #0xFFFF, lsl #32
    movk    x11, #0x7, lsl #48
    x25519_m51 x12

    carry51_full x2, x3, x4, x5, x6, x9, x7, x8, x10
    carry51_full x2, x3, x4, x5, x6, x9, x7, x8, x10
    add     x2, x2, #19
    carry51_full x2, x3, x4, x5, x6, x9, x7, x8, x10

    // 2^255-offset: value is now in [0, 2^255-1]; adding
    // (2^51-19, 2^51-1, ...) = p exactly moves it into
    // [2^255, 2^256-20], so a final carry pass canonicalises mod p
    add     x2, x2, x11
    add     x3, x3, x12
    add     x4, x4, x12
    add     x5, x5, x12
    add     x6, x6, x12
    carry51_final x2, x3, x4, x5, x6, x9, x7

    // pack 4 x 8 bytes, little-endian
    lsl     x7, x3, #51
    orr     x7, x2, x7
    str     x7, [x0]
    lsr     x7, x3, #13
    lsl     x8, x4, #38
    orr     x7, x7, x8
    str     x7, [x0, #8]
    lsr     x7, x4, #26
    lsl     x8, x5, #25
    orr     x7, x7, x8
    str     x7, [x0, #16]
    lsr     x7, x5, #39
    lsl     x8, x6, #12
    orr     x7, x7, x8
    str     x7, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_add
//
// Description: out = a + b mod p (PLAN.MD 8.2). Carry-free limbwise
//   addition: limbs may grow to ~2^52. The ladder always reduces the
//   result (via mul/square) before it is used in a way that needs
//   tighter bounds, so no carries are performed here, exactly like the
//   reference.
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input a
//   x2 — pointer to the 40-byte input b
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias a or b
//
// Clobbered Registers:
//   x3-x12, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_add
x25519_fe_add:
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]
    ldp     x8, x9, [x2]
    ldp     x10, x11, [x2, #16]
    ldr     x12, [x2, #32]

    add     x3, x3, x8
    add     x4, x4, x9
    add     x5, x5, x10
    add     x6, x6, x11
    add     x7, x7, x12

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_sub
//
// Description: out = a - b mod p (PLAN.MD 8.2). Carry-free limbwise
//   subtraction of a multiple of p to keep every limb non-negative:
//   out[0] = a[0] + (2^54-152) - b[0] and out[i] = a[i] + (2^54-8) -
//   b[i]. The added constant is congruent to 0 mod p (a multiple of p),
//   so the result is correct mod p and non-negative for the ladder's
//   input range (limbs < ~2^52), leaving limbs < ~2^55.
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input a
//   x2 — pointer to the 40-byte input b
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias a or b
//
// Clobbered Registers:
//   x3-x15, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_sub
x25519_fe_sub:
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    ldr     x7, [x1, #32]
    ldp     x8, x9, [x2]
    ldp     x10, x11, [x2, #16]
    ldr     x12, [x2, #32]

    mov     x13, #0xFF68               // 2^54 - 152 = 0x003FFFFFFFFFFF68
    movk    x13, #0xFFFF, lsl #16
    movk    x13, #0xFFFF, lsl #32
    movk    x13, #0x3F, lsl #48
    mov     x14, #0xFFF8               // 2^54 - 8 = 0x003FFFFFFFFFFF F8
    movk    x14, #0xFFFF, lsl #16
    movk    x14, #0xFFFF, lsl #32
    movk    x14, #0x3F, lsl #48

    sub     x3, x3, x8
    add     x3, x3, x13
    sub     x4, x4, x9
    add     x4, x4, x14
    sub     x5, x5, x10
    add     x5, x5, x14
    sub     x6, x6, x11
    add     x6, x6, x14
    sub     x7, x7, x12
    add     x7, x7, x14

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_mul
//
// Description: out = a * b mod p (PLAN.MD 8.3). The asymmetric 25-
//   product schoolbook from curve25519-donna: the five diagonal-ordered
//   accumulator columns t[0..4] hold the products of the 5x51 limbs
//   (up to 5 products per column, 128-bit each). The limbs of b above
//   the diagonal are pre-multiplied by 19 so that the partial products
//   with i+j >= 5 are folded into the low columns (2^255 == 19). One
//   carry chain then reduces everything: the top carry c = t[4] >> 51
//   is folded as c*19 into t[0], and the final r1 += c is left
//   unmasked (the reference relies on that small slack).
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input a
//   x2 — pointer to the 40-byte input b
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias a or b
//
// Clobbered Registers:
//   x3-x18, NZCV (x19-x28 are saved/restored)
//
// Stack Usage:
//   96 bytes (x19-x28)
// ─────────────────────────────────────────────────────────────────────
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
.global x25519_fe_sqr_times
x25519_fe_sqr_times:
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_sqr
//
// Description: out = a^2 mod p (PLAN.MD 8.4). One squaring — the
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
//   x0-x18, NZCV
//
// Stack Usage:
//   none (x25519_fe_sqr_times allocates 32 bytes)
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_sqr
x25519_fe_sqr:
    mov     x2, #1
    b       x25519_fe_sqr_times

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_scalar_product
//
// Description: out = in * scalar mod p for a small 64-bit scalar
//   (used in the ladder with scalar = a24 = 121665). curve25519-donna's
//   curve25519_scalar_product: five 128-bit in[i]*scalar + carry steps
//   with a 51-bit mask per limb and the final carry folded as c*19 into
//   out[0] without re-carrying (the reference leaves that slack).
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input field element
//   x2 — the scalar (u64)
//
// Output/Returns:
//   none (void) - out is written to [x0]; out may alias in
//
// Clobbered Registers:
//   x3-x18, NZCV (x19, x28 are saved/restored)
//
// Stack Usage:
//   32 bytes (x19, x28)
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_scalar_product
x25519_fe_scalar_product:
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_swap_conditional
//
// Description: Constant-time conditional swap of two field elements:
//   if iswap is non-zero, x and qpx exchange their 5 limbs, otherwise
//   they are unchanged. The mask -(int64)iswap is all-ones or all-zero
//   and the swap is pure XOR, so the branch pattern is independent of
//   the swap bit (RFC 7748 §5 cswap; PLAN.MD 8.6).
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
//   x3-x15, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
// ─────────────────────────────────────────────────────────────────────
.global x25519_swap_conditional
x25519_swap_conditional:
    cmp     x2, #0
    csetm   x9, ne                     // x9 = 0 - iswap (all-ones if set)

    ldp     x3, x4, [x0]
    ldp     x5, x6, [x0, #16]
    ldr     x7, [x0, #32]
    ldp     x10, x11, [x1]
    ldp     x12, x13, [x1, #16]
    ldr     x14, [x1, #32]

    eor     x15, x3, x10               // m = mask & (x ^ qpx); x ^= m; qpx ^= m
    and     x15, x15, x9
    eor     x3, x3, x15
    eor     x10, x10, x15
    eor     x15, x4, x11
    and     x15, x15, x9
    eor     x4, x4, x15
    eor     x11, x11, x15
    eor     x15, x5, x12
    and     x15, x15, x9
    eor     x5, x5, x15
    eor     x12, x12, x15
    eor     x15, x6, x13
    and     x15, x15, x9
    eor     x6, x6, x15
    eor     x13, x13, x15
    eor     x15, x7, x14
    and     x15, x15, x9
    eor     x7, x7, x15
    eor     x14, x14, x15

    stp     x3, x4, [x0]
    stp     x5, x6, [x0, #16]
    str     x7, [x0, #32]
    stp     x10, x11, [x1]
    stp     x12, x13, [x1, #16]
    str     x14, [x1, #32]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519_fe_recip
//
// Description: out = z^(p-2) = z^-1 mod p (PLAN.MD 8.5). Fermat
//   inversion via the fixed exponentiation chain from curve25519-donna
//   (curve25519_recip + curve25519_pow_two5mtwo0_two250mtwo0):
//   p - 2 = 2^255 - 21 is built as (2^255 - 2^5) * 2^11 via
//   z^(2^5-1) -> z^(2^250-1) -> z^(2^255-32), times z^11.
//
// Input/Arguments:
//   x0 — pointer to the 40-byte output field element
//   x1 — pointer to the 40-byte input field element z
//
// Output/Returns:
//   none (void) - out is written to [x0]; out must not alias z
//
// Clobbered Registers:
//   x0-x18, x19, x20, x30, NZCV
//
// Stack Usage:
//   192 bytes: 4 scratch field elements (a, t0, b, c) + saved x19,
//   x20, x30
// ─────────────────────────────────────────────────────────────────────
.global x25519_fe_recip
x25519_fe_recip:
    sub     sp, sp, #192
    stp     x19, x20, [sp, #160]
    str     x30, [sp, #176]
    mov     x19, x1                    // z
    mov     x20, x0                    // out

    add     x0, sp, #0                 // a = z^2
    mov     x1, x19
    bl      x25519_fe_sqr
    add     x0, sp, #40                // t0 = a^(2^2) = z^8
    add     x1, sp, #0
    mov     x2, #2
    bl      x25519_fe_sqr_times
    add     x0, sp, #80                // b = t0*z = z^9
    add     x1, sp, #40
    mov     x2, x19
    bl      x25519_fe_mul
    add     x0, sp, #0                 // a = b*a = z^11
    add     x1, sp, #80
    add     x2, sp, #0
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = a^2 = z^22
    add     x1, sp, #0
    bl      x25519_fe_sqr
    add     x0, sp, #80                // b = t0*b = z^31 = z^(2^5-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul

    // b = z^(2^250-1) via square-and-multiply chain
    add     x0, sp, #40                // t0 = b^(2^5)
    add     x1, sp, #80
    mov     x2, #5
    bl      x25519_fe_sqr_times
    add     x0, sp, #80                // b = t0*b = z^(2^10-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = b^(2^10)
    add     x1, sp, #80
    mov     x2, #10
    bl      x25519_fe_sqr_times
    add     x0, sp, #120               // c = t0*b = z^(2^20-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = c^(2^20)
    add     x1, sp, #120
    mov     x2, #20
    bl      x25519_fe_sqr_times
    add     x0, sp, #40                // t0 = t0*c = z^(2^40-1)
    add     x1, sp, #40
    add     x2, sp, #120
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = t0^(2^10)
    add     x1, sp, #40
    mov     x2, #10
    bl      x25519_fe_sqr_times
    add     x0, sp, #80                // b = t0*b = z^(2^50-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = b^(2^50)
    add     x1, sp, #80
    mov     x2, #50
    bl      x25519_fe_sqr_times
    add     x0, sp, #120               // c = t0*b = z^(2^100-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = c^(2^100)
    add     x1, sp, #120
    mov     x2, #100
    bl      x25519_fe_sqr_times
    add     x0, sp, #40                // t0 = t0*c = z^(2^200-1)
    add     x1, sp, #40
    add     x2, sp, #120
    bl      x25519_fe_mul
    add     x0, sp, #40                // t0 = t0^(2^50)
    add     x1, sp, #40
    mov     x2, #50
    bl      x25519_fe_sqr_times
    add     x0, sp, #80                // b = t0*b = z^(2^250-1)
    add     x1, sp, #40
    add     x2, sp, #80
    bl      x25519_fe_mul

    add     x0, sp, #80                // b = b^(2^5) = z^(2^255-32)
    add     x1, sp, #80
    mov     x2, #5
    bl      x25519_fe_sqr_times
    mov     x0, x20                    // out = b*a = z^(2^255-21) = z^(p-2)
    add     x1, sp, #80
    add     x2, sp, #0
    bl      x25519_fe_mul

    ldp     x19, x20, [sp, #160]
    ldr     x30, [sp, #176]
    add     sp, sp, #192
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: x25519
//
// Description: X25519 scalar multiplication (PLAN.MD 8.6-8.7):
//   out = scalar * point on Curve25519, i.e. RFC 7748's X25519(k, u).
//   The scalar is clamped (bits 0-2 and 255 cleared, bit 254 set), the
//   u-coordinate is expanded and its top bit masked (RFC 7748 §5), and
//   the Montgomery ladder runs a fixed 255 steps using the bit-254
//   pre-swap optimisation: 252 main-loop iterations (bits 253..2) with
//   a conditional swap at bit ^ lastbit, then 3 doubling-only steps for
//   the zero low bits. The result x2/z2 is recovered via z2^(p-2) and
//   contracted to 32 bytes. The ladder is branch-free on secret data
//   (constant-time cswap, fixed op sequence).
//
//   NOTE: not connected to TLS yet (PLAN.MD 8.7).
//
// Input/Arguments:
//   x0 — pointer to the 32-byte output (shared secret)
//   x1 — pointer to the 32-byte little-endian scalar k
//   x2 — pointer to the 32-byte little-endian u-coordinate
//
// Output/Returns:
//   none (void) - the 32-byte result is written to [x0]
//
// Clobbered Registers:
//   x0-x28, x30, NZCV (x19-x28 and x30 are saved/restored)
//
// Stack Usage:
//   528 bytes: 32-byte clamped scalar, 10 field elements (nqx, nqz,
//   nqpqx, nqpqz, q, qx, qpqx, qqx, zzz, zmone), saved x19-x28, x30
// ─────────────────────────────────────────────────────────────────────
.global x25519
x25519:
    sub     sp, sp, #528
    stp     x19, x20, [sp, #432]
    stp     x21, x22, [sp, #448]
    stp     x23, x24, [sp, #464]
    stp     x25, x26, [sp, #480]
    stp     x27, x28, [sp, #496]
    str     x30, [sp, #512]
    mov     x28, x0                    // out
    mov     x19, sp                    // e = clamped scalar copy

    // e = scalar with RFC 7748 clamping: e[0] &= 248, e[31] &= 127,
    // e[31] |= 64
    ldp     x3, x4, [x1]
    ldp     x5, x6, [x1, #16]
    stp     x3, x4, [x19]
    stp     x5, x6, [x19, #16]
    ldrb    w3, [x19]
    and     w3, w3, #0xf8
    strb    w3, [x19]
    ldrb    w3, [x19, #31]
    and     w3, w3, #0x7f
    orr     w3, w3, #0x40
    strb    w3, [x19, #31]

    add     x20, sp, #192              // q = expand(point)
    mov     x0, x20
    mov     x1, x2
    bl      x25519_fe_frombytes

    add     x21, sp, #32               // nqx = q (x2 starts as x1 = u)
    ldp     x3, x4, [x20]
    ldp     x5, x6, [x20, #16]
    ldr     x7, [x20, #32]
    stp     x3, x4, [x21]
    stp     x5, x6, [x21, #16]
    str     x7, [x21, #32]

    add     x22, sp, #72               // nqz = {1} (z2): limb 0 = 1
    mov     x3, #1
    str     x3, [x22]
    str     xzr, [x22, #8]
    str     xzr, [x22, #16]
    str     xzr, [x22, #24]
    str     xzr, [x22, #32]

    add     x23, sp, #112              // nqpqx = {1} (x3): limb 0 = 1
    str     x3, [x23]
    str     xzr, [x23, #8]
    str     xzr, [x23, #16]
    str     xzr, [x23, #24]
    str     xzr, [x23, #32]

    add     x24, sp, #152              // nqpqz = {0} (z3)
    stp     xzr, xzr, [x24]
    stp     xzr, xzr, [x24, #16]
    str     xzr, [x24, #32]

    mov     x26, #1                    // lastbit = 1 (bit 254 is always 1)

    // ── main ladder: bits 253 down to 2 ────────────────────────────
    mov     x25, #253
.Lx25519_main:
    add     x0, sp, #232               // qx = nqx + nqz
    mov     x1, x21
    mov     x2, x22
    bl      x25519_fe_add
    add     x0, sp, #72                // nqz = nqx - nqz
    mov     x1, x21
    mov     x2, x22
    bl      x25519_fe_sub
    add     x0, sp, #272               // qpqx = nqpqx + nqpqz
    mov     x1, x23
    mov     x2, x24
    bl      x25519_fe_add
    add     x0, sp, #152               // nqpqz = nqpqx - nqpqz
    mov     x1, x23
    mov     x2, x24
    bl      x25519_fe_sub
    add     x0, sp, #112               // nqpqx = qpqx * nqz
    add     x1, sp, #272
    mov     x2, x22
    bl      x25519_fe_mul
    add     x0, sp, #152               // nqpqz = qx * nqpqz
    add     x1, sp, #232
    add     x2, sp, #152
    bl      x25519_fe_mul
    add     x0, sp, #312               // qqx = nqpqx + nqpqz
    mov     x1, x23
    add     x2, sp, #152
    bl      x25519_fe_add
    add     x0, sp, #152               // nqpqz = nqpqx - nqpqz
    mov     x1, x23
    add     x2, sp, #152
    bl      x25519_fe_sub
    add     x0, sp, #152               // nqpqz = nqpqz^2
    add     x1, sp, #152
    bl      x25519_fe_sqr
    add     x0, sp, #112               // nqpqx = qqx^2
    add     x1, sp, #312
    bl      x25519_fe_sqr
    add     x0, sp, #152               // nqpqz = nqpqz * q
    add     x1, sp, #152
    mov     x2, x20
    bl      x25519_fe_mul
    add     x0, sp, #232               // qx = qx^2
    add     x1, sp, #232
    bl      x25519_fe_sqr
    add     x0, sp, #72                // nqz = nqz^2
    add     x1, sp, #72
    bl      x25519_fe_sqr
    add     x0, sp, #32                // nqx = qx * nqz
    add     x1, sp, #232
    mov     x2, x22
    bl      x25519_fe_mul
    add     x0, sp, #72                // nqz = qx - nqz
    add     x1, sp, #232
    mov     x2, x22
    bl      x25519_fe_sub
    add     x0, sp, #352               // zzz = nqz * 121665
    mov     x1, x22
    movz    x2, #0xdb41                // a24 = (486662-2)/4 = 121665 = 0x1DB41
    movk    x2, #0x1, lsl #16
    bl      x25519_fe_scalar_product

    add     x0, sp, #352               // zzz = zzz + qx
    add     x1, sp, #352
    add     x2, sp, #232
    bl      x25519_fe_add

    add     x0, sp, #72                // nqz = nqz * zzz
    mov     x1, x22
    add     x2, sp, #352
    bl      x25519_fe_mul

    lsr     x0, x25, #3                // bit = (e[i/8] >> (i&7)) & 1
    ldrb    w1, [x19, x0]
    and     w2, w25, #7
    lsr     w1, w1, w2
    and     w27, w1, #1
    eor     w2, w27, w26               // swap nqx/nqpqx on bit ^ lastbit
    mov     x0, x21
    mov     x1, x23
    bl      x25519_swap_conditional
    eor     w2, w27, w26               // swap nqz/nqpqz
    mov     x0, x22
    mov     x1, x24
    bl      x25519_swap_conditional
    mov     x26, x27                   // lastbit = bit

    subs    x25, x25, #1
    cmp     x25, #2
    b.ge    .Lx25519_main

    // ── final 3 doubling steps (bits 1, 0 are zero after clamping) ──
    mov     x25, #3
.Lx25519_dbl:
    add     x0, sp, #232               // qx = nqx + nqz
    mov     x1, x21
    mov     x2, x22
    bl      x25519_fe_add
    add     x0, sp, #72                // nqz = nqx - nqz
    mov     x1, x21
    mov     x2, x22
    bl      x25519_fe_sub
    add     x0, sp, #232               // qx = qx^2
    add     x1, sp, #232
    bl      x25519_fe_sqr
    add     x0, sp, #72                // nqz = nqz^2
    add     x1, sp, #72
    bl      x25519_fe_sqr
    add     x0, sp, #32                // nqx = qx * nqz
    add     x1, sp, #232
    mov     x2, x22
    bl      x25519_fe_mul
    add     x0, sp, #72                // nqz = qx - nqz
    add     x1, sp, #232
    mov     x2, x22
    bl      x25519_fe_sub
    add     x0, sp, #352               // zzz = nqz * 121665
    mov     x1, x22
    movz    x2, #0xdb41                // a24 = (486662-2)/4 = 121665 = 0x1DB41
    movk    x2, #0x1, lsl #16
    bl      x25519_fe_scalar_product
    add     x0, sp, #352               // zzz = zzz + qx
    add     x1, sp, #352
    add     x2, sp, #232
    bl      x25519_fe_add
    add     x0, sp, #72                // nqz = nqz * zzz
    mov     x1, x22
    add     x2, sp, #352
    bl      x25519_fe_mul
    subs    x25, x25, #1
    b.ne    .Lx25519_dbl

    // ── recover the result: out = nqx * nqz^(p-2) ──────────────────
    add     x0, sp, #392               // zmone = recip(nqz)
    mov     x1, x22
    bl      x25519_fe_recip
    add     x0, sp, #72                // nqz = nqx * zmone
    mov     x1, x21
    add     x2, sp, #392
    bl      x25519_fe_mul
    mov     x0, x28                    // contract to out
    add     x1, sp, #72
    bl      x25519_fe_tobytes

    ldp     x19, x20, [sp, #432]
    ldp     x21, x22, [sp, #448]
    ldp     x23, x24, [sp, #464]
    ldp     x25, x26, [sp, #480]
    ldp     x27, x28, [sp, #496]
    ldr     x30, [sp, #512]
    add     sp, sp, #528
    ret
