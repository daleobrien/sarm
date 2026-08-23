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
