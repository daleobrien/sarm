// Field squaring and multiplication mod p

#include "../../defs.S"

.extern p256_bn_mul

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_reduce
//
// Description: Solinas-style folding reduction of a 512-bit product (8
//   limbs) mod p, producing a canonical 4-limb result. Replaces the
//   previous Barrett reduction (two p256_bn_mul calls) with a
//   multiplication-free fold that exploits p's special form:
//
//       p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//
//   which gives the exact identity 2^256 = p + 2^224 - 2^192 - 2^96 + 1,
//   i.e. 2^256 == 2^224 - 2^192 - 2^96 + 1 (mod p). Splitting T into
//   sixteen 32-bit words c[0..15] (two per 64-bit limb) and repeatedly
//   applying that identity to rewrite each high word c[8..15]*2^(32i)
//   (i>=8) as a sparse signed combination of the low eight word
//   positions gives, for every output word j, a fixed small set of
//   (input word, +-1/+-2/+-3 coefficient) pairs — see
//   docs/P256-REDUCE-DERIVATION.md for the full derivation and the
//   generator that produced this table.
//
//   Algorithm:
//     1. Seed acc[0..7] with the low 256 bits' words (identity, no
//        reduction needed: c[0..7]).
//     2. Fold each high word c[8..15] into acc[] via its table entry
//        (pure ADD/SUB/shift, no multiply).
//     3. Propagate 32-bit-granular carries across acc[0..7] (ASR/AND,
//        matching two's-complement floor-division semantics exactly)
//        to get eight clean digits plus a carry_final that is exactly
//        bounded to [-4, 4] (proven by linear-extrema search over the
//        input word box, not just sampled — see derivation doc).
//     4. Fold carry_final back in via the *same* identity applied once
//        (it's exactly the c[8] table entry, since carry_final is the
//        coefficient of 2^256) and propagate again. This second, much
//        smaller fold is required because one fold of a 512-bit input
//        does not land inside 256 bits — see the derivation doc for
//        why a single pass is insufficient. The resulting second-pass
//        carry (the "ext" limb below) is bounded to {-1, 0, 1}.
//     5. Reassemble the eight clean digits into 4 output limbs, and
//        canonicalize with the same branchless correction-round shape
//        the previous Barrett implementation used: a defensive +p if
//        ext went negative, then two conditional -p rounds. ext is
//        guaranteed 0 after correction (proven over 2M+ random and
//        adversarial cases in the Python reference).
//
//   This function is a pure register-to-register computation: no
//   multiply instructions, no subroutine calls, no stack.
//
// Input/Arguments:
//   x0 — out pointer (4 limbs)
//   x1 — T pointer (8 limbs, the product to reduce)
//
// Output/Returns:
//   out[0..3] = T mod p, canonical (< p)
//
// Clobbered Registers:
//   x0, x2-x17 (x0 holds the out pointer throughout and is not
//   clobbered until the final stores; x1 is read but never written;
//   no callee-saved register is touched)
//
// Stack Usage:
//   none — leaf function, no calls out, no scratch buffer needed (the
//   previous Barrett implementation's 192-byte frame held q2[10]/q3p[9]
//   buffers for its two multiplies, which this algorithm has no use for)
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_reduce
p256_reduce:
    // Load all 8 T limbs. T0..T3 are consumed immediately below (their
    // words are used as-is, no reduction). T4..T7 (x2-x5) stay live
    // through the accumulation phase below since their halves each
    // contribute to several output words.
    ldp     x14, x15, [x1, #0]      // T0, T1
    ldp     x16, x17, [x1, #16]     // T2, T3
    ldp     x2, x3, [x1, #32]       // T4, T5
    ldp     x4, x5, [x1, #48]       // T6, T7

    // acc[0..7] (x6..x13) seeded with the low 256 bits' words verbatim.
    and     x6,  x14, #0xffffffff   // acc0 = lo(T0)
    lsr     x7,  x14, #32           // acc1 = hi(T0)
    and     x8,  x15, #0xffffffff   // acc2 = lo(T1)
    lsr     x9,  x15, #32           // acc3 = hi(T1)
    and     x10, x16, #0xffffffff   // acc4 = lo(T2)
    lsr     x11, x16, #32           // acc5 = hi(T2)
    and     x12, x17, #0xffffffff   // acc6 = lo(T3)
    lsr     x13, x17, #32           // acc7 = hi(T3)

    // Fold each high word (c[8..15], the two halves of T4..T7) into
    // acc[] per its derived table entry. Generated mechanically from
    // the checked derivation table (docs/P256-REDUCE-DERIVATION.md) —
    // not hand-transcribed — to keep this in lockstep with what was
    // actually verified in Python.
    and     x14, x2, #0xffffffff    // c[8] = lo(T4)
    add     x6, x6, x14
    sub     x9, x9, x14
    sub     x12, x12, x14
    add     x13, x13, x14

    lsr     x14, x2, #32            // c[9] = hi(T4)
    add     x6, x6, x14
    add     x7, x7, x14
    sub     x9, x9, x14
    sub     x10, x10, x14
    sub     x12, x12, x14

    and     x14, x3, #0xffffffff    // c[10] = lo(T5)
    add     x7, x7, x14
    add     x8, x8, x14
    sub     x10, x10, x14
    sub     x11, x11, x14
    sub     x13, x13, x14

    lsr     x14, x3, #32            // c[11] = hi(T5)
    sub     x6, x6, x14
    add     x8, x8, x14
    add     x9, x9, x14, lsl #1
    sub     x11, x11, x14
    sub     x13, x13, x14

    and     x14, x4, #0xffffffff    // c[12] = lo(T6)
    sub     x6, x6, x14
    sub     x7, x7, x14
    add     x9, x9, x14, lsl #1
    add     x10, x10, x14, lsl #1
    sub     x13, x13, x14

    lsr     x14, x4, #32            // c[13] = hi(T6)
    sub     x6, x6, x14
    sub     x7, x7, x14
    sub     x8, x8, x14
    add     x9, x9, x14
    add     x10, x10, x14, lsl #1
    add     x11, x11, x14, lsl #1
    add     x12, x12, x14
    sub     x13, x13, x14

    and     x14, x5, #0xffffffff    // c[14] = lo(T7)
    sub     x6, x6, x14
    sub     x7, x7, x14
    sub     x8, x8, x14
    add     x10, x10, x14
    add     x11, x11, x14, lsl #1
    add     x12, x12, x14
    add     x12, x12, x14, lsl #1

    lsr     x14, x5, #32            // c[15] = hi(T7)
    sub     x7, x7, x14
    sub     x8, x8, x14
    sub     x9, x9, x14
    add     x11, x11, x14
    add     x12, x12, x14, lsl #1
    add     x13, x13, x14
    add     x13, x13, x14, lsl #1

    // Propagate pass 1: 32-bit-granular carry across acc[0..7] (x6-x13).
    // ASR gives an arithmetic (floor) shift, so this handles negative
    // acc[] values correctly — it is the exact hardware equivalent of
    // Python's ">>" on a negative int, which is what the reference was
    // checked against.
    mov     x15, xzr
    .irp r, 6, 7, 8, 9, 10, 11, 12, 13
    add     x14, x\r, x15
    and     x\r, x14, #0xffffffff
    asr     x15, x14, #32
    .endr
    // x15 = carry_final, proven in [-4, 4].

    // Fold carry_final back in via the c[8] table entry (identical in
    // shape to the c[8] fold above, since carry_final is exactly the
    // coefficient of 2^256).
    add     x6, x6, x15
    sub     x9, x9, x15
    sub     x12, x12, x15
    add     x13, x13, x15

    // Propagate pass 2, same as pass 1.
    mov     x15, xzr
    .irp r, 6, 7, 8, 9, 10, 11, 12, 13
    add     x14, x\r, x15
    and     x\r, x14, #0xffffffff
    asr     x15, x14, #32
    .endr
    // x15 = ext, proven in {-1, 0, 1}.

    // Reassemble the eight clean 32-bit digits into 4 output limbs.
    // T4..T7 (x2-x5) are fully consumed by this point and free to reuse.
    orr     x2, x6, x7, lsl #32
    orr     x3, x8, x9, lsl #32
    orr     x4, x10, x11, lsl #32
    orr     x5, x12, x13, lsl #32
    mov     x6, x15                 // ext: the signed 5th limb for correction

    // Defensive: if ext is negative, add p back once.
    cmp     x6, #0
    cset    x16, lt
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

    str     x2, [x0, #0]
    str     x3, [x0, #8]
    str     x4, [x0, #16]
    str     x5, [x0, #24]
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
//   (p256_bn_mul) producing an 8-limb product, followed by the
//   Solinas-style folding reduction (p256_reduce, see its header).
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
