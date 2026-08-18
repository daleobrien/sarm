// Field squaring and multiplication mod p

#include "../../defs.S"

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
//   scripts/p256_reduce_derivation.py for the full derivation and the
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
//   x1-x17 (x0 holds the out pointer throughout and is not clobbered
//   until the final stores; no callee-saved register is touched).
//
//   This function proper reads x1 as the T pointer and never writes it.
//   x1 appears above because p256_fe_mul enters this code at
//   .Lreduce_regs, and it uses x1 as its b pointer — the two entries
//   share everything from that label on, so they share one clobber set
//   and scripts/validate_clobbers.py reads them as a single region. The
//   set is the union, which is the safe direction for a caller of
//   either.
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

// Register entry point: T already in x14, x15, x16, x17, x2, x3, x4, x5
// and out in x0. p256_fe_mul below branches straight here rather than
// storing its product to the stack for the four `ldp`s above to read
// back. Everything from this label on is the reduction proper, so the
// two entries cannot drift apart.
.Lreduce_regs:

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
    // the checked derivation table (scripts/p256_reduce_derivation.py) —
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
// Macro: P256_FE_PRODROW
//
// One row of the schoolbook product: T[i..i+4] += a[0..3] * b[i], where
// b[i] is loaded from the b pointer in x1 at byte offset \off. a[0..3]
// live in x6-x9 for the whole product; x10 holds b[i]; x11-x13 are the
// only scratch.
//
// The low halves are accumulated first, depositing their carry-out into
// \t4 with `adc \t4, xzr, xzr` — a SET, not an accumulate, because this
// is the first time \t4 is written. The high halves then run a second
// carry chain into \t1..\t4.
//
// The final `adc \t4, \t4, x11` cannot itself carry out, and that is
// what makes this shape correct with no propagation loop: after row i
// the accumulator holds exactly a * (b mod 2^(64*(i+1))), which is less
// than 2^256 * 2^(64*(i+1)) = 2^(64*(i+5)) and so fits in i+5 limbs with
// nothing left over. scripts/p256_fe_mul_derivation.py (`prove`) checks
// that argument at its extremes and then replays this exact instruction
// sequence with the bound as an assertion.
//
// `mul` and `umulh` do not write NZCV, so the multiplies interleaved
// into the two adcs chains below do not disturb the carry in flight.
// That is what lets three scratch registers cover a row.
// ─────────────────────────────────────────────────────────────────────
.macro P256_FE_PRODROW off, t0, t1, t2, t3, t4
    ldr     x10, [x1, #\off]        // b[i]
    mul     x11, x6, x10
    mul     x12, x7, x10
    mul     x13, x8, x10
    adds    \t0, \t0, x11
    adcs    \t1, \t1, x12
    adcs    \t2, \t2, x13
    mul     x11, x9, x10
    adcs    \t3, \t3, x11
    adc     \t4, xzr, xzr           // SET: first write of this limb
    umulh   x11, x6, x10
    umulh   x12, x7, x10
    umulh   x13, x8, x10
    adds    \t1, \t1, x11
    adcs    \t2, \t2, x12
    adcs    \t3, \t3, x13
    umulh   x11, x9, x10
    adc     \t4, \t4, x11           // proven not to carry out
.endm

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_sqr
//
// Description: out = a^2 mod p. Thin trampoline into p256_fe_mul(out,
//   a, a) — see p256_fe_mul below. A dedicated squaring would save six
//   of the sixteen limb products (the off-diagonal terms appear twice),
//   but it needs its own doubling carry chain and its own proof; this
//   file does not have one yet.
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
// Description: out = (a * b) mod p — a fully unrolled 4x4-limb
//   schoolbook product, feeding straight into the Solinas-style folding
//   reduction (p256_reduce, see its header).
//
//   This used to call p256_bn_mul, the generic (na x nb) schoolbook
//   loop, and then p256_reduce. The algorithm is unchanged — it is the
//   same schoolbook product — but the generic loop pays a load, a
//   store, two index computations and two branches for every one of the
//   sixteen limb products, and that overhead was most of its cost: 26.7
//   ns for the 4x4 shape, against 11.7 ns for a whole Montgomery
//   multiply in src/crypto/p256_scalar/mont_mul.S that does a 4x4
//   product AND a full reduction. p256_bn_mul itself is untouched and
//   still serves the 5x5/5x4 Barrett shapes in
//   src/crypto/p256_scalar/mul.S; only the field path stopped using it.
//
//   Two things follow from unrolling, and both matter more than the
//   instruction count:
//
//     1. The 512-bit product never reaches memory. It is produced
//        directly in the eight registers p256_reduce reads, and control
//        falls into that function at .Lreduce_regs, past its four
//        `ldp`s. No 8-limb stack buffer, no eight stores, no eight
//        loads.
//     2. With no call out and no stack buffer, this is a leaf: no
//        frame, no saved x29/x30, no callee-saved registers, and the
//        `ret` at the end of p256_reduce returns to *this* function's
//        caller.
//
//   The risk moved from the algorithm (unchanged) to the hand-written
//   carry chain, which is where this repo has shipped bugs before. See
//   P256_FE_PRODROW above for the bound the shape depends on, and
//   scripts/p256_fe_mul_derivation.py for its proof, its cross-check
//   against Python's arbitrary-precision multiply, and its cross-check
//   against `cryptography` (OpenSSL) via whole public keys computed
//   with every field multiply routed through the modelled carry chain.
//   tests/unit/test_p256/mul_carry.c holds the vectors it generates.
//
// Register map (the whole product fits in x0-x17, which is what allows
// the leaf form — using any of x19+ would need a frame to save them,
// and the fall-through into p256_reduce leaves nowhere to restore):
//   x0  out (untouched until p256_reduce's final stores)
//   x1  b pointer (a's limbs are read out before this is overwritten)
//   x6-x9    a[0..3], live for the whole product
//   x10      b[i], one row at a time
//   x11-x13  scratch
//   x14, x15, x16, x17, x2, x3, x4, x5   T[0..7], in p256_reduce's order
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer, x2 — b fe pointer
//   (out may alias a and/or b: both operands are consumed before
//   p256_reduce writes anything to out)
//
// Clobbered Registers:
//   x1-x17 (x0 holds out throughout; no callee-saved register is
//   touched, and x30 is not used)
//
// Stack Usage:
//   none — leaf function
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_mul
p256_fe_mul:
    // a into x6-x9, then x1 becomes the b pointer — x2 held b but is
    // needed as T[4], and every b limb is read through x1 from here on.
    ldp     x6, x7, [x1, #0]
    ldp     x8, x9, [x1, #16]
    mov     x1, x2

    // Row 0: T[0..4] = a[0..3] * b[0], written outright. There is no
    // zeroing pass over T, so this row SETS its limbs where rows 1..3
    // accumulate — a different instruction sequence, not the macro with
    // a zeroed accumulator.
    //
    // The trailing `adc x2, x2, xzr` cannot overflow: umulh of two
    // 64-bit words is at most 2^64-2 (attained only at 2^64-1 squared),
    // so adding one carry bit stays inside a limb.
    ldr     x10, [x1, #0]           // b[0]
    mul     x14, x6, x10
    umulh   x15, x6, x10
    mul     x11, x7, x10
    umulh   x16, x7, x10
    mul     x12, x8, x10
    umulh   x17, x8, x10
    mul     x13, x9, x10
    umulh   x2,  x9, x10
    adds    x15, x15, x11
    adcs    x16, x16, x12
    adcs    x17, x17, x13
    adc     x2,  x2,  xzr

    P256_FE_PRODROW 8,  x15, x16, x17, x2, x3
    P256_FE_PRODROW 16, x16, x17, x2,  x3, x4
    P256_FE_PRODROW 24, x17, x2,  x3,  x4, x5

    // T[0..7] now sit exactly where p256_reduce's `ldp`s would have put
    // them, so enter past those loads. p256_reduce's `ret` returns to
    // this function's caller.
    b       .Lreduce_regs
