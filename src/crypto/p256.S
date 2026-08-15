// ====================================================================
// ARM64 (AArch64) P-256 field arithmetic for ymawky (PLAN.MD Phase 16.1)
// File: p256.S
//
//   p256_fe_frombytes — decode 32 big-endian bytes (SEC1 encoding) into
//                       a field element (PLAN.MD 16.1)
//   p256_fe_tobytes   — encode a field element to 32 big-endian bytes
//   p256_fe_add       — a + b mod p
//   p256_fe_sub       — a - b mod p
//   p256_fe_mul       — a * b mod p
//   p256_fe_sqr       — a^2 mod p
//
// ── Field representation ──────────────────────────────────────────────
// An "fe" is 4 x 64-bit limbs, little-endian limb order (limb 0 is the
// least significant 64 bits), stored in a 32-byte buffer:
//
//     value = limb[0] + limb[1]*2^64 + limb[2]*2^128 + limb[3]*2^192
//
// working mod the NIST P-256 prime
//
//     p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//       = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffff
//
// All functions here take fully-reduced inputs (< p) and produce
// fully-reduced outputs (< p); this is what makes them safely
// composable without an explicit "canonicalize" step between calls.
//
// ── Multiplication / reduction strategy ─────────────────────────────
// Unlike x25519.S's radix-2^51 representation (chosen for x25519's
// friendly reduction, p = 2^255-19), P-256's prime doesn't reduce that
// cheaply against a 64-bit-limb layout: the fast NIST/Solinas reduction
// (FIPS 186-4 Appendix D.2.3) operates at 32-bit-word granularity and
// is easy to get subtly wrong by hand. Instead this file uses:
//
//   1. a generic multi-precision schoolbook multiply, p256_bn_mul(out,
//      a, na, b, nb), used for both a*b (4x4 limbs) and the two
//      Barrett-reduction products below — one routine, three call
//      sites, instead of three hand-specialized multiplies.
//   2. Barrett reduction of the resulting 512-bit product mod p, using
//      a precomputed mu = floor(2^512 / p) (p256_mu below). Because p
//      has exactly 4 64-bit limbs, every shift Barrett needs (by 192
//      and by 320 bits) is a whole number of 64-bit limbs — i.e. those
//      "shifts" are just pointer offsets into an existing buffer, no
//      bit-level shift instructions required at all.
//
// This is not the fastest possible P-256 multiply, but every building
// block (schoolbook multiply, multi-limb add/sub-with-borrow, a fixed
// number of branchless correction rounds) is a standard, mechanically
// checkable bignum primitive, cross-checked against an independent
// Python reference (pow(a*b, 1, p) etc.) over thousands of random
// vectors while developing this file. p256_bn_mul and p256_reduce are
// file-local (not exported) — p256_fe_mul/p256_fe_sqr are the only
// entry points that use them.
//
// All correction steps (fe_add/fe_sub's conditional +-p, p256_reduce's
// final range checks) use CSEL/CSET rather than data-dependent
// branches, and p256_bn_mul's carry-propagation runs a fixed number of
// iterations determined only by the (public, compile-time-constant per
// call site) limb counts — not by carry values — so none of this
// leaks operand data through timing.
//
// Exported Symbols:
//   p256_fe_frombytes — expand (doc block below)
//   p256_fe_tobytes   — contract (doc block below)
//   p256_fe_add       — a + b mod p (doc block below)
//   p256_fe_sub       — a - b mod p (doc block below)
//   p256_fe_mul       — a * b mod p (doc block below)
//   p256_fe_sqr       — a^2 mod p (doc block below)
//
// ====================================================================

#include "../defs.S"

.data
.align 4
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1, little-endian 64-bit limbs.
p256_p:
    .quad 0xffffffffffffffff
    .quad 0x00000000ffffffff
    .quad 0x0000000000000000
    .quad 0xffffffff00000001

// mu = floor(2^512 / p), little-endian 64-bit limbs (257 bits, 5 limbs).
p256_mu:
    .quad 0x0000000000000003
    .quad 0xfffffffeffffffff
    .quad 0xfffffffefffffffe
    .quad 0x00000000ffffffff
    .quad 0x0000000000000001

// p - 2, the (public) Fermat inversion exponent: a^(p-2) = a^-1 mod p.
p256_p_minus_2:
    .quad 0xfffffffffffffffd
    .quad 0x00000000ffffffff
    .quad 0x0000000000000000
    .quad 0xffffffff00000001

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_bn_mul
//
// Description: Generic multi-precision multiply: out[0..na+nb-1] =
//   a[0..na-1] * b[0..nb-1], schoolbook long multiplication with a
//   64x64->128 bit multiply-accumulate per (i,j) pair. out must not
//   alias a or b. Used for the field a*b product (na=nb=4) and both
//   products inside Barrett reduction (5x5 and 5x4) — see the file
//   header for why one routine covers all three shapes. Exported
//   (.global) so p256_scalar.S can reuse it for arithmetic mod the
//   group order n, with its own Barrett constants.
//
// Input/Arguments:
//   x0 — out pointer (na+nb limbs, zeroed by this function)
//   x1 — a pointer (na limbs)
//   x2 — na (limb count of a)
//   x3 — b pointer (nb limbs)
//   x4 — nb (limb count of b)
//
// Output/Returns:
//   out[0..na+nb-1] holds the full product, little-endian limbs.
//
// Clobbered Registers:
//   x0-x17 (leaf-internal scratch; caller must save anything it needs
//   across a call)
//
// Stack Usage:
//   none — leaf function, no calls out
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_bn_mul
p256_bn_mul:
    add     x5, x2, x4              // total = na + nb
    mov     x6, #0
.Lbn_mul_zero:
    cmp     x6, x5
    b.ge    .Lbn_mul_outer_init
    str     xzr, [x0, x6, lsl #3]
    add     x6, x6, #1
    b       .Lbn_mul_zero

.Lbn_mul_outer_init:
    mov     x7, #0                  // i = 0
.Lbn_mul_outer:
    cmp     x7, x2
    b.ge    .Lbn_mul_done
    ldr     x8, [x1, x7, lsl #3]    // ai = a[i]
    mov     x9, #0                  // carry
    mov     x10, #0                 // j = 0
.Lbn_mul_inner:
    cmp     x10, x4
    b.ge    .Lbn_mul_row_done
    ldr     x11, [x3, x10, lsl #3]  // bj = b[j]
    mul     x12, x8, x11            // lo = (ai*bj) & 2^64-1
    umulh   x13, x8, x11            // hi = (ai*bj) >> 64
    add     x14, x7, x10            // idx = i+j
    ldr     x15, [x0, x14, lsl #3]  // cur = out[idx]
    adds    x15, x15, x12           // cur += lo
    cset    x16, cs                 // c1 = carry out of that add
    adds    x15, x15, x9            // cur += carry-in
    cset    x17, cs                 // c2 = carry out of that add
    str     x15, [x0, x14, lsl #3]
    add     x9, x13, x16
    add     x9, x9, x17             // new carry = hi + c1 + c2
    add     x10, x10, #1
    b       .Lbn_mul_inner

.Lbn_mul_row_done:
    // Deposit the row's carry at out[i+nb], then unconditionally
    // propagate through the rest of the buffer via ADCS. The loop
    // count here (na-i-1) depends only on i and na, never on carry
    // values, so this stays constant-time.
    add     x14, x7, x4             // idx = i + nb
    ldr     x15, [x0, x14, lsl #3]
    adds    x15, x15, x9
    str     x15, [x0, x14, lsl #3]
    add     x14, x14, #1
.Lbn_mul_propagate:
    cmp     x14, x5
    b.ge    .Lbn_mul_outer_next
    ldr     x15, [x0, x14, lsl #3]
    adcs    x15, x15, xzr
    str     x15, [x0, x14, lsl #3]
    add     x14, x14, #1
    b       .Lbn_mul_propagate

.Lbn_mul_outer_next:
    add     x7, x7, #1
    b       .Lbn_mul_outer

.Lbn_mul_done:
    ret

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
// Function Name: p256_fe_frombytes
//
// Description: Decode 32 big-endian bytes (the SEC1 / X9.62 integer
//   encoding P-256 coordinates and scalars use on the wire) into a
//   field element (4 little-endian 64-bit limbs). Input must already
//   be < p; this does no reduction.
//
// Input/Arguments:
//   x0 — out fe pointer (4 limbs)
//   x1 — in pointer (32 big-endian bytes)
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_frombytes
p256_fe_frombytes:
    ldr     x2, [x1, #0]
    rev     x2, x2                  // most significant 8 bytes -> limb3
    ldr     x3, [x1, #8]
    rev     x3, x3                  // limb2
    ldr     x4, [x1, #16]
    rev     x4, x4                  // limb1
    ldr     x5, [x1, #24]
    rev     x5, x5                  // least significant 8 bytes -> limb0
    str     x5, [x0, #0]
    str     x4, [x0, #8]
    str     x3, [x0, #16]
    str     x2, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_tobytes
//
// Description: Encode a field element to 32 big-endian bytes (SEC1 /
//   X9.62 integer encoding). Inverse of p256_fe_frombytes.
//
// Input/Arguments:
//   x0 — out pointer (32 big-endian bytes)
//   x1 — in fe pointer (4 limbs)
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_tobytes
p256_fe_tobytes:
    ldr     x2, [x1, #0]            // limb0
    ldr     x3, [x1, #8]            // limb1
    ldr     x4, [x1, #16]           // limb2
    ldr     x5, [x1, #24]           // limb3
    rev     x2, x2
    rev     x3, x3
    rev     x4, x4
    rev     x5, x5
    str     x5, [x0, #0]            // limb3 (most significant) first
    str     x4, [x0, #8]
    str     x3, [x0, #16]
    str     x2, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_add
//
// Description: out = (a + b) mod p, constant-time (branchless
//   conditional subtract via CSEL).
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer, x2 — b fe pointer
//   (out may alias a and/or b)
//
// Clobbered Registers:
//   x3-x14
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_add
p256_fe_add:
    ldr     x3, [x1, #0]
    ldr     x4, [x1, #8]
    ldr     x5, [x1, #16]
    ldr     x6, [x1, #24]
    ldr     x7, [x2, #0]
    ldr     x8, [x2, #8]
    ldr     x9, [x2, #16]
    ldr     x10, [x2, #24]

    adds    x3, x3, x7
    adcs    x4, x4, x8
    adcs    x5, x5, x9
    adcs    x6, x6, x10
    cset    x11, cs                 // x11 = 1 if the sum overflowed 256 bits

    adr_l   x12, p256_p
    ldr     x13, [x12, #0]
    ldr     x14, [x12, #8]
    subs    x13, x3, x13
    sbcs    x14, x4, x14
    ldr     x9, [x12, #16]
    ldr     x10, [x12, #24]
    sbcs    x9, x5, x9
    sbcs    x10, x6, x10
    cset    x12, cs                 // 1 if sum >= p (ignoring the 257th bit)

    orr     x11, x11, x12           // subtract p if either condition holds
    cmp     x11, #1
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x9, x5, eq
    csel    x6, x10, x6, eq

    str     x3, [x0, #0]
    str     x4, [x0, #8]
    str     x5, [x0, #16]
    str     x6, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_sub
//
// Description: out = (a - b) mod p, constant-time (branchless
//   conditional add via CSEL).
//
// Input/Arguments:
//   x0 — out fe pointer, x1 — a fe pointer, x2 — b fe pointer
//   (out may alias a and/or b)
//
// Clobbered Registers:
//   x3-x13
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_sub
p256_fe_sub:
    ldr     x3, [x1, #0]
    ldr     x4, [x1, #8]
    ldr     x5, [x1, #16]
    ldr     x6, [x1, #24]
    ldr     x7, [x2, #0]
    ldr     x8, [x2, #8]
    ldr     x9, [x2, #16]
    ldr     x10, [x2, #24]

    subs    x3, x3, x7
    sbcs    x4, x4, x8
    sbcs    x5, x5, x9
    sbcs    x6, x6, x10
    cset    x11, cc                 // 1 if a < b (the subtract borrowed)

    adr_l   x12, p256_p
    ldr     x13, [x12, #0]
    adds    x13, x3, x13
    str     x13, [x0, #0]           // stash a-b+p limb0 temporarily
    ldr     x13, [x12, #8]
    adcs    x13, x4, x13
    str     x13, [x0, #8]
    ldr     x13, [x12, #16]
    adcs    x13, x5, x13
    str     x13, [x0, #16]
    ldr     x13, [x12, #24]
    adcs    x13, x6, x13
    // x13 now holds a-b+p limb3; the other three limbs are in [x0]

    cmp     x11, #1
    ldr     x7, [x0, #0]
    csel    x3, x7, x3, eq
    ldr     x7, [x0, #8]
    csel    x4, x7, x4, eq
    ldr     x7, [x0, #16]
    csel    x5, x7, x5, eq
    csel    x6, x13, x6, eq

    str     x3, [x0, #0]
    str     x4, [x0, #8]
    str     x5, [x0, #16]
    str     x6, [x0, #24]
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_cmov
//
// Description: Constant-time conditional move: if cond != 0, dst = src;
//   otherwise dst is unchanged. Implemented with CSEL, not a branch, so
//   it is safe to use on secret-dependent conditions (e.g. selecting
//   between point-arithmetic results based on a scalar bit).
//
// Input/Arguments:
//   x0 — dst fe pointer, x1 — src fe pointer, x2 — cond
//
// Clobbered Registers:
//   x3-x6
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_cmov
p256_fe_cmov:
    cmp     x2, #0
    ldr     x3, [x0, #0]
    ldr     x4, [x1, #0]
    csel    x3, x4, x3, ne
    str     x3, [x0, #0]
    ldr     x3, [x0, #8]
    ldr     x4, [x1, #8]
    csel    x3, x4, x3, ne
    str     x3, [x0, #8]
    ldr     x3, [x0, #16]
    ldr     x4, [x1, #16]
    csel    x3, x4, x3, ne
    str     x3, [x0, #16]
    ldr     x3, [x0, #24]
    ldr     x4, [x1, #24]
    csel    x3, x4, x3, ne
    str     x3, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_eq
//
// Description: Constant-time equality test of two canonical (< p)
//   field elements: exact limb comparison (safe since fe_add/sub/mul
//   always produce canonical output, so two field elements are equal
//   iff their limbs are identical).
//
// Input/Arguments:
//   x0 — a fe pointer, x1 — b fe pointer
//
// Output/Returns:
//   x0 — 1 if equal, 0 otherwise
//
// Clobbered Registers:
//   x2-x5
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_eq
p256_fe_eq:
    ldr     x2, [x0, #0]
    ldr     x3, [x1, #0]
    eor     x2, x2, x3
    ldr     x3, [x0, #8]
    ldr     x4, [x1, #8]
    eor     x3, x3, x4
    orr     x2, x2, x3
    ldr     x3, [x0, #16]
    ldr     x4, [x1, #16]
    eor     x3, x3, x4
    orr     x2, x2, x3
    ldr     x3, [x0, #24]
    ldr     x4, [x1, #24]
    eor     x3, x3, x4
    orr     x2, x2, x3
    cmp     x2, #0
    cset    x0, eq
    ret

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
