// ====================================================================
// ARM64 (AArch64) P-256 scalar (mod n) arithmetic for ymawky
// (PLAN.MD Phase 16.5/16.6 support)
// File: p256_scalar.S
//
//   p256_scalar_reduce — reduce a raw 256-bit value mod n
//   p256_scalar_add    — a + b mod n
//   p256_scalar_mul    — a * b mod n
//   p256_scalar_inv    — a^-1 mod n
//
// ECDSA signing/verification needs a second modular ring besides the
// field mod p that p256.S implements: arithmetic mod n, the order of
// the P-256 base point's group (s = k^-1(z + r*d) mod n when signing,
// u1 = z*s^-1 mod n / u2 = r*s^-1 mod n when verifying). n is a
// different 256-bit prime-like modulus from p, so it needs its own
// Barrett constant (mu_n) and its own reduction/inversion — but the
// underlying representation (4 little-endian 64-bit limbs, same
// big-endian byte encoding) and building blocks are identical to
// p256.S's field layer, right down to reusing its generic
// p256_bn_mul for both the multiply and the Barrett product. See
// p256.S's file header for the shared rationale (why Barrett instead
// of a hand-derived Solinas-style reduction, why the exponentiation
// loop's branch-on-exponent-bit is not a timing leak).
//
// p256_fe_frombytes/tobytes (p256.S) double as the scalar
// byte<->limb conversion too — the encoding is modulus-independent,
// so there's no separate p256_scalar_frombytes/tobytes here.
//
// ====================================================================

#include "../defs.S"

.extern p256_bn_mul

.data
.align 4
// n = the order of the P-256 base point, little-endian 64-bit limbs.
.global p256_n
p256_n:
    .quad 0xf3b9cac2fc632551
    .quad 0xbce6faada7179e84
    .quad 0xffffffffffffffff
    .quad 0xffffffff00000000

// mu_n = floor(2^512 / n), little-endian 64-bit limbs (257 bits, 5 limbs).
p256_mu_n:
    .quad 0x012ffd85eedf9bfe
    .quad 0x43190552df1a6c21
    .quad 0xfffffffeffffffff
    .quad 0x00000000ffffffff
    .quad 0x0000000000000001

// n - 2, the (public) Fermat inversion exponent: a^(n-2) = a^-1 mod n.
p256_n_minus_2:
    .quad 0xf3b9cac2fc63254f
    .quad 0xbce6faada7179e84
    .quad 0xffffffffffffffff
    .quad 0xffffffff00000000

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_reduce
//
// Description: out = in mod n, where in is a raw 256-bit value (as
//   from a SHA-256 hash, which may be >= n since n < 2^256). Two
//   branchless conditional-subtract-n rounds suffice: n > 2^255, so a
//   single subtraction already covers any in < 2^256.
//
// Input/Arguments:
//   x0 — out scalar pointer (4 limbs), x1 — in pointer (4 limbs, < 2^256)
//
// Clobbered Registers:
//   x2-x10
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_scalar_reduce
p256_scalar_reduce:
    ldr     x2, [x1, #0]
    ldr     x3, [x1, #8]
    ldr     x4, [x1, #16]
    ldr     x5, [x1, #24]

    .irp round, 1, 2
    adr_l   x6, p256_n
    ldr     x7, [x6, #0]
    ldr     x8, [x6, #8]
    ldr     x9, [x6, #16]
    ldr     x10, [x6, #24]
    subs    x7, x2, x7
    sbcs    x8, x3, x8
    sbcs    x9, x4, x9
    sbcs    x10, x5, x10
    cset    x6, cs                  // 1 if in >= n (no borrow)
    cmp     x6, #1
    csel    x2, x7, x2, eq
    csel    x3, x8, x3, eq
    csel    x4, x9, x4, eq
    csel    x5, x10, x5, eq
    .endr

    str     x2, [x0, #0]
    str     x3, [x0, #8]
    str     x4, [x0, #16]
    str     x5, [x0, #24]
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_add
//
// Description: out = (a + b) mod n, constant-time. Same shape as
//   p256_fe_add in p256.S, against n instead of p.
//
// Input/Arguments:
//   x0 — out, x1 — a, x2 — b (all 4-limb scalar pointers; out may
//   alias a and/or b)
//
// Clobbered Registers:
//   x3-x14
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_scalar_add
p256_scalar_add:
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
    cset    x11, cs

    adr_l   x12, p256_n
    ldr     x13, [x12, #0]
    ldr     x14, [x12, #8]
    subs    x13, x3, x13
    sbcs    x14, x4, x14
    ldr     x9, [x12, #16]
    ldr     x10, [x12, #24]
    sbcs    x9, x5, x9
    sbcs    x10, x6, x10
    cset    x12, cs

    orr     x11, x11, x12
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
// Function Name: p256_scalar_reduce_wide (file-local)
//
// Description: Barrett-reduce an 8-limb (512-bit) product mod n. Same
//   algorithm/structure as p256_reduce in p256.S; see that function's
//   doc comment for the derivation. n's Barrett estimate needs at most
//   1 correction round (checked against thousands of random vectors
//   while developing this file); two rounds are used for the same
//   defensive margin p256_reduce uses.
//
// Input/Arguments:
//   x0 — out pointer (4 limbs), x1 — T pointer (8 limbs)
//
// Stack Usage:
//   192 bytes, same layout as p256_reduce.
// ─────────────────────────────────────────────────────────────────────
.align 2
p256_scalar_reduce_wide:
    sub     sp, sp, #192
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    mov     x19, x0
    mov     x20, x1

    add     x0, sp, #32
    add     x1, x20, #24
    mov     x2, #5
    adr_l   x3, p256_mu_n
    mov     x4, #5
    bl      p256_bn_mul

    add     x0, sp, #112
    add     x1, sp, #32 + 40
    mov     x2, #5
    adr_l   x3, p256_n
    mov     x4, #4
    bl      p256_bn_mul

    ldr     x2, [x20, #0]
    ldr     x3, [x20, #8]
    ldr     x4, [x20, #16]
    ldr     x5, [x20, #24]
    ldr     x6, [x20, #32]
    ldr     x7, [x20, #40]
    ldr     x8, [x20, #48]
    ldr     x9, [x20, #56]

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
    subs    x10, xzr, x14
    cset    x16, cc
    // x2..x6 hold r's low 5 limbs; see the matching comment in
    // p256_reduce (p256.S) for why the 5th limb (x6) has to be carried
    // through the correction rounds instead of truncated away first —
    // n is close enough to 2^256 that a real correction can cross the
    // 256-bit boundary, and truncating before correcting silently
    // drops that bit on exactly the inputs that need correcting.

    adr_l   x11, p256_n
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

    .irp round, 1, 2
    adr_l   x11, p256_n
    ldr     x12, [x11, #0]
    ldr     x13, [x11, #8]
    ldr     x14, [x11, #16]
    ldr     x15, [x11, #24]
    subs    x12, x2, x12
    sbcs    x13, x3, x13
    sbcs    x14, x4, x14
    sbcs    x15, x5, x15
    sbcs    x17, x6, xzr
    cset    x16, cs
    cmp     x16, #1
    csel    x2, x12, x2, eq
    csel    x3, x13, x3, eq
    csel    x4, x14, x4, eq
    csel    x5, x15, x5, eq
    csel    x6, x17, x6, eq
    .endr
    // x6 is guaranteed 0 here.

    str     x2, [x19, #0]
    str     x3, [x19, #8]
    str     x4, [x19, #16]
    str     x5, [x19, #24]

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #192
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_mul
//
// Description: out = (a * b) mod n.
//
// Input/Arguments:
//   x0 — out, x1 — a, x2 — b (4-limb scalar pointers; out may alias
//   a and/or b)
//
// Stack Usage:
//   96 bytes, same layout as p256_fe_mul.
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_scalar_mul
p256_scalar_mul:
    sub     sp, sp, #96
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]

    mov     x19, x0
    mov     x20, x2

    add     x0, sp, #32
    mov     x2, #4
    mov     x3, x20
    mov     x4, #4
    bl      p256_bn_mul

    mov     x0, x19
    add     x1, sp, #32
    bl      p256_scalar_reduce_wide

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #96
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_inv
//
// Description: out = a^-1 mod n, via Fermat (a^(n-2) mod n) and
//   square-and-multiply against the public exponent p256_n_minus_2.
//   Scalars have no dedicated "square" primitive, so both steps call
//   p256_scalar_mul.
//
// Input/Arguments:
//   x0 — out, x1 — a (4-limb scalar pointers)
//
// Stack Usage:
//   80 bytes, same layout as p256_fe_inv.
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_scalar_inv
p256_scalar_inv:
    sub     sp, sp, #80
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]

    mov     x19, x0
    mov     x20, x1

    mov     x9, #1
    str     x9, [sp, #48]
    str     xzr, [sp, #56]
    str     xzr, [sp, #64]
    str     xzr, [sp, #72]

    mov     x22, #255
.Lscalar_inv_loop:
    lsr     x9, x22, #6
    and     x10, x22, #63
    adr_l   x11, p256_n_minus_2
    ldr     x12, [x11, x9, lsl #3]
    lsr     x12, x12, x10
    and     x21, x12, #1

    add     x0, sp, #48
    add     x1, sp, #48
    mov     x2, x0
    bl      p256_scalar_mul

    cmp     x21, #0
    b.eq    .Lscalar_inv_skip_mul
    add     x0, sp, #48
    add     x1, sp, #48
    mov     x2, x20
    bl      p256_scalar_mul
.Lscalar_inv_skip_mul:
    subs    x22, x22, #1
    b.ge    .Lscalar_inv_loop

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
