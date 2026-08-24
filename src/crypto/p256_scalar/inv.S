// P-256 scalar inversion mod n

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_scalar_inv
//
// Description: out = a^-1 mod n, via Fermat (a^(n-2) mod n). The
//   contract is unchanged from the previous square-and-multiply
//   implementation — a is taken as a raw 4-limb value and the result
//   is (a mod n)^(n-2), so callers need not reduce first and
//   p256_ecdsa_sign_with_k does not — but both factors of the cost
//   are different:
//
//   1. The multiply. Every step is p256_scalar_mont_mul (Montgomery,
//      20 limb products to reduce) instead of p256_scalar_mul
//      (Barrett, 45 limb products across two more p256_bn_mul calls).
//      The whole exponentiation runs in the Montgomery domain: one
//      multiply by R^2 mod n on the way in, one by 1 on the way out.
//
//   2. The schedule. n-2 is a public curve constant, so the order of
//      operations is free. Instead of 256 squarings + 169 multiplies
//      over its bits, this runs a fixed addition chain of 257
//      squarings + 43 multiplies — 300 modular multiplications
//      against 425 — built from the run structure of n-2 (a 32-bit
//      run of ones, 32 zeros, a 65-bit run, then 128 unstructured
//      bits whose runs are all <= 6 long). The chain is derived and
//      proved to reconstruct exactly n-2 in
//      scripts/p256_scalar_inv_derivation.py (`prove`), and lives as
//      a 44-instruction program in
//      src/crypto/p256_scalar/inv_chain.S rather than as unrolled
//      code, which keeps it 180 bytes instead of ~5 KB.
//
//   Program encoding — four bytes per instruction, dst slot, src
//   slot, squaring count, multiply slot (0xFF for none):
//
//       t = slot[src]; t = t^(2^nsq); if mul != 0xFF: t *= slot[mul]
//       slot[dst] = t
//
//   nsq is always >= 1, so the first squaring reads src and writes
//   dst and no slot-copy opcode is needed. Slots 0..8 hold
//   a^(2^k - 1) for k = 1,2,3,4,5,6,8,16,32; slot 9 is the
//   accumulator and holds the answer when the program ends.
//
// Constant time: the program, like the exponent it encodes, is a
//   public curve constant, so the loop's branches carry no
//   information about a — the same reasoning the previous
//   implementation used to branch on the bits of n-2, and the one
//   p256_fe_inv still uses. Every multiply underneath is branchless.
//
// Input/Arguments:
//   x0 — out (4 limbs), may alias a
//   x1 — a (4 limbs), any 256-bit value
//
// Stack Usage:
//   416 bytes: saved x29/x30, three pairs of saved x19-x24, a 32-byte
//   constant 1 for the exit-from-Montgomery multiply, and the
//   10-slot, 320-byte chain table
// ─────────────────────────────────────────────────────────────────────
.align 2
FUNC p256_scalar_inv
    sub     sp, sp, #416
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    // sp+64  one   (32 bytes)
    // sp+96  slots (10 * 32 bytes) -- slot 9 is the accumulator

    mov     x19, x0                 // out
    add     x20, sp, #96            // slot table base

    // slot 0 = a mod n. p256_scalar_mont_mul's operand bound is < n,
    // and a is only bounded by 2^256, so this reduction is required,
    // not cosmetic.
    mov     x0, x20
    bl      p256_scalar_reduce      // x1 still holds a

    // slot 0 = a*R mod n -- Montgomery form, which the whole chain
    // then stays in.
    mov     x0, x20
    mov     x1, x20
    adr_l   x2, p256_scalar_rr_n
    bl      p256_scalar_mont_mul

    adr_l   x21, p256_scalar_inv_chain
.Lsi_step:
    ldrb    w9, [x21, #0]           // dst slot
    cmp     x9, #0xFF
    b.eq    .Lsi_done
    ldrb    w10, [x21, #1]          // src slot
    ldrb    w23, [x21, #2]          // squaring count, always >= 1
    ldrb    w24, [x21, #3]          // multiply slot, 0xFF for none
    add     x21, x21, #4

    add     x22, x20, x9, lsl #5    // -> slot[dst]
    add     x11, x20, x10, lsl #5   // -> slot[src]

    // First squaring reads src and writes dst; the rest are in place.
    mov     x0, x22
    mov     x1, x11
    mov     x2, x11
    bl      p256_scalar_mont_mul
    sub     x23, x23, #1
.Lsi_sq:
    cbz     x23, .Lsi_sq_done
    mov     x0, x22
    mov     x1, x22
    mov     x2, x22
    bl      p256_scalar_mont_mul
    sub     x23, x23, #1
    b       .Lsi_sq
.Lsi_sq_done:

    cmp     x24, #0xFF
    b.eq    .Lsi_step
    add     x2, x20, x24, lsl #5    // -> slot[mul]
    mov     x0, x22
    mov     x1, x22
    bl      p256_scalar_mont_mul
    b       .Lsi_step
.Lsi_done:

    // out = acc * 1 * R^-1 -- back out of Montgomery form.
    mov     x9, #1
    str     x9, [sp, #64]
    str     xzr, [sp, #72]
    str     xzr, [sp, #80]
    str     xzr, [sp, #88]
    mov     x0, x19
    add     x1, x20, #(9 * 32)      // the accumulator slot
    add     x2, sp, #64
    bl      p256_scalar_mont_mul

    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #416
    ret
ENDFUNC p256_scalar_inv
