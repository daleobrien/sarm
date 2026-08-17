// Generic multi-precision multiply

#include "../../defs.S"

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
//   x5-x17 (leaf-internal scratch; caller must save anything it needs
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
