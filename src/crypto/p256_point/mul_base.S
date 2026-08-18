// P-256 fixed-base scalar multiplication (4-bit comb)

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_point_mul_base
//
// Description: (outX, outY) = k * G, constant-time, for the *fixed*
//   generator G only. p256_point_mul is the general-base routine and
//   stays as it is; this one exists because k*G is what the server
//   actually computes on the hot path (one ECDSA CertificateVerify
//   signature per TLS connection), and a fixed base can be precomputed
//   against.
//
//   Algorithm — 4-bit fixed-base comb. k is read as 64 little-endian
//   nibbles; nibble i has weight 2^(4i), so
//
//       k*G = sum over i of (d_i * 2^(4i)) * G
//
//   and every one of those 64 terms is a *table lookup*
//   (p256_comb_table, src/crypto/p256_point/comb_table.S, entry
//   [i][d_i]) rather than something built by doubling. The cost is
//   therefore 64 mixed additions and **zero** doublings, against
//   p256_point_mul's 256 doublings + 256 generic additions — and each
//   addition is the 11-field-multiply p256_point_add_affine rather
//   than the ~26-field-multiply p256_point_add.
//
//   The two structural facts that make the cheap addition valid here —
//   the accumulator is never equal to +-the table point, and digit 0
//   is the only case needing masking — are proved, not assumed, in
//   scripts/p256_comb_derivation.py (`prove`). The one degenerate
//   scalar is k == n exactly, where the true product is the point at
//   infinity; this returns (0, 0) for it, exactly as p256_point_mul
//   does, and p256_ecdsa_sign_with_k rejects that via its r == 0 check.
//
//   k is treated as a raw 256-bit value, matching p256_point_mul's
//   contract — the caller need not reduce mod n first, and
//   p256_ecdsa_sign_with_k does not.
//
// Constant time:
//   - The table scan reads all 15 entries of a block every time, at
//     addresses that depend only on the (public) block index, so the
//     digit never steers a memory access or a cache line.
//   - Both digit-dependent decisions (digit == 0, accumulator still
//     infinity) are p256_fe_cmov, i.e. CSEL, not branches.
//   - The only branches are the two loop counters, both public.
//
// Input/Arguments:
//   x0 — outX, x1 — outY (4-limb fe pointers)
//   x2 — k (4-limb scalar pointer)
//
// Stack Usage:
//   368 bytes: saved x29/x30, 4 pairs of saved x19-x26, a 96-byte R
//   accumulator, a 64-byte selected-affine-point buffer, a 32-byte
//   constant 1, and a 96-byte cand buffer
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_point_mul_base
p256_point_mul_base:
    sub     sp, sp, #368
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    // sp+80  R    (96 bytes) -- the accumulator, starts at infinity
    // sp+176 A    (64 bytes) -- the affine point selected this block
    // sp+240 one  (32 bytes) -- the field element 1, for Z of a fresh R
    // sp+272 cand (96 bytes) -- scratch for R + A each iteration

    mov     x19, x0                 // outX
    mov     x20, x1                 // outY
    mov     x21, x2                 // k

    // R = infinity (all-zero Jacobian point)
    add     x12, sp, #80
    mov     x9, #0
.Lmb_zero_r:
    cmp     x9, #96
    b.ge    .Lmb_zero_r_done
    str     xzr, [x12, x9]
    add     x9, x9, #8
    b       .Lmb_zero_r
.Lmb_zero_r_done:

    // one = 1
    mov     x9, #1
    str     x9, [sp, #240]
    str     xzr, [sp, #248]
    str     xzr, [sp, #256]
    str     xzr, [sp, #264]

    adr_l   x24, p256_comb_table    // block 0's 15 entries
    mov     x22, #0                 // block index i = 0 .. 63

.Lmb_loop:
    // d = (k[i/16] >> (4*(i%16))) & 0xF
    lsr     x9, x22, #4
    ldr     x10, [x21, x9, lsl #3]
    and     x11, x22, #15
    lsl     x11, x11, #2
    lsr     x10, x10, x11
    and     x23, x10, #0xF

    // A = table[i][d], by scanning all 15 entries of the block and
    // masking. Digit 0 matches nothing and leaves A = (0, 0), which
    // the cmov below then discards.
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x6, #0
    mov     x7, #0
    mov     x8, #0
    mov     x9, #0
    mov     x10, x24                // entry pointer
    mov     x14, #1                 // j = 1 .. 15
.Lmb_sel:
    cmp     x14, x23
    csetm   x11, eq                 // all-ones iff this entry is the one
    ldp     x12, x13, [x10, #0]
    and     x12, x12, x11
    and     x13, x13, x11
    orr     x2, x2, x12
    orr     x3, x3, x13
    ldp     x12, x13, [x10, #16]
    and     x12, x12, x11
    and     x13, x13, x11
    orr     x4, x4, x12
    orr     x5, x5, x13
    ldp     x12, x13, [x10, #32]
    and     x12, x12, x11
    and     x13, x13, x11
    orr     x6, x6, x12
    orr     x7, x7, x13
    ldp     x12, x13, [x10, #48]
    and     x12, x12, x11
    and     x13, x13, x11
    orr     x8, x8, x12
    orr     x9, x9, x13
    add     x10, x10, #64
    add     x14, x14, #1
    cmp     x14, #16
    b.lt    .Lmb_sel

    add     x10, sp, #176
    stp     x2, x3, [x10, #0]
    stp     x4, x5, [x10, #16]
    stp     x6, x7, [x10, #32]
    stp     x8, x9, [x10, #48]

    // cand = R + A
    add     x0, sp, #272
    add     x1, sp, #80
    add     x2, sp, #176
    bl      p256_point_add_affine

    // inf = (R.Z == 0), i.e. every nibble so far was zero
    ldr     x9, [sp, #144]
    ldr     x10, [sp, #152]
    orr     x9, x9, x10
    ldr     x10, [sp, #160]
    orr     x9, x9, x10
    ldr     x10, [sp, #168]
    orr     x9, x9, x10
    cmp     x9, #0
    cset    x25, eq                 // inf

    // if R was infinity, the sum is just A: cand = (A.x, A.y, 1).
    // (p256_point_add_affine's output is meaningless in that case —
    // this is the substitution its header requires the caller to make.)
    add     x0, sp, #272
    add     x1, sp, #176
    mov     x2, x25
    bl      p256_fe_cmov
    add     x0, sp, #304
    add     x1, sp, #208
    mov     x2, x25
    bl      p256_fe_cmov
    add     x0, sp, #336
    add     x1, sp, #240
    mov     x2, x25
    bl      p256_fe_cmov

    // R = (d != 0) ? cand : R
    cmp     x23, #0
    cset    x26, ne
    add     x0, sp, #80
    add     x1, sp, #272
    mov     x2, x26
    bl      p256_fe_cmov
    add     x0, sp, #112
    add     x1, sp, #304
    mov     x2, x26
    bl      p256_fe_cmov
    add     x0, sp, #144
    add     x1, sp, #336
    mov     x2, x26
    bl      p256_fe_cmov

    add     x24, x24, #960          // next block's 15 entries
    add     x22, x22, #1
    cmp     x22, #64
    b.lt    .Lmb_loop

    mov     x0, x19
    mov     x1, x20
    add     x2, sp, #80
    bl      p256_point_to_affine

    ldp     x25, x26, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #368
    ret
