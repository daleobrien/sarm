// GF(2^128) multiplication

#include "data.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: gf_mult_128
//
// Description: Z = X·Y in GF(2^128) (NIST SP 800-38D §6.3) — the basis
//   for GHASH. X, Y and Z are 16-byte blocks in GCM wire
//   order. Internally the operands are mapped into the natural polynomial
//   domain (per-byte bit reversal), multiplied with PMULL, reduced with
//   the 0x87 constant, and mapped back.
//
// Input/Arguments:
//   x0 — pointer to the 16-byte multiplicand X
//   x1 — pointer to the 16-byte multiplier Y
//   x2 — pointer to the 16-byte result buffer Z (must not overlap X or Y)
//
// Output/Returns:
//   none (void) - 16 Z bytes written to [x2]
//
// Clobbered Registers:
//   x9, x10, v0-v7, v16-v18, v21, NZCV
//
// Stack Usage:
//   16 bytes (x30)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global gf_mult_128

gf_mult_128:
    sub     sp, sp, #16
    str     x30, [sp]

    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    ld1     {v0.16b}, [x0]
    ld1     {v1.16b}, [x1]
    gcm_rbit v0.16b, v0.16b              // X into the natural domain
    gcm_rbit v1.16b, v1.16b              // Y into the natural domain
    bl      .Lgcm_gf_mul               // v0 = X·Y mod (x^128+x^7+x^2+x+1)
    gcm_rbit v0.16b, v0.16b              // back to GCM wire order
    st1     {v0.16b}, [x2]

    ldr     x30, [sp]
    add     sp, sp, #16
    ret
