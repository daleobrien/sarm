// GCM helper functions, macros, and constants

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Macro: gcm_rbit
//
// Description: Per-byte bit reversal of a 16-byte vector via nibble
//   lookups (see the file header for why GCM needs this). v16 must hold
//   the nibble-reversal table .Lgcm_rbit_table and v21 the byte mask
//   0x0f (NEON has no byte-granular immediate AND). The operands are
//   passed with their element qualifier, e.g. gcm_rbit v0.16b, v0.16b.
//
// Input/Arguments:
//   \src — source operand (full "vN.16b" form)
//   \dst — destination operand (full "vN.16b" form; may alias \src)
//
// Clobbered Registers:
//   v2, v3
// ─────────────────────────────────────────────────────────────────────
.macro gcm_rbit src, dst
    ushr    v2.16b, \src, #4             // high nibble -> low position
    tbl     v3.16b, {v16.16b}, v2.16b    // T[hi] -> result low nibble
    and     v2.16b, \src, v21.16b        // keep the low nibble only
    tbl     v2.16b, {v16.16b}, v2.16b    // T[lo] -> result high nibble
    shl     v2.16b, v2.16b, #4
    orr     \dst, v3.16b, v2.16b
.endm

// ─────────────────────────────────────────────────────────────────────
// Macro: gcm_inc32
//
// Description: Increment the rightmost 32 bits of the 16-byte counter
//   block at \ptr as a big-endian value, wrapping mod 2^32 (SP 800-38D
//   §6.2 inc32).
//
// Input/Arguments:
//   \ptr — X register holding the 16-byte counter block address
//
// Clobbered Registers:
//   w9
// ─────────────────────────────────────────────────────────────────────
.macro gcm_inc32 ptr
    ldr     w9, [\ptr, #12]
    rev     w9, w9
    add     w9, w9, #1
    rev     w9, w9
    str     w9, [\ptr, #12]
.endm

.text
.align 4

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lgcm_gf_mul (private, leaf)
//
// Description: GF(2^128) multiply in the natural polynomial domain:
//   v0 = v0·v1 mod (x^128 + x^7 + x^2 + x + 1). The 256-bit product is
//   built with three Karatsuba PMULLs (PMULL has no cross-lane form, so
//   a_lo·b_hi ⊕ a_hi·b_lo is folded into the middle product
//   (a_lo⊕a_hi)·(b_lo⊕b_hi)); the reduction then folds the high half by
//   x^128 ≡ 0x87 in three steps (see the file header).
//
// Input/Arguments:
//   v0  — multiplicand A (natural domain)
//   v1  — multiplier B (natural domain)
//   v17 — [0x87, 0x87] reduction constant
//   v18 — zero vector
//
// Output/Returns:
//   v0 - the reduced 128-bit product
//
// Clobbered Registers:
//   v2-v7
//
// Stack Usage:
//   0 bytes - leaf function, no stack frame
// ─────────────────────────────────────────────────────────────────────
.Lgcm_gf_mul:
    ext     v2.16b, v0.16b, v0.16b, #8 // rol64(A)
    eor     v2.16b, v2.16b, v0.16b     // v2 = [a_lo⊕a_hi, a_lo⊕a_hi]
    ext     v3.16b, v1.16b, v1.16b, #8 // rol64(B)
    eor     v3.16b, v3.16b, v1.16b     // v3 = [b_lo⊕b_hi, b_lo⊕b_hi]
    pmull   v4.1q, v0.1d, v1.1d        // lo = a_lo·b_lo (bits 0..127)
    pmull2  v5.1q, v0.2d, v1.2d        // hi = a_hi·b_hi (bits 128..255)
    pmull   v6.1q, v2.1d, v3.1d        // m = (a_lo⊕a_hi)·(b_lo⊕b_hi)
    eor     v2.16b, v6.16b, v4.16b     // m ⊕ lo
    eor     v2.16b, v2.16b, v5.16b     // mid = m ⊕ lo ⊕ hi
    ext     v6.16b, v18.16b, v2.16b, #8  // mid[0..63] at bits 64..127
    ext     v7.16b, v2.16b, v18.16b, #8  // mid[64..127] at bits 0..63
    eor     v4.16b, v4.16b, v6.16b     // P_lo = lo ⊕ mid·x^64
    eor     v5.16b, v5.16b, v7.16b     // P_hi = hi ⊕ mid/x^64
    // ── reduction: P mod (x^128+x^7+x^2+x+1), constant 0x87 ──
    // x^128 ≡ x^7+x^2+x+1, so every set bit j of P_hi contributes to
    // positions j, j+1, j+2, j+7 of the result.
    pmull   v2.1q, v5.1d, v17.1d       // P_hi[0..63]·0x87 → positions 0..70
    eor     v4.16b, v4.16b, v2.16b     // fold 1
    pmull2  v2.1q, v5.2d, v17.2d       // P_hi[64..127]·0x87 → bits 0..70
    ext     v6.16b, v18.16b, v2.16b, #8  // bits 0..63 → positions 64..127
    eor     v4.16b, v4.16b, v6.16b     // fold 2
    ext     v3.16b, v2.16b, v2.16b, #8   // spill (bits 64..70) → bits 0..6
    pmull   v3.1q, v3.1d, v17.1d       // spill·0x87 → positions 0..13
    eor     v4.16b, v4.16b, v3.16b     // fold 3
    mov     v0.16b, v4.16b
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lgcm_ghash_run (private)
//
// Description: Folds nbytes of GCM wire-order data at x27 into the GHASH
//   accumulator v20: each 16-byte block is bit-reversed into the natural
//   domain, XORed into Y', and multiplied by H' (v19). A trailing
//   partial block is zero-padded in a private 16-byte stack buffer.
//
// Input/Arguments:
//   x27 — pointer to the data
//   x28 — byte count (any value; 0 is a no-op)
//   v16 — nibble table, v17 — 0x87 constant, v18 — zero
//   v19 — H' (natural domain), v20 — running Y' accumulator
//   (v1 is loaded with H' on entry: .Lgcm_gf_mul multiplies v0 by v1)
//
// Output/Returns:
//   v20 - the updated accumulator
//
// Clobbered Registers:
//   x9-x12, x30, v0-v7 (x19-x28 and v16-v21 are preserved)
//
// Stack Usage:
//   32 bytes - 16 for the zero-padded partial block, 8 for x30, 8 slack
// ─────────────────────────────────────────────────────────────────────
.Lgcm_ghash_run:
    sub     sp, sp, #32
    str     x30, [sp, #16]
    mov     v1.16b, v19.16b           // gf_mul reads its multiplier from v1
    add     x12, sp, #0                // pad buffer (16 bytes, zeroed)
    stp     xzr, xzr, [x12]
    lsr     x9, x28, #4                // full blocks
    and     x10, x28, #0xf             // trailing bytes
    cbz     x9, .Lgcm_ghash_run_tail
.Lgcm_ghash_run_loop:
    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b            // into the natural domain
    eor     v0.16b, v0.16b, v20.16b    // Y ⊕ X
    bl      .Lgcm_gf_mul               // (Y ⊕ X)·H'
    mov     v20.16b, v0.16b
    subs    x9, x9, #1
    b.ne    .Lgcm_ghash_run_loop
.Lgcm_ghash_run_tail:
    cbz     x10, .Lgcm_ghash_run_done
    mov     x9, #0
.Lgcm_ghash_run_tailcopy:
    ldrb    w11, [x27, x9]             // copy the partial block
    strb    w11, [x12, x9]
    add     x9, x9, #1
    cmp     x9, x10
    b.ne    .Lgcm_ghash_run_tailcopy
    ld1     {v0.16b}, [x12]            // zero-padded block
    gcm_rbit v0.16b, v0.16b
    eor     v0.16b, v0.16b, v20.16b
    bl      .Lgcm_gf_mul
    mov     v20.16b, v0.16b
.Lgcm_ghash_run_done:
    ldr     x30, [sp, #16]
    add     sp, sp, #32
    ret

// ---- Nibble-reversal table: T[i] = bit-reversed 4-bit value i ----
.align 4
.Lgcm_rbit_table:
.byte 0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e
.byte 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f
