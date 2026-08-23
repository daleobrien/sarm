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
// Function Name: .Lgcm_karatsuba_br (private, leaf)
//
// Description: Unreduced half of GF(2^128) multiplication: computes the
//   256-bit Karatsuba product A·B (natural domain) but does NOT reduce
//   it mod (x^128+x^7+x^2+x+1) — that is left to .Lgcm_reduce87, so that
//   several products can be XOR-accumulated in their unreduced 256-bit
//   form and reduced once. This is the same three-PMULL Karatsuba step
//   as .Lgcm_gf_mul (data.S:79-92), except the caller supplies
//   B's "rolled" cross term (b_lo⊕b_hi, replicated across both lanes)
//   directly in v3 instead of it being recomputed here — valid because
//   every call site multiplies a variable block by a *fixed* precomputed
//   power of H, so B (and therefore its rolled form) never changes
//   across loop iterations and is worth hoisting out.
//
// Input/Arguments:
//   v0  — multiplicand A (natural domain, varies per call)
//   v1  — multiplier B (natural domain, a fixed power of H)
//   v3  — precomputed rol64(B) ⊕ B, replicated across both 64-bit lanes
//   v18 — zero vector
//
// Output/Returns:
//   v4 — P_lo (bits 0..127 of the unreduced 256-bit product)
//   v5 — P_hi (bits 128..255 of the unreduced 256-bit product)
//
// Clobbered Registers:
//   v2, v4-v7
//
// Stack Usage:
//   0 bytes - leaf function, no stack frame
// ─────────────────────────────────────────────────────────────────────
.Lgcm_karatsuba_br:
    ext     v2.16b, v0.16b, v0.16b, #8 // rol64(A)
    eor     v2.16b, v2.16b, v0.16b     // v2 = [a_lo⊕a_hi, a_lo⊕a_hi]
    pmull   v4.1q, v0.1d, v1.1d        // lo = a_lo·b_lo (bits 0..127)
    pmull2  v5.1q, v0.2d, v1.2d        // hi = a_hi·b_hi (bits 128..255)
    pmull   v6.1q, v2.1d, v3.1d        // m = (a_lo⊕a_hi)·(b_lo⊕b_hi)
    eor     v2.16b, v6.16b, v4.16b     // m ⊕ lo
    eor     v2.16b, v2.16b, v5.16b     // mid = m ⊕ lo ⊕ hi
    ext     v6.16b, v18.16b, v2.16b, #8  // mid[0..63] at bits 64..127
    ext     v7.16b, v2.16b, v18.16b, #8  // mid[64..127] at bits 0..63
    eor     v4.16b, v4.16b, v6.16b     // P_lo = lo ⊕ mid·x^64
    eor     v5.16b, v5.16b, v7.16b     // P_hi = hi ⊕ mid/x^64
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lgcm_reduce87 (private, leaf)
//
// Description: Reduces an unreduced 256-bit GF(2^128) product (as
//   produced by .Lgcm_karatsuba_br, or by summing several such products)
//   mod (x^128+x^7+x^2+x+1). Identical to the reduction half of
//   .Lgcm_gf_mul (data.S:93-104), split out so it can be applied once to
//   an XOR-sum of several unreduced products instead of once per product
//   — valid because reduction is linear over GF(2): reduce(a) ⊕
//   reduce(b) == reduce(a ⊕ b) (proved in
//   scripts/prompts/ghash_pmull_proto.py, "accumulate-then-reduce-once
//   == reduce-then-sum").
//
// Input/Arguments:
//   v4  — P_lo (bits 0..127 of the unreduced product, or XOR-sum thereof)
//   v5  — P_hi (bits 128..255, or XOR-sum thereof)
//   v17 — [0x87, 0x87] reduction constant
//   v18 — zero vector
//
// Output/Returns:
//   v0 - the reduced 128-bit result
//
// Clobbered Registers:
//   v2, v3, v4, v6
//
// Stack Usage:
//   0 bytes - leaf function, no stack frame
// ─────────────────────────────────────────────────────────────────────
.Lgcm_reduce87:
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
// Function Name: .Lgcm_ghash_powers (private)
//
// Description: Derives the GHASH subkey powers .Lgcm_ghash_run's
//   4-block aggregation needs — H^2, H^3, H^4, and the rolled cross
//   term rol64(H^k) ⊕ H^k that .Lgcm_karatsuba_br takes in v3 — from
//   H' in v19.
//
//   This used to live at the top of .Lgcm_ghash_run, computed lazily on
//   any call that had four or more blocks to fold. That is once per
//   record on the live path, three chained GF(2^128) multiplies deep,
//   for values that are a pure function of H — and therefore of the
//   key. It is a helper now so that both callers can decide when to pay
//   for it: aes_gcm_ctx_init runs it once per epoch and stores the
//   results in the key context, and ghash (test-only) runs it inline.
//
// Input/Arguments:
//   v19 — H' (natural domain)
//   v17 — the 0x87 reduction constant, v18 — zero (.Lgcm_gf_mul's)
//
// Output/Returns:
//   v22 — H'^2, v23 — H'^3, v24 — H'^4
//   v25..v28 — the rolled cross terms of H'^1..H'^4, in that order
//
// Clobbered Registers:
//   v0-v7, v22-v28
//
// Stack Usage:
//   16 bytes - 8 for x30, 8 slack
// ─────────────────────────────────────────────────────────────────────
.Lgcm_ghash_powers:
    sub     sp, sp, #16
    str     x30, [sp]
    mov     v0.16b, v19.16b
    mov     v1.16b, v19.16b
    bl      .Lgcm_gf_mul                // v0 = H^2
    mov     v22.16b, v0.16b
    mov     v1.16b, v19.16b
    bl      .Lgcm_gf_mul                // v0 = H^2·H = H^3
    mov     v23.16b, v0.16b
    mov     v1.16b, v19.16b
    bl      .Lgcm_gf_mul                // v0 = H^3·H = H^4
    mov     v24.16b, v0.16b

    ext     v25.16b, v19.16b, v19.16b, #8
    eor     v25.16b, v25.16b, v19.16b   // BR(H^1)
    ext     v26.16b, v22.16b, v22.16b, #8
    eor     v26.16b, v26.16b, v22.16b   // BR(H^2)
    ext     v27.16b, v23.16b, v23.16b, #8
    eor     v27.16b, v27.16b, v23.16b   // BR(H^3)
    ext     v28.16b, v24.16b, v24.16b, #8
    eor     v28.16b, v28.16b, v24.16b   // BR(H^4)
    ldr     x30, [sp]
    add     sp, sp, #16
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lgcm_ghash_run (private)
//
// Description: Folds nbytes of GCM wire-order data at x27 into the GHASH
//   accumulator v20: each 16-byte block is bit-reversed into the natural
//   domain, XORed into Y', and multiplied by H' (v19). A trailing
//   partial block is zero-padded in a private 16-byte stack buffer.
//
//   When at least 4 full blocks remain, they are processed 4 at a time
//   via aggregated Horner evaluation (docs/HISTORY.md):
//   given Y and blocks X1..X4,
//
//       Y' = (Y⊕X1)·H^4 ⊕ X2·H^3 ⊕ X3·H^2 ⊕ X4·H^1
//
//   which is algebraically identical to four sequential
//   multiply-then-reduce steps (proved in
//   scripts/prompts/ghash_proto.py) but has only ONE cross-iteration
//   dependency (the Y⊕X1 term) instead of four — the other three terms
//   depend only on freshly loaded, independent block data, so their
//   PMULL chains are free to overlap with each other and with the
//   previous iteration's tail on real hardware. All four unreduced
//   products are XOR-accumulated and reduced exactly once per 4 blocks
//   instead of once per block (reduction is linear — see
//   .Lgcm_reduce87). H^2..H^4 and their rolled cross terms are
//   supplied by the caller in v22-v28 (.Lgcm_ghash_powers), which is
//   what lets a connection derive them once per epoch rather than once
//   per record — they depend only on H. Calls with fewer than 4 blocks
//   (the common case for AAD and the fixed 16-byte length block) never
//   look at them and take the one-block-at-a-time path unchanged.
//
// Input/Arguments:
//   x27 — pointer to the data
//   x28 — byte count (any value; 0 is a no-op)
//   v16 — nibble table, v17 — 0x87 constant, v18 — zero
//   v19 — H' (natural domain), v20 — running Y' accumulator
//   v22-v24 — H'^2, H'^3, H'^4; v25-v28 — their rolled cross terms and
//   H's, as .Lgcm_ghash_powers leaves them. Only read when four or more
//   blocks remain, but the caller cannot know that in advance, so they
//   must be live across every call.
//   (v1 is loaded with H' on entry: .Lgcm_gf_mul multiplies v0 by v1)
//
// Output/Returns:
//   v20 - the updated accumulator
//
// Clobbered Registers:
//   x9-x12, x27, v0-v7, v29, v30 (x19-x26, x28, v16-v21 and the
//   caller's v22-v28 powers are preserved)
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
    cmp     x9, #4
    b.lt    .Lgcm_ghash_run_loop
    // ≥4 blocks: H^2..H^4 and the rolled cross terms are already in
    // v22-v28, courtesy of .Lgcm_ghash_powers.
.Lgcm_ghash_run4_loop:
    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b            // X1 into the natural domain
    eor     v0.16b, v0.16b, v20.16b    // Y ⊕ X1 -- the one term that
    mov     v1.16b, v24.16b            // depends on the previous
    mov     v3.16b, v28.16b            // iteration's accumulator
    bl      .Lgcm_karatsuba_br         // v4/v5 = (Y⊕X1)·H^4, unreduced
    mov     v29.16b, v4.16b            // acc_lo
    mov     v30.16b, v5.16b            // acc_hi

    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b            // X2 -- independent of Y
    mov     v1.16b, v23.16b
    mov     v3.16b, v27.16b
    bl      .Lgcm_karatsuba_br         // v4/v5 = X2·H^3, unreduced
    eor     v29.16b, v29.16b, v4.16b
    eor     v30.16b, v30.16b, v5.16b

    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b            // X3 -- independent of Y
    mov     v1.16b, v22.16b
    mov     v3.16b, v26.16b
    bl      .Lgcm_karatsuba_br         // v4/v5 = X3·H^2, unreduced
    eor     v29.16b, v29.16b, v4.16b
    eor     v30.16b, v30.16b, v5.16b

    ld1     {v0.16b}, [x27], #16
    gcm_rbit v0.16b, v0.16b            // X4 -- independent of Y
    mov     v1.16b, v19.16b
    mov     v3.16b, v25.16b
    bl      .Lgcm_karatsuba_br         // v4/v5 = X4·H^1, unreduced
    eor     v29.16b, v29.16b, v4.16b
    eor     v30.16b, v30.16b, v5.16b

    mov     v4.16b, v29.16b
    mov     v5.16b, v30.16b
    bl      .Lgcm_reduce87             // one reduction for all 4 blocks
    mov     v20.16b, v0.16b

    sub     x9, x9, #4
    cmp     x9, #4
    b.ge    .Lgcm_ghash_run4_loop

    mov     v1.16b, v19.16b            // restore gf_mul's multiplier for
    cbz     x9, .Lgcm_ghash_run_tail   // the scalar remainder/tail below
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lgcm_ghash_lengths (private)
//
// Description: Folds GCM's final length block — [len(A)]_64 ||
//   [len(C)]_64, the two lengths as big-endian *bit* counts (NIST SP
//   800-38D §6.4) — into the GHASH accumulator v20, closing the hash
//   over A || 0^pad || C || 0^pad || lengths.
//
//   This is the last thing every GCM tag computation does, and it used
//   to be written out three times: in aes_gcm_encrypt, in
//   aes_gcm_decrypt, and in ghash. All three are swept against an
//   independent reference, so any one of them drifting alone would be
//   caught — what the duplication cost was not detection but leverage:
//   a fix, or a mistake, in one copy reached only that copy, and the
//   three had already diverged in scratch offsets and register choice.
//   There is now one length block, and one edit to it is felt by all
//   three sweeps at once (docs/SECURITY.md §14 A2).
//
//   The 16-byte block lives in this function's own frame rather than
//   the caller's. Nothing outside needs it — it is written, hashed and
//   dead within these few instructions — so it should not be occupying
//   a named slot in three separate stack layouts.
//
// Input/Arguments:
//   x9  — AAD length in bytes
//   x10 — ciphertext length in bytes
//   plus the state .Lgcm_ghash_run reads: v16 nibble table, v17 the
//   0x87 constant, v18 zero, v19 H', v20 the running accumulator, and
//   the v22-v28 subkey powers
//
// Output/Returns:
//   v20 - the accumulator, with the length block folded in
//
// Clobbered Registers:
//   x9-x12, x27, x28, v0-v7, v29, v30 (x19-x26 and the caller's v22-v28
//   powers are preserved)
//
// Stack Usage:
//   32 bytes - 16 for the length block, 8 for x30, 8 slack
// ─────────────────────────────────────────────────────────────────────
.Lgcm_ghash_lengths:
    sub     sp, sp, #32
    str     x30, [sp, #16]
    lsl     x9, x9, #3                 // bytes -> bits
    rev     x9, x9                     // ... big-endian
    str     x9, [sp]
    lsl     x10, x10, #3
    rev     x10, x10
    str     x10, [sp, #8]
    mov     x27, sp                    // the block is one full,
    mov     x28, #16                   //   16-byte GHASH block
    bl      .Lgcm_ghash_run
    ldr     x30, [sp, #16]
    add     sp, sp, #32
    ret

// ---- Nibble-reversal table: T[i] = bit-reversed 4-bit value i ----
.align 4
.Lgcm_rbit_table:
.byte 0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e
.byte 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07, 0x0f
