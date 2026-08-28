// GCM helper functions, macros, and constants

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Macro: gcm_rbit
//
// Description: Per-byte bit reversal of a 16-byte vector (see the file
//   header for why GCM needs this) — which is precisely what the RBIT
//   instruction does, one instruction, no operands but its own.
//
//   This used to be a six-instruction nibble-lookup: two TBLs against a
//   16-byte reversal table in v16, masked with 0x0f in v21, with a
//   four-deep serial dependency between them. The two spellings agree on
//   all 256 byte values — the equivalence is a table, and it was checked
//   exhaustively rather than argued. RBIT Vd.16b is baseline Armv8.0
//   ASIMD (it needs no -march extension and no runtime feature check), so
//   the lookup was buying nothing on any machine that can run the PMULL
//   this file is built around.
//
//   Dropping it frees v16 and v21 — every caller used to spend four
//   instructions on entry loading a table and a mask that only this
//   macro read — and leaves v2/v3 alone, which the old body clobbered.
//   The operands keep their element qualifier and their order, e.g.
//   gcm_rbit v0.16b, v0.16b, so no call site changes.
//
// Input/Arguments:
//   \src — source operand (full "vN.16b" form)
//   \dst — destination operand (full "vN.16b" form; may alias \src)
//
// Clobbered Registers:
//   none beyond \dst
// ─────────────────────────────────────────────────────────────────────
.macro gcm_rbit src, dst
    rbit    \dst, \src
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

// ── inline AES-128 round scheduling for the CTR keystream ────────────
// The round keys sit in v16-v26 (RK0..RK10) for the whole CTR section,
// loaded once per record rather than once per block. `bl aes128_encrypt`
// per block reloaded all 176 bytes every time: on a Neoverse-N1 profile
// of an HTTP/2-over-TLS load that single `ld1` of the schedule was 77% of
// aes128_encrypt's samples, and the pair was 12.3% of all cycles.
//
// AESE/AESMC are 2-cycle-latency, ~1-per-cycle-throughput on N1, so a
// single serial block chain leaves most of the crypto unit idle. Four
// independent chains fill it for very nearly the cost of one. Each
// `aese vN` stays immediately in front of its `aesmc vN` so the
// fused-pair optimisation in the pipeline still fires.

.macro aes_round4 rk
    aese    v0.16b, \rk\().16b
    aesmc   v0.16b, v0.16b
    aese    v1.16b, \rk\().16b
    aesmc   v1.16b, v1.16b
    aese    v2.16b, \rk\().16b
    aesmc   v2.16b, v2.16b
    aese    v3.16b, \rk\().16b
    aesmc   v3.16b, v3.16b
.endm

// Nine full rounds (RK0..RK8), then round 10: AESE with RK9 and a plain
// XOR of RK10, which is FIPS-197's final round without MixColumns.
.macro aes_block4
    aes_round4 v16
    aes_round4 v17
    aes_round4 v18
    aes_round4 v19
    aes_round4 v20
    aes_round4 v21
    aes_round4 v22
    aes_round4 v23
    aes_round4 v24
    aese    v0.16b, v25.16b
    eor     v0.16b, v0.16b, v26.16b
    aese    v1.16b, v25.16b
    eor     v1.16b, v1.16b, v26.16b
    aese    v2.16b, v25.16b
    eor     v2.16b, v2.16b, v26.16b
    aese    v3.16b, v25.16b
    eor     v3.16b, v3.16b, v26.16b
.endm

// One block, same schedule, for the 0-3 leftover blocks and the tail.
.macro aes_block1 st
    aese    \st\().16b, v16.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v17.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v18.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v19.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v20.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v21.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v22.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v23.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v24.16b
    aesmc   \st\().16b, \st\().16b
    aese    \st\().16b, v25.16b
    eor     \st\().16b, \st\().16b, v26.16b
.endm

// Build one counter block: the 12-byte IV is invariant across the record
// and stays in the template v27; only the big-endian 32-bit counter in
// lane 3 changes. \ctr is a *w* register — the +1/+2/+3 offsets its
// callers pass must be 32-bit adds so they wrap at 2^32 exactly like
// SP 800-38D inc32 (and like the gcm_inc32 this replaces). A 64-bit add
// would silently diverge on the wrapping record.
.macro gcm_ctr_block dst, ctr
    rev     w9, \ctr
    mov     \dst\().16b, v27.16b
    mov     \dst\().s[3], w9
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
    // positions j, j+1, j+2, j+7 of the result. Two phases, each
    // retiring 64 bits of P_hi: see .Lgcm_reduce87 for why this is
    // shorter than folding the three contributions separately.
    pmull2  v2.1q, v5.2d, v17.2d       // P_hi[64..127]·0x87
    ext     v3.16b, v18.16b, v5.16b, #8  // P_hi[0..63] → positions 64..127
    eor     v3.16b, v3.16b, v2.16b     // phase 1: 64 bits of P_hi retired
    pmull2  v2.1q, v3.2d, v17.2d       // and again on what is left
    ext     v6.16b, v18.16b, v3.16b, #8
    eor     v4.16b, v4.16b, v6.16b     // phase 2: the rest, into P_lo
    eor     v0.16b, v4.16b, v2.16b
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
//   .Lgcm_gf_mul, split out so it can be applied once to an XOR-sum of
//   several unreduced products instead of once per product — valid
//   because reduction is linear over GF(2): reduce(a) ⊕ reduce(b) ==
//   reduce(a ⊕ b).
//
//   Two phases, not three folds. The obvious way to reduce is to take
//   the three places a set bit of P_hi lands (j, j+1, j+2, j+7 for the
//   low lane; the same shifted by 64 for the high lane; then the handful
//   of bits that spill past 128 on the way) and fold each separately —
//   nine instructions and three PMULLs, which is what this used to be.
//
//   Instead, each phase retires exactly 64 bits of P_hi: multiply the
//   high lane by 0x87, shift what remains up by 64, and XOR. Two phases
//   clear all 128 bits, and the spill the three-fold version handled
//   explicitly is simply part of the second phase's input. Seven
//   instructions and two PMULLs — and on Neoverse N1, PMULL is the
//   scarce port (one per cycle), so dropping one matters more than the
//   two instructions do.
//
//   Both forms are GF(2)-linear maps from 256 bits to 128, so "identical"
//   here is not a claim about test coverage: the two matrices were
//   compared column by column over all 256 basis vectors and agree
//   exactly. That is a proof over every input, and it is how this
//   replacement was arrived at — by searching the space of two-phase
//   shapes against the old map as an oracle, rather than by recalling a
//   constant.
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
    pmull2  v2.1q, v5.2d, v17.2d       // P_hi[64..127]·0x87
    ext     v3.16b, v18.16b, v5.16b, #8  // P_hi[0..63] → positions 64..127
    eor     v3.16b, v3.16b, v2.16b     // phase 1: 64 bits of P_hi retired
    pmull2  v2.1q, v3.2d, v17.2d       // and again on what is left
    ext     v6.16b, v18.16b, v3.16b, #8
    eor     v4.16b, v4.16b, v6.16b     // phase 2: the rest, into P_lo
    eor     v0.16b, v4.16b, v2.16b
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
//   v17 — 0x87 constant, v18 — zero
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
//   x9-x12, x27, v0-v7, v29, v30 (x19-x26, x28, v17-v21 and the
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
//   plus the state .Lgcm_ghash_run reads: v17 the 0x87 constant, v18
//   zero, v19 H', v20 the running accumulator, and
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
