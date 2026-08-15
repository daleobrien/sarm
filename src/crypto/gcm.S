// ====================================================================
// ARM64 (AArch64) AES-GCM Implementation for ymawky (PLAN.MD Phase 7)
// File: gcm.S
//
//   gf_mult_128     — GF(2^128) multiplication (NIST SP 800-38D §6.3)
//   ghash           — GHASH over AAD || ciphertext || bit-lengths (§6.4)
//   aes_gcm_encrypt — AES-128-GCM seal, 96-bit IV (the TLS 1.3 nonce)
//   aes_gcm_decrypt — AES-128-GCM open; the tag is verified in constant
//                     time *before* any plaintext is written (§7.4)
//
// ── Design: GHASH on the ARMv8 Crypto Extensions ─────────────────────
// GCM multiplies in GF(2^128) with reduction polynomial
//     x^128 + x^7 + x^2 + x + 1.
// The wire representation stores the coefficient vector MSB-first within
// each byte: byte 0's MSB is the coefficient of x^0 and byte 15's LSB is
// the coefficient of x^127 (the famous "bit-reflected" GCM byte order).
// The ARMv8 PMULL instruction, by contrast, wants bit i of the register
// to be the coefficient of x^i. The two conventions differ by exactly a
// bit-reversal of each byte, so every block (and H) is mapped with a
// tiny nibble lookup table (gcm_rbit, 6 instructions per 16 bytes):
//
//     rbit_byte(b) = T[b >> 4] | (T[b & 0xf] << 4),  T = nibble reversal
//
// The whole GHASH then runs in the natural polynomial domain, where a
// 128×128 product is three Karatsuba PMULLs (PMULL only multiplies the
// matching 64-bit lanes, so a_lo·b_hi ⊕ a_hi·b_lo is folded into the
// middle product (a_lo⊕a_hi)·(b_lo⊕b_hi)) and the reduction
//     x^128 ≡ x^7 + x^2 + x + 1
// is a two-step fold of the high half by the constant 0x87 (three PMULLs
// and two EXT shuffles). The final accumulator is bit-reversed back to
// wire order before it is XORed into the tag. H is transformed once per
// key; per block the transform costs one table lookup.
//
// All scratch state lives on the stack: the functions are re-entrant and
// need no global context beyond the read-only nibble table below.
//
// Exported Symbols:
//   gf_mult_128      — one-shot GF(2^128) multiply (doc block below)
//   ghash            — one-shot GHASH of the GCM input string (below)
//   aes_gcm_encrypt  — one-shot seal (doc block below)
//   aes_gcm_decrypt  — one-shot open with constant-time tag check (below)
//
// ====================================================================

#include "../defs.S"

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
// Function Name: gf_mult_128
//
// Description: Z = X·Y in GF(2^128) (NIST SP 800-38D §6.3) — the basis
//   for GHASH (PLAN.MD 7.1). X, Y and Z are 16-byte blocks in GCM wire
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
//   x0-x2, x9, x10, x30, v0-v7, v16-v18, v21, NZCV
//
// Stack Usage:
//   16 bytes (x30)
// ─────────────────────────────────────────────────────────────────────
.global gf_mult_128
gf_mult_128:
    sub     sp, sp, #16
    str     x30, [sp]

    // GHASH constants: v16 = nibble table, v17 = [0x87,0x87], v18 = 0,
    // v21 = 0x0f byte mask
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: ghash
//
// Description: GHASH (NIST SP 800-38D §6.4) of the GCM input string
//   A || 0^pad || C || 0^pad || [len(A)]_64 || [len(C)]_64 (bit lengths,
//   big-endian) — exactly the construction the GCM tag is built on
//   (PLAN.MD 7.2). H = E_K(0^128) must be supplied by the caller.
//
// Input/Arguments:
//   x0 — pointer to the 16-byte hash subkey H
//   x1 — pointer to the additional authenticated data (ignored when
//        aad_len == 0)
//   x2 — AAD length in bytes
//   x3 — pointer to the ciphertext (ignored when ct_len == 0)
//   x4 — ciphertext length in bytes
//   x5 — pointer to the 16-byte GHASH result buffer (must not overlap
//        the inputs)
//
// Output/Returns:
//   none (void) - 16 result bytes written to [x5]
//
// Clobbered Registers:
//   x0-x15, x19-x28 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   112 bytes - 88 for x19-x28 + x30, 16 for the bit-length block
// ─────────────────────────────────────────────────────────────────────
.global ghash
ghash:
    sub     sp, sp, #112
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    str     x30, [sp, #80]

    mov     x19, x0                    // h
    mov     x20, x1                    // aad
    mov     x21, x2                    // aad_len
    mov     x22, x3                    // ct
    mov     x23, x4                    // ct_len
    mov     x24, x5                    // out

    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    ld1     {v19.16b}, [x19]           // H
    gcm_rbit v19.16b, v19.16b          // H' in the natural domain
    movi    v20.16b, #0                // Y' = 0

    mov     x27, x20                   // feed AAD blocks
    mov     x28, x21
    bl      .Lgcm_ghash_run
    mov     x27, x22                   // feed ciphertext blocks
    mov     x28, x23
    bl      .Lgcm_ghash_run

    // [len(A)]_64 || [len(C)]_64, bit lengths, big-endian
    lsl     x9, x21, #3
    rev     x9, x9
    str     x9, [sp, #88]
    lsl     x9, x23, #3
    rev     x9, x9
    str     x9, [sp, #96]
    add     x27, sp, #88
    mov     x28, #16
    bl      .Lgcm_ghash_run

    gcm_rbit v20.16b, v0.16b           // back to GCM wire order
    st1     {v0.16b}, [x24]

    ldr     x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #112
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes_gcm_encrypt
//
// Description: AES-128-GCM seal (PLAN.MD 7.3): C = GCTR_K(J1..Jn, P) and
//   tag = GCTR_K(J0, GHASH_H(A, C)) with J0 = IV || 0^31 || 1 and a
//   96-bit (12-byte) IV — the TLS 1.3 nonce form. The ciphertext is
//   produced first, then hashed, so in-place operation (ct == pt) is
//   safe. The tag is always 16 bytes.
//
// Input/Arguments:
//   x0 — pointer to the 16-byte AES-128 key
//   x1 — pointer to the 12-byte IV/nonce
//   x2 — pointer to the AAD (ignored when aad_len == 0)
//   x3 — AAD length in bytes
//   x4 — pointer to the plaintext (ignored when pt_len == 0)
//   x5 — plaintext length in bytes
//   x6 — pointer to the ciphertext output buffer (pt_len bytes; may
//        alias the plaintext)
//   x7 — pointer to the 16-byte authentication tag output buffer
//
// Output/Returns:
//   none (void) - pt_len ciphertext bytes and the 16-byte tag written
//
// Clobbered Registers:
//   x0-x12, x19-x28 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   352 bytes - 88 for x19-x28 + x30 (+1 slot), 176 round keys, and the
//   16-byte H / counter / tag mask / keystream / length-block scratch
// ─────────────────────────────────────────────────────────────────────
.global aes_gcm_encrypt
aes_gcm_encrypt:
    sub     sp, sp, #352
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    str     x30, [sp, #80]

    mov     x19, x2                    // aad
    mov     x20, x3                    // aad_len
    mov     x21, x4                    // pt
    mov     x22, x5                    // pt_len
    mov     x23, x6                    // ct
    mov     x24, x7                    // tag out
    mov     x27, x1                    // iv (12 bytes)
    str     x6, [sp, #88]              // ct start (GHASH reads it later)
    add     x25, sp, #288              // jbuf (counter block)
    add     x26, sp, #96               // rk (176-byte round keys)

    // ── GHASH constants ──
    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    // ── H = E_K(0^128), mapped into the natural domain (v19) ──
    add     x9, sp, #320               // pad = the zero block
    stp     xzr, xzr, [x9]
    mov     x1, x26
    bl      aes128_key_expand          // x0 = key, x1 = rk
    mov     x0, x9                     // zero block
    mov     x1, x26
    add     x2, sp, #272               // h
    bl      aes128_encrypt
    add     x9, sp, #272
    ld1     {v19.16b}, [x9]
    gcm_rbit v19.16b, v19.16b          // H' (natural domain)

    // ── J0 = IV || 0x00000001; tag mask = E_K(J0) ──
    ldr     x9, [x27]                  // IV[0..8)
    str     x9, [x25]
    ldr     w9, [x27, #8]              // IV[8..12)
    str     w9, [x25, #8]
    str     wzr, [x25, #12]            // counter bytes 12..15 = 0
    mov     w9, #1
    strb    w9, [x25, #15]             // ...0001
    mov     x0, x25
    mov     x1, x26
    add     x2, sp, #304               // tagmask
    bl      aes128_encrypt

    // ── CTR: C_i = P_i ⊕ E_K(J0+i), i = 1, 2, ... ──
    gcm_inc32 x25                      // J0 -> J1
    lsr     x28, x22, #4               // full 16-byte blocks
    and     x27, x22, #0xf             // trailing partial-block bytes
    cbz     x28, .Lgcm_enc_tail
.Lgcm_enc_blockloop:
    mov     x0, x25                    // counter block
    mov     x1, x26
    add     x2, sp, #320               // keystream block
    bl      aes128_encrypt
    ld1     {v0.16b}, [x21], #16       // plaintext block
    add     x9, sp, #320
    ld1     {v1.16b}, [x9]
    eor     v0.16b, v0.16b, v1.16b
    st1     {v0.16b}, [x23], #16       // ciphertext block
    gcm_inc32 x25
    subs    x28, x28, #1
    b.ne    .Lgcm_enc_blockloop
.Lgcm_enc_tail:
    cbz     x27, .Lgcm_enc_ghash
    mov     x0, x25
    mov     x1, x26
    add     x2, sp, #320
    bl      aes128_encrypt
    mov     x28, #0
.Lgcm_enc_tailloop:
    ldrb    w9, [x21, x28]             // partial block, byte by byte
    add     x10, sp, #320
    ldrb    w10, [x10, x28]
    eor     w9, w9, w10
    strb    w9, [x23, x28]
    add     x28, x28, #1
    cmp     x28, x27
    b.ne    .Lgcm_enc_tailloop

    // ── tag = E_K(J0) ⊕ GHASH_H(A || C || lengths) ──
.Lgcm_enc_ghash:
    movi    v20.16b, #0                // Y' = 0
    mov     x27, x19                   // AAD
    mov     x28, x20
    bl      .Lgcm_ghash_run
    ldr     x27, [sp, #88]             // ciphertext (now fully written)
    mov     x28, x22
    bl      .Lgcm_ghash_run
    lsl     x9, x20, #3                // [len(A)]_64 || [len(C)]_64
    rev     x9, x9
    str     x9, [sp, #336]
    lsl     x9, x22, #3
    rev     x9, x9
    str     x9, [sp, #344]
    add     x27, sp, #336
    mov     x28, #16
    bl      .Lgcm_ghash_run

    gcm_rbit v20.16b, v0.16b           // Y' back to GCM wire order
    add     x9, sp, #304
    ld1     {v1.16b}, [x9]             // tag mask E_K(J0)
    eor     v0.16b, v0.16b, v1.16b
    st1     {v0.16b}, [x24]            // write the tag

    ldr     x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #352
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes_gcm_decrypt
//
// Description: AES-128-GCM open (PLAN.MD 7.4/7.5). The authentication
//   tag is recomputed over the received AAD and ciphertext and compared
//   with the supplied tag in constant time; only on a match is the
//   plaintext decrypted into the output buffer. On failure the plaintext
//   buffer is left untouched and 0 is returned. The IV is 12 bytes and
//   the tag 16 bytes.
//
// Input/Arguments:
//   x0 — pointer to the 16-byte AES-128 key
//   x1 — pointer to the 12-byte IV/nonce
//   x2 — pointer to the AAD (ignored when aad_len == 0)
//   x3 — AAD length in bytes
//   x4 — pointer to the received ciphertext (ignored when ct_len == 0)
//   x5 — ciphertext length in bytes
//   x6 — pointer to the 16-byte received tag
//   x7 — pointer to the plaintext output buffer (ct_len bytes; may
//        alias the ciphertext — but see the "no plaintext on failure"
//        guarantee below)
//
// Output/Returns:
//   x0 — 1 if the tag verified (plaintext written), 0 otherwise
//
// Clobbered Registers:
//   x0-x12, x19-x28 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   352 bytes — same layout as aes_gcm_encrypt
// ─────────────────────────────────────────────────────────────────────
.global aes_gcm_decrypt
aes_gcm_decrypt:
    sub     sp, sp, #352
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    str     x30, [sp, #80]

    mov     x19, x2                    // aad
    mov     x20, x3                    // aad_len
    mov     x21, x4                    // ct
    mov     x22, x5                    // ct_len
    mov     x23, x6                    // supplied tag
    mov     x24, x7                    // pt out
    mov     x27, x1                    // iv (12 bytes)
    add     x25, sp, #288              // jbuf
    add     x26, sp, #96               // rk

    // ── GHASH constants ──
    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    // ── H = E_K(0^128), mapped into the natural domain (v19) ──
    add     x9, sp, #320               // pad = the zero block
    stp     xzr, xzr, [x9]
    mov     x1, x26
    bl      aes128_key_expand          // x0 = key, x1 = rk
    mov     x0, x9
    mov     x1, x26
    add     x2, sp, #272               // h
    bl      aes128_encrypt
    add     x9, sp, #272
    ld1     {v19.16b}, [x9]
    gcm_rbit v19.16b, v19.16b          // H' (natural domain)

    // ── J0 = IV || 0x00000001; tag mask = E_K(J0) ──
    ldr     x9, [x27]                  // IV[0..8)
    str     x9, [x25]
    ldr     w9, [x27, #8]              // IV[8..12)
    str     w9, [x25, #8]
    str     wzr, [x25, #12]
    mov     w9, #1
    strb    w9, [x25, #15]
    mov     x0, x25
    mov     x1, x26
    add     x2, sp, #304               // tagmask
    bl      aes128_encrypt

    // ── recompute the tag BEFORE any decryption ──
    movi    v20.16b, #0                // Y' = 0
    mov     x27, x19                   // AAD
    mov     x28, x20
    bl      .Lgcm_ghash_run
    mov     x27, x21                   // received ciphertext
    mov     x28, x22
    bl      .Lgcm_ghash_run
    lsl     x9, x20, #3                // [len(A)]_64 || [len(C)]_64
    rev     x9, x9
    str     x9, [sp, #336]
    lsl     x9, x22, #3
    rev     x9, x9
    str     x9, [sp, #344]
    add     x27, sp, #336
    mov     x28, #16
    bl      .Lgcm_ghash_run

    // ── constant-time tag comparison ──
    // computed = E_K(J0) ⊕ rbit(Y'); the sum over the 16 difference
    // bytes is zero iff the tags match, and no branch depends on the
    // data until every byte has been compared.
    gcm_rbit v20.16b, v0.16b           // Y' back to GCM wire order
    add     x9, sp, #304
    ld1     {v1.16b}, [x9]             // tag mask
    eor     v0.16b, v0.16b, v1.16b     // computed tag
    ld1     {v1.16b}, [x23]            // supplied tag
    eor     v0.16b, v0.16b, v1.16b     // difference
    uaddlv  h2, v0.16b
    umov    w9, v2.h[0]
    cbnz    w9, .Lgcm_dec_fail

    // ── tag verified: P_i = C_i ⊕ E_K(J0+i), i = 1, 2, ... ──
    gcm_inc32 x25                      // J0 -> J1
    lsr     x28, x22, #4
    and     x27, x22, #0xf
    cbz     x28, .Lgcm_dec_tail
.Lgcm_dec_blockloop:
    mov     x0, x25
    mov     x1, x26
    add     x2, sp, #320               // keystream block
    bl      aes128_encrypt
    ld1     {v0.16b}, [x21], #16       // ciphertext block
    add     x9, sp, #320
    ld1     {v1.16b}, [x9]
    eor     v0.16b, v0.16b, v1.16b
    st1     {v0.16b}, [x24], #16       // plaintext block
    gcm_inc32 x25
    subs    x28, x28, #1
    b.ne    .Lgcm_dec_blockloop
.Lgcm_dec_tail:
    cbz     x27, .Lgcm_dec_ok
    mov     x0, x25
    mov     x1, x26
    add     x2, sp, #320
    bl      aes128_encrypt
    mov     x28, #0
.Lgcm_dec_tailloop:
    ldrb    w9, [x21, x28]
    add     x10, sp, #320
    ldrb    w10, [x10, x28]
    eor     w9, w9, w10
    strb    w9, [x24, x28]
    add     x28, x28, #1
    cmp     x28, x27
    b.ne    .Lgcm_dec_tailloop
.Lgcm_dec_ok:
    mov     x0, #1
    b       .Lgcm_dec_ret
.Lgcm_dec_fail:
    mov     x0, #0                     // plaintext buffer untouched
.Lgcm_dec_ret:
    ldr     x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #352
    ret

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
