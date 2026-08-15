// AES-128-GCM authenticated decryption

#include "data.S"

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

.text
.align 2
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
