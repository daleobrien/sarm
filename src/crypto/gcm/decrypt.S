// AES-128-GCM authenticated decryption

#include "data.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes_gcm_decrypt
//
// Description: AES-128-GCM open. The authentication
//   tag is recomputed over the received AAD and ciphertext and compared
//   with the supplied tag in constant time; only on a match is the
//   plaintext decrypted into the output buffer. On failure the plaintext
//   buffer is left untouched and 0 is returned. The IV is 12 bytes and
//   the tag 16 bytes.
//
//   Two entry points, mirroring aes_gcm_encrypt. aes_gcm_decrypt_ctx
//   takes a prebuilt key context (aes_gcm_ctx_init) holding the
//   round-key schedule and H, both key-derived; aes_gcm_decrypt keeps
//   the original key-pointer signature by building a context on its own
//   stack and falling through. Neither entry changes the tag check: the
//   comparison below is the same constant-time one, over the same
//   bytes, and the "no plaintext on failure" guarantee is unaffected —
//   the context holds only values an attacker-supplied record cannot
//   influence.
//
// Input/Arguments:
//   x0 — aes_gcm_decrypt_ctx: pointer to a GCM_CTX_SIZE-byte context
//        (aes_gcm_ctx_init); aes_gcm_decrypt: pointer to the 16-byte
//        AES-128 key
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
//   x0-x12, x19-x28 (saved/restored), x30 (saved/restored), v0-v11,
//   v16-v25, NZCV (v22-v25 via aes128_encrypt, which holds four round
//   keys there — this function's own live state stays in v16-v21)
//
// Stack Usage:
//   144 / 256 bytes — same layout as aes_gcm_encrypt
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global aes_gcm_decrypt
.global aes_gcm_decrypt_ctx

// ── key-pointer entry: build a one-shot context, then open with it ──
aes_gcm_decrypt:
    sub     sp, sp, #256
    str     x30, [sp, #192]
    stp     x1, x2, [sp, #200]         // aes_gcm_ctx_init clobbers
    stp     x3, x4, [sp, #216]         //   x0-x8, x10, x11 — every
    stp     x5, x6, [sp, #232]         //   argument but the key it is
    str     x7, [sp, #248]             //   about to consume
    mov     x1, sp                     // ctx at [sp, #0 .. #191]
    bl      aes_gcm_ctx_init           // x0 = key
    mov     x0, sp
    ldp     x1, x2, [sp, #200]
    ldp     x3, x4, [sp, #216]
    ldp     x5, x6, [sp, #232]
    ldr     x7, [sp, #248]
    bl      aes_gcm_decrypt_ctx        // x0 = 1 verified, 0 bad tag
    ldr     x30, [sp, #192]
    add     sp, sp, #256
    ret

aes_gcm_decrypt_ctx:
    sub     sp, sp, #144
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
    add     x25, sp, #96               // jbuf
    add     x26, x0, #GCM_CTX_RK       // rk

    // ── GHASH constants ──
    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    // ── H', already in the natural domain, out of the context ──
    // See aes_gcm_encrypt_ctx: expanding the key and encrypting a zero
    // block to recover H is per-key work, not per-record work.
    add     x9, x0, #GCM_CTX_H
    ld1     {v19.16b}, [x9]

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
    add     x2, sp, #112               // tagmask
    bl      aes128_encrypt

    // ── recompute the tag BEFORE any decryption ──
    movi    v20.16b, #0                // Y' = 0
    mov     x27, x19                   // AAD
    mov     x28, x20
    bl      .Lgcm_ghash_run
    mov     x27, x21                   // received ciphertext
    mov     x28, x22
    bl      .Lgcm_ghash_run
    mov     x9, x20                    // [len(A)]_64 || [len(C)]_64
    mov     x10, x22
    bl      .Lgcm_ghash_lengths

    // ── constant-time tag comparison ──
    // computed = E_K(J0) ⊕ rbit(Y'); the sum over the 16 difference
    // bytes is zero iff the tags match, and no branch depends on the
    // data until every byte has been compared.
    gcm_rbit v20.16b, v0.16b           // Y' back to GCM wire order
    add     x9, sp, #112
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
    add     x2, sp, #128               // keystream block
    bl      aes128_encrypt
    ld1     {v0.16b}, [x21], #16       // ciphertext block
    add     x9, sp, #128
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
    add     x2, sp, #128
    bl      aes128_encrypt
    mov     x28, #0
.Lgcm_dec_tailloop:
    ldrb    w9, [x21, x28]
    add     x10, sp, #128
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
    add     sp, sp, #144
    ret
