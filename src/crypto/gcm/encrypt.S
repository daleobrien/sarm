// AES-128-GCM authenticated encryption

#include "data.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes_gcm_encrypt
//
// Description: AES-128-GCM seal: C = GCTR_K(J1..Jn, P) and
//   tag = GCTR_K(J0, GHASH_H(A, C)) with J0 = IV || 0^31 || 1 and a
//   96-bit (12-byte) IV — the TLS 1.3 nonce form. The ciphertext is
//   produced first, then hashed, so in-place operation (ct == pt) is
//   safe. The tag is always 16 bytes.
//
//   Two entry points. aes_gcm_encrypt_ctx takes a prebuilt key context
//   (aes_gcm_ctx_init) holding the round-key schedule and H, both of
//   which depend only on the key; this is what the record layer calls,
//   once per record, with the context its epoch built once.
//   aes_gcm_encrypt keeps the original key-pointer signature by
//   building a context on its own stack and falling through — the same
//   work the ctx form used to do inline, now paid only by callers that
//   genuinely have a one-shot key (the test vectors and the
//   differential sweeps).
//
// Input/Arguments:
//   x0 — aes_gcm_encrypt_ctx: pointer to a GCM_CTX_SIZE-byte context
//        (aes_gcm_ctx_init); aes_gcm_encrypt: pointer to the 16-byte
//        AES-128 key
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
//   x0-x12, x19-x28 (saved/restored), x30 (saved/restored), v0-v11,
//   v16-v25, NZCV (v22-v25 via aes128_encrypt, which holds four round
//   keys there — this function's own live state stays in v16-v21)
//
// Stack Usage:
//   aes_gcm_encrypt_ctx: 144 bytes - 88 for x19-x28 + x30 (+1 slot) and
//   the 16-byte counter / tag mask / keystream scratch (the round keys
//   now live in the caller's context, and the length block has its own
//   frame, in .Lgcm_ghash_lengths).
//   aes_gcm_encrypt: 256 bytes on top of that - GCM_CTX_SIZE for the
//   one-shot context, plus x30 and the seven arguments aes_gcm_ctx_init
//   would otherwise destroy.
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global aes_gcm_encrypt
.global aes_gcm_encrypt_ctx

// ── key-pointer entry: build a one-shot context, then seal with it ──
aes_gcm_encrypt:
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
    bl      aes_gcm_encrypt_ctx
    ldr     x30, [sp, #192]
    add     sp, sp, #256
    ret

aes_gcm_encrypt_ctx:
    sub     sp, sp, #144
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
    add     x25, sp, #96               // jbuf (counter block)
    add     x26, x0, #GCM_CTX_RK       // rk (176-byte round keys)

    // ── GHASH constants ──
    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    // ── H', already in the natural domain, out of the context ──
    // Deriving it here — expand the key, encrypt a zero block, rbit the
    // result — is what this used to cost per record, for a value that
    // cannot change while the key does not. aes_gcm_ctx_init does it
    // once per epoch instead.
    add     x9, x0, #GCM_CTX_H
    ld1     {v19.16b}, [x9]

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
    add     x2, sp, #112               // tagmask
    bl      aes128_encrypt

    // ── CTR: C_i = P_i ⊕ E_K(J0+i), i = 1, 2, ... ──
    gcm_inc32 x25                      // J0 -> J1
    lsr     x28, x22, #4               // full 16-byte blocks
    and     x27, x22, #0xf             // trailing partial-block bytes
    cbz     x28, .Lgcm_enc_tail
.Lgcm_enc_blockloop:
    mov     x0, x25                    // counter block
    mov     x1, x26
    add     x2, sp, #128               // keystream block
    bl      aes128_encrypt
    ld1     {v0.16b}, [x21], #16       // plaintext block
    add     x9, sp, #128
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
    add     x2, sp, #128
    bl      aes128_encrypt
    mov     x28, #0
.Lgcm_enc_tailloop:
    ldrb    w9, [x21, x28]             // partial block, byte by byte
    add     x10, sp, #128
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
    mov     x9, x20                    // [len(A)]_64 || [len(C)]_64
    mov     x10, x22
    bl      .Lgcm_ghash_lengths

    gcm_rbit v20.16b, v0.16b           // Y' back to GCM wire order
    add     x9, sp, #112
    ld1     {v1.16b}, [x9]             // tag mask E_K(J0)
    eor     v0.16b, v0.16b, v1.16b
    st1     {v0.16b}, [x24]            // write the tag

    ldr     x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #144
    ret
