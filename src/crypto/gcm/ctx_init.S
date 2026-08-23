// AES-128-GCM key context construction

#include "data.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes_gcm_ctx_init
//
// Description: Build the key-derived half of an AES-128-GCM context —
//   the FIPS-197 round-key schedule and GHASH's hash subkey
//   H = E_K(0^128) — so that neither has to be recomputed inside
//   aes_gcm_encrypt_ctx / aes_gcm_decrypt_ctx on every record.
//
//   Both quantities depend on nothing but the key. The record path used
//   to derive them from scratch each time it ran: one aes128_key_expand
//   plus one aes128_encrypt plus a gcm_rbit, per record, in both
//   directions, for a key that is fixed for the whole epoch. On a
//   TLS connection the key changes exactly twice (handshake keys, then
//   application keys), so this runs four times per connection — twice
//   per direction — instead of twice per record.
//
//   H is stored already mapped into the natural polynomial domain (the
//   bit-reversed form .Lgcm_gf_mul multiplies in), so the per-record
//   path is a plain 16-byte load into v19.
//
//   C prototype:
//     void aes_gcm_ctx_init(const uint8_t *key, uint8_t *ctx);
//
// Input/Arguments:
//   x0 — pointer to the 16-byte AES-128 key
//   x1 — pointer to the GCM_CTX_SIZE-byte context to fill
//
// Output/Returns:
//   none (void) - GCM_CTX_SIZE bytes written to [x1]
//
// Clobbered Registers:
//   x0-x11, v0-v7, v16, v21-v25, NZCV (x20, x30 saved/restored) —
//   x0-x8, x10, x11 via aes128_key_expand, x1 and v22-v25 via
//   aes128_encrypt, v16/v21 for the gcm_rbit table and mask
//
// Stack Usage:
//   32 bytes - 16 for the all-zero block fed to aes128_encrypt, 8 for
//   x20, 8 for x30
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global aes_gcm_ctx_init

aes_gcm_ctx_init:
    sub     sp, sp, #32
    str     x20, [sp, #16]
    str     x30, [sp, #24]
    mov     x20, x1                    // ctx

    // ── RK0..RK10 at ctx + GCM_CTX_RK ──
    add     x1, x20, #GCM_CTX_RK       // x0 = key, still live
    bl      aes128_key_expand

    // ── H = E_K(0^128) at ctx + GCM_CTX_H ──
    stp     xzr, xzr, [sp]             // the all-zero block
    mov     x0, sp
    add     x1, x20, #GCM_CTX_RK
    add     x2, x20, #GCM_CTX_H
    bl      aes128_encrypt

    // ── map H into the natural domain, in place ──
    // gcm_rbit needs the nibble table in v16 and the 0x0f mask in v21;
    // nothing else in this function cares about either.
    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    movi    v21.16b, #0x0f
    add     x9, x20, #GCM_CTX_H
    ld1     {v0.16b}, [x9]
    gcm_rbit v0.16b, v0.16b            // H'
    st1     {v0.16b}, [x9]

    ldr     x30, [sp, #24]
    ldr     x20, [sp, #16]
    add     sp, sp, #32
    ret
