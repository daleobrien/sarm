// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/encrypt.S — TLS record encryption (RFC 8446 §5.2)
// ─────────────────────────────────────────────────────────────────────
#include "../../defs.S"


// Forward declaration: tls_record_nonce is defined in nonce.S
.extern tls_record_nonce

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_encrypt
//
// Description: Seal one plaintext fragment into a TLS 1.3
//   TLSCiphertext record (PLAN.MD §11.3, RFC 8446 §5.2): the outer
//   header is `23 03 03 len(2)` with length = pt_len + 1 + 16, the
//   AEAD plaintext is `fragment || inner_content_type` (no padding is
//   ever added), the additional data is the 5-byte header itself, and
//   the nonce is the write IV XORed with the record sequence number
//   (tls_record_nonce). The ciphertext and 16-byte tag are written
//   after the header, in place over the plaintext, so the output
//   buffer needs 5 + pt_len + 1 + 16 bytes. A zero-length handshake or
//   alert content is rejected (§5.4 — the inner type byte alone would
//   have nothing to label).
//
// Input/Arguments:
//   x0 — inner content type (20..23)
//   x1 — pointer to the plaintext fragment (ignored when pt_len == 0)
//   x2 — fragment length in bytes (0..TLS_MAX_PLAINTEXT)
//   x3 — pointer to the 16-byte AES-128 write key
//   x4 — pointer to the 12-byte write IV
//   x5 — the 64-bit record sequence number
//   x6 — pointer to the output buffer (>= 5 + pt_len + 17 bytes)
//
// Output/Returns:
//   carry clear (success): x0 — total record length (5 + pt_len + 17)
//   carry set (failure):   x0 — TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
//
// Clobbered Registers:
//   x0-x12, x19-x24 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   80 bytes - x19-x24 + x30, plus a 16-byte nonce scratch
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_record_encrypt
tls_record_encrypt:
    sub     sp, sp, #80
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0                 // inner content type
    mov     x20, x2                 // plaintext length
    mov     x21, x3                 // key
    mov     x22, x4                 // write IV
    mov     x23, x5                 // sequence number
    mov     x24, x6                 // output buffer

    // ── validate: type in {20..23}, length within the plaintext
    //    limit, zero-length handshake/alert content is forbidden ──
    sub     w5, w19, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w5, #4
    b.hs    .Lrec_enc_type
    cmp     x20, #TLS_MAX_PLAINTEXT
    b.hi    .Lrec_enc_length
    cbz     x20, .Lrec_enc_zero
    b       .Lrec_enc_go
.Lrec_enc_zero:
    cmp     w19, #TLS_RECORD_HANDSHAKE
    b.eq    .Lrec_enc_empty
    cmp     w19, #TLS_RECORD_ALERT
    b.eq    .Lrec_enc_empty
.Lrec_enc_go:
    // ── outer header: type 23, version 0x0303, length = pt_len + 17 ──
    mov     w5, #TLS_RECORD_APPLICATION_DATA
    strb    w5, [x24]
    mov     w5, #0x03
    strb    w5, [x24, #1]
    strb    w5, [x24, #2]
    add     x5, x20, #(TLS_INNER_TYPE_LEN + TLS_TAG_LEN)
    lsr     x6, x5, #8
    strb    w6, [x24, #3]
    strb    w5, [x24, #4]

    // ── copy the fragment to out+5 (the plaintext, in place) ──
    add     x0, x24, #TLS_RECORD_HEADER_LEN
    bl      memcpy                  // x1 = pt, x2 = pt_len still live

    // ── append the inner content type to the plaintext ──
    add     x5, x24, x20
    add     x5, x5, #TLS_RECORD_HEADER_LEN
    strb    w19, [x5]

    // ── per-record nonce at [sp, #56] ──
    mov     x0, x22
    mov     x1, x23
    add     x2, sp, #56
    bl      tls_record_nonce

    // ── seal in place; aad = the 5-byte header just written ──
    mov     x0, x21                 // key
    add     x1, sp, #56             // nonce
    mov     x2, x24                 // aad = record header
    mov     x3, #TLS_RECORD_HEADER_LEN
    add     x4, x24, #TLS_RECORD_HEADER_LEN   // pt / ct (in place)
    add     x5, x20, #TLS_INNER_TYPE_LEN      // pt_len + 1
    mov     x6, x4                  // ct == pt (in place is safe)
    add     x7, x4, x5              // tag at out + 5 + pt_len + 1
    bl      aes_gcm_encrypt

    add     x0, x20, #(TLS_RECORD_HEADER_LEN + TLS_INNER_TYPE_LEN + TLS_TAG_LEN)
    cmn     xzr, xzr                // success — carry clear
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
.Lrec_enc_type:
    mov     x0, #TLS_RECORD_ERR_TYPE
    b       .Lrec_enc_fail
.Lrec_enc_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrec_enc_fail
.Lrec_enc_empty:
    mov     x0, #TLS_RECORD_ERR_EMPTY
.Lrec_enc_fail:
    cmp     xzr, xzr                // failure — carry set
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
