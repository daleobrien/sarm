// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/decrypt.S — TLS record decryption (RFC 8446 §5.2)
// ─────────────────────────────────────────────────────────────────────
#include "../../defs.S"


// Forward declaration: tls_record_nonce is defined in nonce.S
.extern tls_record_nonce

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_decrypt
//
// Description: Open one TLS 1.3 TLSCiphertext record (RFC 8446 §5.2):
//   the AEAD is checked with the 5-byte record header as additional
//   data and the nonce from the read IV and the sequence number; only
//   on a successful tag check is the plaintext written, so a bad tag
//   leaves the output untouched and returns TLS_RECORD_ERR_MAC (the
//   RFC 8446 "bad_record_mac" condition). The inner plaintext is
//   `content || type || zeros(padding)`: the last non-zero octet is
//   the content type and everything after it is padding, which is
//   zero by construction (§5.4). An all-zero plaintext — the malformed
//   case of Appendix C.3 — is rejected as TLS_RECORD_ERR_INNER, as is
//   an inner content type outside 20..23. The record must carry at
//   least 17 fragment bytes (the tag plus the inner type byte) and at
//   most TLS_MAX_AEAD (the AES-128-GCM bound). The outer header type
//   and version are not re-validated here: the caller parses them
//   first (tls_record_parse), and the header bytes are consumed
//   verbatim as the AEAD additional data, which binds them.
//
// Input/Arguments:
//   x0 — pointer to the record buffer (header + ciphertext + tag)
//   x1 — number of bytes available in the buffer
//   x2 — pointer to the read direction's AES-128-GCM key context
//        (GCM_CTX_SIZE bytes, built by aes_gcm_ctx_init when the read
//        key was installed — tls_client_gcm_ctx for a real connection).
//        Passed straight through to aes_gcm_decrypt_ctx; this layer
//        never inspects it.
//   x3 — pointer to the 12-byte read IV
//   x4 — the 64-bit record sequence number
//   x5 — pointer to the plaintext output buffer (>= len - 16 bytes)
//
// Output/Returns:
//   carry clear (success):
//     x0 — content length in bytes (padding and the type byte removed)
//     x1 — inner content type (20..23)
//   carry set (failure):
//     x0 — TLS_RECORD_ERR_SHORT / _LENGTH / _BOUNDS / _MAC / _INNER
//
// Clobbered Registers:
//   x0-x12, x19-x24 (saved/restored), x30 (saved/restored), v0-v11,
//   v16-v21, NZCV
//
// Stack Usage:
//   80 bytes - x19-x24 + x30, plus a 16-byte nonce scratch
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_record_decrypt
    sub     sp, sp, #80
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0                 // record buffer (header + ct + tag)
    mov     x20, x5                 // plaintext output
    mov     x21, x2                 // GCM key context
    mov     x22, x3                 // read IV
    mov     x23, x4                 // sequence number

    cmp     x1, #TLS_RECORD_HEADER_LEN
    b.lo    .Lrec_dec_short
    ldrb    w6, [x19, #3]
    ldrb    w7, [x19, #4]
    orr     w6, w7, w6, lsl #8      // TLSCiphertext.length (big-endian)
    // length = ct + tag; the smallest valid record is the tag plus the
    // inner type byte, and the largest is the AES-128-GCM bound.
    cmp     w6, #(TLS_TAG_LEN + TLS_INNER_TYPE_LEN)
    b.lo    .Lrec_dec_length
    mov     w7, #TLS_MAX_AEAD
    cmp     w6, w7
    b.hi    .Lrec_dec_length
    add     x7, x6, #TLS_RECORD_HEADER_LEN
    cmp     x7, x1
    b.hi    .Lrec_dec_bounds
    sub     x24, x6, #TLS_TAG_LEN   // plaintext length (content + type)

    // ── per-record nonce at [sp, #56] ──
    mov     x0, x22
    mov     x1, x23
    add     x2, sp, #56
    bl      tls_record_nonce

    // ── open; aad = the 5-byte header, tag is the last 16 bytes ──
    mov     x0, x21                 // GCM key context
    add     x1, sp, #56             // nonce
    mov     x2, x19                 // aad = record header
    mov     x3, #TLS_RECORD_HEADER_LEN
    add     x4, x19, #TLS_RECORD_HEADER_LEN   // ciphertext
    mov     x5, x24                 // ct_len
    add     x6, x4, x5              // tag
    mov     x7, x20                 // plaintext output
    bl      aes_gcm_decrypt_ctx     // x0 = 1 verified, 0 bad tag

    cbz     x0, .Lrec_dec_mac

    // ── find the inner content type: scan from the end for the first
    //    non-zero octet; everything after it is padding (§5.4) ──
    add     x5, x20, x24            // one past the last plaintext byte
    mov     x6, x24                 // plaintext length remaining
.Lrec_dec_scan:
    cbz     x6, .Lrec_dec_inner     // scanned the whole plaintext: zeros
    ldrb    w7, [x5, #-1]!
    sub     x6, x6, #1
    cbz     w7, .Lrec_dec_scan
    sub     w7, w7, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w7, #4                  // inner type in 20..23?
    b.hs    .Lrec_dec_inner
    mov     x0, x6                  // content length (bytes before the type)
    ldrb    w1, [x5]                // inner content type
    cmn     xzr, xzr                // success — carry clear
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
.Lrec_dec_short:
    mov     x0, #TLS_RECORD_ERR_SHORT
    b       .Lrec_dec_fail
.Lrec_dec_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrec_dec_fail
.Lrec_dec_bounds:
    mov     x0, #TLS_RECORD_ERR_BOUNDS
    b       .Lrec_dec_fail
.Lrec_dec_mac:
    mov     x0, #TLS_RECORD_ERR_MAC
    b       .Lrec_dec_fail
.Lrec_dec_inner:
    mov     x0, #TLS_RECORD_ERR_INNER
.Lrec_dec_fail:
    cmp     xzr, xzr                // failure — carry set
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
ENDFUNC tls_record_decrypt
