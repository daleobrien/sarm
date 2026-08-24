// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/certificate_verify/content_hash.S — the
//   CertificateVerify signature input (RFC 8446 §4.4.3)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

rodata
.align 4
// 64 spaces, the server context string, and its terminating 0x00 —
// the fixed prefix of every CertificateVerify signature content (RFC
// 8446 §4.4.3). The transcript hash (32 bytes) follows at sign time,
// making the full "Content" 64 + 34 + 32 = 130 bytes.
cv_content_prefix:
    .rept 64
    .byte 0x20
    .endr
    .ascii "TLS 1.3, server CertificateVerify"
    .byte 0x00
cv_content_prefix_len = . - cv_content_prefix

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_certificate_verify_content_hash
//
// Description: Compute the 32-byte digest that gets ECDSA-signed for
//   CertificateVerify (RFC 8446 §4.4.3):
//
//     Content = 64*0x20 || "TLS 1.3, server CertificateVerify" || 0x00
//               || transcript_hash
//     digest  = SHA-256(Content)
//
//   This server always signs as the server (never the client), so the
//   context string is fixed at "TLS 1.3, server CertificateVerify" —
//   no client-side variant is implemented. Content is never actually
//   concatenated into one buffer; the fixed 98-byte prefix and the
//   32-byte transcript hash are fed to the streaming SHA-256 API as
//   two separate updates.
//
// Input/Arguments:
//   x0 — out (32-byte digest output buffer)
//   x1 — transcript_hash (32 bytes — see tls_transcript_hash)
//
// Output/Returns:
//   none (void) — 32 digest bytes written to [x0]
//
// Clobbered Registers:
//   x0-x2, NZCV (x19, x20, x30 saved/restored) — everything
//   sha256_update/sha256_final clobber
//
// Stack Usage:
//   128 bytes: x19, x20, x30 (rounded to 16), plus a 112-byte
//   SHA256_CTX scratch buffer (SHA256_CTX_SIZE), 16-aligned
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_certificate_verify_content_hash
    sub     sp, sp, #144
    stp     x19, x20, [sp]
    str     x30, [sp, #16]

    mov     x19, x0                  // out — live across the calls
    mov     x20, x1                  // transcript_hash

    add     x0, sp, #32              // scratch SHA256_CTX (16-aligned)
    bl      sha256_init

    add     x0, sp, #32
    adr_l   x1, cv_content_prefix
    mov     x2, #cv_content_prefix_len
    bl      sha256_update

    add     x0, sp, #32
    mov     x1, x20
    mov     x2, #32
    bl      sha256_update

    add     x0, sp, #32
    mov     x1, x19
    bl      sha256_final

    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #144
    ret
ENDFUNC tls_certificate_verify_content_hash
