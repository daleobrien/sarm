// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/certificate_verify/sign_with_k.S — sign the
//   CertificateVerify content with a caller-supplied nonce (RFC 8446
//   §4.4.3, PLAN.MD Phase 17)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_certificate_verify_sign_with_k
//
// Description: Produce the raw ECDSA signature (r,s) for
//   CertificateVerify over the current transcript, using the
//   server's embedded private key (tls_priv_key, src/tls/cert_data.S)
//   and a caller-supplied nonce k. Like p256_ecdsa_sign_with_k, k is
//   an argument rather than drawn here so this function stays
//   deterministic and testable; the caller
//   (tls_certificate_verify_write) is responsible for drawing k from
//   crypto_random_bytes.
//
// Algorithm:
//   digest = tls_certificate_verify_content_hash(transcript_hash)
//   (r,s)  = p256_ecdsa_sign_with_k(digest, tls_priv_key, k)
//
// Input/Arguments:
//   x0 — sig_r out (32 bytes), x1 — sig_s out (32 bytes)
//   x2 — transcript_hash (32 bytes)
//   x3 — k, the nonce (32 bytes)
//
// Output/Returns:
//   x0 — 0 on success, 1 on failure (see p256_ecdsa_sign_with_k —
//        r == 0 or s == 0, probability ~2^-256 for a valid random k;
//        the caller should draw a fresh k and retry)
//
// Clobbered Registers:
//   x0-x5, x19-x22 (saved/restored), x30 (saved/restored), v0, v1,
//   NZCV — everything content_hash/p256_ecdsa_sign_with_k clobber
//
// Stack Usage:
//   80 bytes: x19-x22 + x30 (40 bytes, rounded to 48), plus a 32-byte
//   digest scratch slot
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_certificate_verify_sign_with_k
tls_certificate_verify_sign_with_k:
    sub     sp, sp, #80
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]

    mov     x19, x0                  // sig_r out
    mov     x20, x1                  // sig_s out
    mov     x21, x2                  // transcript_hash
    mov     x22, x3                  // k

    add     x0, sp, #48              // digest scratch
    mov     x1, x21
    bl      tls_certificate_verify_content_hash

    mov     x0, x19
    mov     x1, x20
    add     x2, sp, #48              // digest
    adr_l   x3, tls_priv_key
    mov     x4, x22
    bl      p256_ecdsa_sign_with_k

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
