// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/certificate_verify/write.S — CertificateVerify
//   generation (RFC 8446 §4.4.3)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_certificate_verify_write
//
// Description: Generate and serialize the CertificateVerify handshake
//   message (RFC 8446 §4.4.3): draw a fresh ECDSA nonce k, sign the
//   current transcript with the server's embedded private key
//   (tls_certificate_verify_sign_with_k), DER-encode (r,s)
//   (p256_ecdsa_der_sig_encode), then write the 4-byte handshake
//   header, the fixed 2-byte signature_algorithm
//   (ecdsa_secp256r1_sha256, 0x0403 — the only scheme this server
//   supports) and the length-prefixed DER signature.
//
//   p256_ecdsa_sign_with_k fails (r == 0 or s == 0) with probability
//   ~2^-256 for a valid random k — astronomically unlikely, but on
//   failure this draws a fresh k and retries rather than either
//   looping forever or silently using a bad signature; a handful of
//   retries is already unreachable in practice, so a small fixed cap
//   is enough to keep the function provably terminating.
//
//   The nonce k and the raw (r,s) live only in this function's own
//   stack frame and are wiped before returning, the same discipline
//   as the ephemeral X25519 scalar in tls_build_server_hello.
//
// Input/Arguments:
//   x0 — pointer to the output buffer (>= 4 + 2 + 2 + 72 = 80 bytes)
//   x1 — pointer to the 32-byte transcript hash (see
//        tls_transcript_hash — the running transcript up to and
//        including the Certificate message)
//
// Output/Returns:
//   carry clear (success):
//     x0 — total message length
//   carry set (failure):
//     x0 — TLS_ALERT_INTERNAL_ERROR (crypto_random_bytes failed, or
//          every retry produced r == 0 / s == 0)
//
// Clobbered Registers:
//   x0-x3, x9-x12, NZCV (x19-x21, x30 saved/restored)
//
// Stack Usage:
//   128 bytes: x19-x21 + x30 (rounded to 32), a 32-byte nonce slot,
//   a 32-byte sig_r slot, and a 32-byte sig_s slot
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_certificate_verify_write
tls_certificate_verify_write:
    sub     sp, sp, #128
    stp     x19, x20, [sp]
    str     x21, [sp, #16]
    str     x30, [sp, #24]

    mov     x19, x0                  // out buffer
    mov     x20, x1                  // transcript_hash
    // scratch: sp+32 k (32 bytes), sp+64 sig_r (32 bytes),
    // sp+96 sig_s (32 bytes)
    mov     x21, #4                  // retries remaining

.Lcvw_try:
    add     x0, sp, #32              // k
    mov     x1, #32
    bl      crypto_random_bytes
    b.cs    .Lcvw_rng_fail

    add     x0, sp, #64              // sig_r
    add     x1, sp, #96              // sig_s
    mov     x2, x20                  // transcript_hash
    add     x3, sp, #32              // k
    bl      tls_certificate_verify_sign_with_k
    cbz     x0, .Lcvw_signed

    subs    x21, x21, #1
    b.ne    .Lcvw_try
    b       .Lcvw_sign_fail

.Lcvw_signed:
    // ── DER-encode (r,s) straight onto the wire, after the header +
    //    signature_algorithm(2) + signature length(2) ──────────────
    add     x0, x19, #8
    add     x1, sp, #64              // sig_r
    add     x2, sp, #96              // sig_s
    bl      p256_ecdsa_der_sig_encode
    mov     x9, x0                   // DER length

    // wipe the nonce and the raw signature — nothing past this point
    // needs them, and the DER copy already lives on the wire
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    stp     xzr, xzr, [sp, #64]
    stp     xzr, xzr, [sp, #80]
    stp     xzr, xzr, [sp, #96]
    stp     xzr, xzr, [sp, #112]

    // body = signature_algorithm(2) + signature length(2) + DER(x9)
    add     x10, x9, #4              // body length

    // ── handshake header: type(1) + length(3), big-endian ────────
    mov     w11, #TLS_HS_CERTIFICATE_VERIFY
    strb    w11, [x19]
    lsr     w11, w10, #16
    strb    w11, [x19, #1]
    lsr     w11, w10, #8
    strb    w11, [x19, #2]
    strb    w10, [x19, #3]

    // ── signature_algorithm: ecdsa_secp256r1_sha256 (0x0403) ──────
    mov     w11, #SIG_ECDSA_SECP256R1_SHA256
    lsr     w12, w11, #8
    strb    w12, [x19, #4]
    strb    w11, [x19, #5]

    // ── signature<0..2^16-1>: length + the DER bytes already at
    //    x19+8 ───────────────────────────────────────────────────
    lsr     w11, w9, #8
    strb    w11, [x19, #6]
    strb    w9, [x19, #7]

    add     x0, x10, #4              // total message length
    cmn     xzr, xzr                 // success — carry clear
    b       .Lcvw_done

.Lcvw_rng_fail:
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    mov     x0, #TLS_ALERT_INTERNAL_ERROR
    cmp     xzr, xzr                 // failure — carry set
    b       .Lcvw_done

.Lcvw_sign_fail:
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]
    mov     x0, #TLS_ALERT_INTERNAL_ERROR
    cmp     xzr, xzr                 // failure — carry set

.Lcvw_done:
    ldr     x30, [sp, #24]
    ldr     x21, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #128
    ret
