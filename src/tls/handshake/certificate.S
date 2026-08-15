// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/certificate.S — Certificate generation
//   (RFC 8446 §4.4.2, PLAN.MD Phase 15)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_certificate_write
//
// Description: Serialize the Certificate handshake message (RFC 8446
//   §4.4.2) — the 4-byte handshake header, an empty
//   certificate_request_context (this is never a CertificateRequest
//   reply), and a certificate_list of exactly one CertificateEntry
//   carrying the DER certificate embedded at build time
//   (tls_cert_der/tls_cert_der_end, src/tls/cert_data.S — see
//   certs/embed_cert.sh and PLAN.MD Phase 15's note against a general
//   X.509 parser: the DER bytes are copied onto the wire verbatim, with
//   no per-entry extensions. Pure serializer — no key material or
//   randomness involved, so it needs no failure mode; like
//   tls_encrypted_extensions_write, the caller is responsible for
//   encrypting the result under the server's handshake traffic key
//   before it goes on the wire.
//
// Input/Arguments:
//   x0 — pointer to the output buffer (>= 13 + the embedded certificate
//        length, TLS_CERT_HEADER_LEN + (tls_cert_der_end - tls_cert_der))
//
// Output/Returns:
//   x0 — total message length (4 + body length), including the
//        handshake header
//
// Clobbered Registers:
//   x0-x2, x9-x14 (x9 = cursor, x10 = certificate length, x11 = body
//   length, x12 = certificate list length; x13, x14 free scratch)
//
// Stack Usage:
//   none — leaf function, no calls out
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_certificate_write
tls_certificate_write:
    mov     x9, x0                          // cursor
    adr_l   x1, tls_cert_der
    adr_l   x2, tls_cert_der_end
    sub     x10, x2, x1                     // x10 = certificate length

    // body = context(1, always 0) + certificate_list(3) +
    //        [cert_data(3) + cert_len + extensions(2)]
    add     x12, x10, #5                    // certificate list length
    add     x11, x12, #4                    // body length

    // ── handshake header: type(1) + length(3), big-endian ────────────
    mov     w13, #TLS_HS_CERTIFICATE
    strb    w13, [x9]
    lsr     w13, w11, #16
    strb    w13, [x9, #1]
    lsr     w13, w11, #8
    strb    w13, [x9, #2]
    strb    w11, [x9, #3]
    add     x9, x9, #4

    // ── certificate_request_context<0..2^8-1>: always empty ─────────
    mov     w13, #0
    strb    w13, [x9]
    add     x9, x9, #1

    // ── certificate_list<0..2^24-1>: one CertificateEntry ────────────
    lsr     w13, w12, #16
    strb    w13, [x9]
    lsr     w13, w12, #8
    strb    w13, [x9, #1]
    strb    w12, [x9, #2]
    add     x9, x9, #3

    // ── cert_data<1..2^24-1>: length + the embedded DER bytes ───────
    lsr     w13, w10, #16
    strb    w13, [x9]
    lsr     w13, w10, #8
    strb    w13, [x9, #1]
    strb    w10, [x9, #2]
    add     x9, x9, #3

    mov     x14, #0
.Lcert_copy:
    cmp     x14, x10
    b.hs    .Lcert_copy_done
    ldrb    w13, [x1, x14]
    strb    w13, [x9, x14]
    add     x14, x14, #1
    b       .Lcert_copy
.Lcert_copy_done:
    add     x9, x9, x10

    // ── extensions<0..2^16-1>: always empty ──────────────────────────
    mov     w13, #0
    strb    w13, [x9]
    strb    w13, [x9, #1]

    add     x0, x11, #4                     // total message length
    ret
