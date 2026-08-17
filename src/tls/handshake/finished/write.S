// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/finished/write.S — serialize the server's
//   Finished handshake message (RFC 8446 §4.4.4)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_finished_write
//
// Description: Build the server's Finished message:
//
//     finished_key = tls_finished_key(TLS_SERVER_HS_TRAFFIC_SECRET)
//     verify_data  = tls_finished_verify_data(finished_key,
//                      transcript_hash)
//     Finished     = handshake header (type=20, length=32) ||
//                      verify_data
//
//   Unlike CertificateVerify, Finished has no randomness and no
//   failure mode — HMAC-SHA256 always succeeds — so this is a plain
//   serializer, not a retry loop. The caller is responsible for
//   snapshotting the transcript hash (ClientHello..CertificateVerify
//   for the server's Finished) before calling this and for
//   encrypting the result under the server's handshake traffic keys,
//   same division of responsibility as
//   tls_encrypted_extensions_write and tls_certificate_verify_write.
//
// Input/Arguments:
//   x0 — pointer to the output buffer (>= 4 + 32 = 36 bytes)
//   x1 — pointer to the 32-byte transcript hash
//
// Output/Returns:
//   x0 — total message length (36)
//
// Clobbered Registers:
//   x0-x2, x9 (x19, x20, x30 saved/restored) —
//   everything tls_finished_key / tls_finished_verify_data clobber
//
// Stack Usage:
//   64 bytes: x19, x20 + x30 (24 bytes, rounded to 32), plus a
//   32-byte finished_key scratch slot
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_finished_write
tls_finished_write:
    sub     sp, sp, #64
    stp     x19, x20, [sp]
    str     x30, [sp, #16]

    mov     x19, x0                     // out
    mov     x20, x1                     // transcript_hash

    adr_l   x9, tls_state
    add     x0, x9, #TLS_SERVER_HS_TRAFFIC_SECRET
    add     x1, sp, #32                 // finished_key scratch
    bl      tls_finished_key

    add     x0, sp, #32                 // finished_key
    mov     x1, x20                     // transcript_hash
    add     x2, x19, #4                 // verify_data straight into place
    bl      tls_finished_verify_data

    // ── handshake header: type(1) + length(3) = 0x000020, big-endian ──
    mov     w9, #TLS_HS_FINISHED
    strb    w9, [x19]
    strb    wzr, [x19, #1]
    strb    wzr, [x19, #2]
    mov     w9, #32
    strb    w9, [x19, #3]

    mov     x0, #36                     // total message length

    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #64
    ret
