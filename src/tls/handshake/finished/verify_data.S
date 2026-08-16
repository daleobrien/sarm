// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/finished/verify_data.S — the Finished
//   verify_data (RFC 8446 §4.4.4)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_finished_verify_data
//
// Description: Compute the Finished message's verify_data (RFC 8446
//   §4.4.4):
//
//     verify_data = HMAC(finished_key, Transcript-Hash(Handshake
//                     Context, Certificate*, CertificateVerify*))
//
//   The transcript hash argument here is the running transcript hash
//   *at the point this Finished is sent* — for the server's Finished
//   that's ClientHello..CertificateVerify (tls_transcript_hash, kept
//   current by every preceding tls_transcript_update call) — not the
//   CertificateVerify-specific "64 spaces || context string" content
//   hash from Phase 17; this function just wraps hmac_sha256 and
//   doesn't care what the 32 hash bytes represent.
//
// Input/Arguments:
//   x0 — pointer to the 32-byte finished_key (from tls_finished_key)
//   x1 — pointer to the 32-byte transcript hash
//   x2 — pointer to the 32-byte output buffer
//
// Output/Returns:
//   none (void) - 32 verify_data bytes written to [x2]
//
// Clobbered Registers:
//   x0-x7, x19-x27 (saved/restored), x30 (saved/restored) —
//   everything hmac_sha256 clobbers
//
// Stack Usage:
//   none — leaf-of-one-call, all scratch belongs to hmac_sha256
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_finished_verify_data
tls_finished_verify_data:
    str     x30, [sp, #-16]!

    mov     x9, x0                      // finished_key
    mov     x10, x1                     // transcript_hash
    mov     x11, x2                     // out

    mov     x0, x9                      // key
    mov     x1, #32                     // keylen
    mov     x2, x10                     // data
    mov     x3, #32                     // datalen
    mov     x4, x11                     // out
    bl      hmac_sha256

    ldr     x30, [sp], #16
    ret
