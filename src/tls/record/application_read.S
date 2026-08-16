// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/application_read.S — open incoming application
//   data (RFC 8446 §5.2, §23.3, PLAN.MD Phase 19)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.extern tls_record_next_client_seq
.extern tls_record_decrypt

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_app_data_read
//
// Description: Open one incoming TLSCiphertext record (RFC 8446 §5.2)
//   under the client's application traffic key/IV
//   (tls_derive_application_secrets, Phase 19), consuming the next
//   client→server record sequence number (tls_record_next_client_seq,
//   §5.3). A thin, state-aware specialization of the generic
//   tls_record_decrypt, mirroring tls_app_data_write for the read
//   direction: the connection handler (Phase 20) hands over the raw
//   record bytes and gets back plaintext plus the inner content type,
//   without threading key/IV/seq material through by hand. Mechanical
//   composition of two already-verified primitives — no algorithmic
//   content of its own.
//
// Input/Arguments:
//   x0 — pointer to the record buffer (header + ciphertext + tag)
//   x1 — number of bytes available in the buffer
//   x2 — pointer to the plaintext output buffer (>= len - 16 bytes)
//
// Output/Returns:
//   carry clear (success):
//     x0 — content length in bytes (padding and the type byte removed)
//     x1 — inner content type (20..23)
//   carry set (failure):
//     x0 — TLS_RECORD_ERR_SHORT / _LENGTH / _BOUNDS / _MAC / _INNER
//     (propagated verbatim from tls_record_decrypt)
//
// Clobbered Registers:
//   x0-x12, x19-x24, x30 (x19-x22, x30 saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   48 bytes: x19-x22, x30 (padded)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_app_data_read
tls_app_data_read:
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x20, x0                     // record buffer
    mov     x21, x1                     // buffer length
    mov     x22, x2                     // plaintext output buffer
    adr_l   x19, tls_state

    bl      tls_record_next_client_seq
    mov     x9, x0                      // sequence number

    mov     x0, x20
    mov     x1, x21
    add     x2, x19, #TLS_CLIENT_APP_KEY
    add     x3, x19, #TLS_CLIENT_APP_IV
    mov     x4, x9
    mov     x5, x22
    bl      tls_record_decrypt          // carry propagates to our caller

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
