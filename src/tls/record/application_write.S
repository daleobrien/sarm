// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/application_write.S — seal outgoing application
//   data (RFC 8446 §5.2, §23.3)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.extern tls_record_next_server_seq
.extern tls_record_encrypt

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_app_data_write
//
// Description: Seal one outgoing application_data record (RFC 8446
//   §5.2) under the server's application traffic key/IV
//   (tls_derive_application_secrets, Phase 19), consuming the next
//   server→client record sequence number (tls_record_next_server_seq,
//   §5.3). A thin, state-aware specialization of the generic
//   tls_record_encrypt — the same relationship next_server_seq.S has
//   to the record layer's sequence counters — so the connection
//   handler (Phase 20) only needs to hand over plaintext and a
//   destination buffer, not thread key/IV/seq material through by
//   hand. Has no algorithmic content of its own: it is a mechanical
//   composition of two already-verified primitives.
//
// Input/Arguments:
//   x0 — pointer to the plaintext fragment (ignored when len == 0)
//   x1 — fragment length in bytes (0..TLS_MAX_PLAINTEXT)
//   x2 — pointer to the output buffer (>= 5 + len + 17 bytes)
//
// Output/Returns:
//   carry clear (success): x0 — total record length (5 + len + 17)
//   carry set (failure):   x0 — TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
//     (propagated verbatim from tls_record_encrypt; application_data
//     is never rejected for being zero-length, only handshake/alert
//     content is, so in practice only _LENGTH can fire here)
//
// Clobbered Registers:
//   x0-x12, v0-v7, v16-v30, NZCV (x19-x22, x30 saved/restored)
//
//   v22-v30 are the GHASH working set, not just v16-v21: v22-v28 hold
//   the H^2..H^4 subkey powers and their rolled cross terms
//   (.Lgcm_ghash_powers), and v29-v30 the Karatsuba accumulators inside
//   .Lgcm_ghash_run. Both leaves have always declared them; this header
//   said v16-v21 because it predates the 4-block Karatsuba GHASH and was
//   never widened with it. v8-v15 are untouched -- AAPCS64 makes d8-d15
//   callee-saved -- so the v8-v11 this used to claim was wrong in the
//   other direction.
//
// Stack Usage:
//   48 bytes: x19-x22, x30 (padded)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_app_data_write
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x20, x0                     // plaintext
    mov     x21, x1                     // plaintext length
    mov     x22, x2                     // output buffer
    adr_l   x19, tls_state

    bl      tls_record_next_server_seq
    mov     x9, x0                      // sequence number

    mov     x0, #TLS_RECORD_APPLICATION_DATA
    mov     x1, x20
    mov     x2, x21
    adr_l   x3, tls_server_gcm_ctx      // the app epoch's write context
    add     x4, x19, #TLS_SERVER_APP_IV
    mov     x5, x9
    mov     x6, x22
    bl      tls_record_encrypt          // carry propagates to our caller

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
ENDFUNC tls_app_data_write
