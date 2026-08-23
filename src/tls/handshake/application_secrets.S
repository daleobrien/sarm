// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/application_secrets.S — TLS 1.3 application
//   traffic keys (RFC 8446 §7.1)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

rodata
.align 4
// HKDF-Expand-Label bare labels (no "tls13 " prefix — hkdf_expand_label
// adds that), matching the convention in key_schedule.S.
as_label_c_ap_traffic:
    .ascii "c ap traffic"
as_label_s_ap_traffic:
    .ascii "s ap traffic"
as_label_key:
    .ascii "key"
as_label_iv:
    .ascii "iv"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_derive_application_secrets
//
// Description: Run the last step of the TLS 1.3 key schedule (RFC 8446
//   §7.1) from the Master Secret (persisted by tls_derive_handshake_
//   secrets, Phase 10) through the application traffic keys:
//
//     c_ap_traffic = Derive-Secret(Master Secret, "c ap traffic",
//                       CH..SF transcript hash)
//     s_ap_traffic = Derive-Secret(Master Secret, "s ap traffic",
//                       CH..SF transcript hash)
//     {c,s}_app_{key,iv} = HKDF-Expand-Label({c,s}_ap_traffic,
//                       "key" / "iv", "", 16 / 12)
//
//   The caller-supplied transcript hash covers ClientHello through the
//   server's Finished (CH..SF, RFC 8446 §7.1) — one step short of the
//   CH..CF hash Phase 18's own Finished verification uses. Both
//   application traffic secrets are transient (kept only in stack
//   scratch): nothing past this call needs them again, only their
//   key/IV derivatives are persisted. RFC 8446 §5.3 resets each
//   direction's record sequence number "at the beginning of a
//   connection and whenever the key changes" — moving from the
//   handshake keys to the application keys is exactly such a change,
//   so both TLS_CLIENT_SEQ and TLS_SERVER_SEQ are zeroed here.
//
// Input/Arguments:
//   x0 — pointer to the 32-byte ClientHello..server-Finished transcript
//        hash
//
// Output/Returns:
//   none (void). tls_state's client_app_key, client_app_iv,
//   server_app_key, server_app_iv are filled in and both sequence
//   counters are reset to zero (src/tls/data.S).
//
// Clobbered Registers:
//   x0-x11, x13 (x19, x20, x30 saved/restored), v0-v7, v16, v18, v19,
//   v21-v25, NZCV — everything hkdf_expand_label clobbers, plus
//   v21-v25 from aes_gcm_ctx_init's key expansion and zero-block
//   encrypt
//
// Stack Usage:
//   96 bytes: x19, x20, x30 (32, padded), then two 32-byte scratch
//   secrets — c_ap_traffic, s_ap_traffic
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_derive_application_secrets
tls_derive_application_secrets:
    sub     sp, sp, #96
    stp     x19, x20, [sp]
    str     x30, [sp, #16]
    mov     x20, x0                     // transcript hash (CH..SF)
    adr_l   x19, tls_state

    // ── client_application_traffic_secret_0, then its key/iv ────────
    add     x0, x19, #TLS_MASTER_SECRET
    adr_l   x1, as_label_c_ap_traffic
    mov     x2, #12
    mov     x3, x20
    mov     x4, #32
    add     x5, sp, #32                 // c_ap_traffic scratch
    mov     x6, #32
    bl      hkdf_expand_label

    add     x0, sp, #32
    adr_l   x1, as_label_key
    mov     x2, #3
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_CLIENT_APP_KEY
    mov     x6, #16
    bl      hkdf_expand_label

    add     x0, sp, #32
    adr_l   x1, as_label_iv
    mov     x2, #2
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_CLIENT_APP_IV
    mov     x6, #12
    bl      hkdf_expand_label

    // ── server_application_traffic_secret_0, then its key/iv ────────
    add     x0, x19, #TLS_MASTER_SECRET
    adr_l   x1, as_label_s_ap_traffic
    mov     x2, #12
    mov     x3, x20
    mov     x4, #32
    add     x5, sp, #64                 // s_ap_traffic scratch
    mov     x6, #32
    bl      hkdf_expand_label

    add     x0, sp, #64
    adr_l   x1, as_label_key
    mov     x2, #3
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_SERVER_APP_KEY
    mov     x6, #16
    bl      hkdf_expand_label

    add     x0, sp, #64
    adr_l   x1, as_label_iv
    mov     x2, #2
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_SERVER_APP_IV
    mov     x6, #12
    bl      hkdf_expand_label

    // ── the application epoch's GCM key contexts ────────────────────
    // Same reason as the handshake epoch, and the same place in the
    // sequence: the moment both directions' keys are final, and before
    // any record is sealed or opened under them.
    add     x0, x19, #TLS_CLIENT_APP_KEY
    adr_l   x1, tls_client_gcm_ctx
    bl      aes_gcm_ctx_init
    add     x0, x19, #TLS_SERVER_APP_KEY
    adr_l   x1, tls_server_gcm_ctx
    bl      aes_gcm_ctx_init

    // ── key change: reset both record sequence numbers (§5.3) ───────
    str     xzr, [x19, #TLS_CLIENT_SEQ]
    str     xzr, [x19, #TLS_SERVER_SEQ]

    ldp     x19, x20, [sp]
    ldr     x30, [sp, #16]
    add     sp, sp, #96
    ret
