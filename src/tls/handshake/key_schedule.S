// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/key_schedule.S — TLS 1.3 key schedule
//   (RFC 8446 §7.1)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.data
.align 4
// HKDF-Expand-Label bare labels (no "tls13 " prefix — hkdf_expand_label
// adds that). Lengths are passed explicitly by every caller below, so
// these need no NUL terminator.
khs_label_derived:
    .ascii "derived"
khs_label_c_hs_traffic:
    .ascii "c hs traffic"
khs_label_s_hs_traffic:
    .ascii "s hs traffic"
khs_label_key:
    .ascii "key"
khs_label_iv:
    .ascii "iv"

.align 4
// SHA-256("") — the context of both "derived" derivations (RFC 8446
// §7.1: the Early Secret and the Handshake Secret are each collapsed
// through Derive-Secret(., "derived", "") before the next HKDF-Extract,
// and an empty transcript hashes to this fixed value).
khs_empty_hash:
    .byte 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
    .byte 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
    .byte 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
    .byte 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_derive_handshake_secrets
//
// Description: Run the TLS 1.3 key schedule (RFC 8446 §7.1) from the
//   ECDHE shared secret through the handshake traffic keys and the
//   Master Secret:
//
//     Early Secret     = HKDF-Extract(0, 0)
//     dES               = Derive-Secret(Early Secret, "derived", "")
//     Handshake Secret  = HKDF-Extract(dES, shared_secret)
//     c/s hs traffic    = Derive-Secret(Handshake Secret,
//                           "c hs traffic" / "s hs traffic",
//                           transcript_hash)
//     {c,s}_hs_{key,iv} = HKDF-Expand-Label({c,s} hs traffic,
//                           "key" / "iv", "", 16 / 12)
//     dHS               = Derive-Secret(Handshake Secret, "derived", "")
//     Master Secret     = HKDF-Extract(dHS, 0)
//
//   The ECDHE shared secret (TLS_SHARED_SECRET, filled by
//   tls_build_server_hello) and the caller-supplied transcript hash
//   (the running SHA-256 over ClientHello..ServerHello, from
//   tls_transcript_hash) are the only connection-specific inputs; Early
//   Secret and both "derived" intermediates depend on nothing but fixed
//   constants, so they're recomputed here rather than cached. The
//   client and server handshake traffic secrets are both persisted
//   (TLS_CLIENT_HS_TRAFFIC_SECRET, TLS_SERVER_HS_TRAFFIC_SECRET): the
//   server's is the Finished BaseKey for the message Phase 18 sends
//   (RFC 8446 §4.4.4), and the client's is the BaseKey Phase 20's
//   handshake driver needs to verify the Finished the client sends
//   back. The Master
//   Secret is stored for Phase 19's application traffic secrets; it
//   is not itself a key.
//
// Input/Arguments:
//   x0 — pointer to the 32-byte ClientHello..ServerHello transcript hash
//
// Output/Returns:
//   none (void). tls_state's handshake_secret, client_hs_key,
//   client_hs_iv, server_hs_key, server_hs_iv and master_secret are
//   filled in (src/tls/data.S).
//
// Clobbered Registers:
//   x0-x11, x13, v0-v7, v16, v18, v19, NZCV (x19, x20, x30
//   saved/restored) — everything hkdf_extract / hkdf_expand_label clobber
//
// Stack Usage:
//   192 bytes: x19, x20, x30 (32, padded), then five 32-byte scratch
//   secrets — zeros32, early_secret, dES/derived1, a traffic-secret
//   slot reused for both directions, dHS/derived2
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_derive_handshake_secrets
tls_derive_handshake_secrets:
    sub     sp, sp, #192
    stp     x19, x20, [sp]
    str     x30, [sp, #16]
    mov     x20, x0                     // transcript hash (CH..SH)
    adr_l   x19, tls_state

    // ── zeros32 at sp+32: the IKM for Early Secret, the salt-free
    // "0" IKM for the Master Secret extract ──
    stp     xzr, xzr, [sp, #32]
    stp     xzr, xzr, [sp, #48]

    // ── Early Secret = HKDF-Extract(salt=0, ikm=32 zeros) ────────────
    mov     x0, #0
    mov     x1, #0
    add     x2, sp, #32
    mov     x3, #32
    add     x4, sp, #64                 // early_secret
    bl      hkdf_extract

    // ── dES = Derive-Secret(Early Secret, "derived", "") ─────────────
    add     x0, sp, #64
    adr_l   x1, khs_label_derived
    mov     x2, #7
    adr_l   x3, khs_empty_hash
    mov     x4, #32
    add     x5, sp, #96                 // dES
    mov     x6, #32
    bl      hkdf_expand_label

    // ── Handshake Secret = HKDF-Extract(dES, shared_secret) ──────────
    add     x0, sp, #96
    mov     x1, #32
    add     x2, x19, #TLS_SHARED_SECRET
    mov     x3, #32
    add     x4, x19, #TLS_HANDSHAKE_SECRET
    bl      hkdf_extract

    // ── client_handshake_traffic_secret, then its key/iv ─────────────
    // Persisted (not scratch) since Phase 20's handshake driver needs
    // it again as the BaseKey for verifying the client's own Finished
    // (RFC 8446 §4.4.4) — the same reason the server direction below
    // is persisted rather than kept transient.
    add     x0, x19, #TLS_HANDSHAKE_SECRET
    adr_l   x1, khs_label_c_hs_traffic
    mov     x2, #12
    mov     x3, x20                     // transcript hash
    mov     x4, #32
    add     x5, x19, #TLS_CLIENT_HS_TRAFFIC_SECRET
    mov     x6, #32
    bl      hkdf_expand_label

    add     x0, x19, #TLS_CLIENT_HS_TRAFFIC_SECRET
    adr_l   x1, khs_label_key
    mov     x2, #3
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_CLIENT_HS_KEY
    mov     x6, #16
    bl      hkdf_expand_label

    add     x0, x19, #TLS_CLIENT_HS_TRAFFIC_SECRET
    adr_l   x1, khs_label_iv
    mov     x2, #2
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_CLIENT_HS_IV
    mov     x6, #12
    bl      hkdf_expand_label

    // ── server_handshake_traffic_secret, then its key/iv ─────────────
    // Unlike the client direction, this secret is persisted (not just
    // scratch) — it's TLS_SECRET_LEN worth of storage, so writing it
    // straight to TLS_SERVER_HS_TRAFFIC_SECRET costs nothing extra and
    // is needed later as the Finished BaseKey (Phase 18, RFC 8446
    // §4.4.4: finished_key = HKDF-Expand-Label(BaseKey, "finished", "",
    // Hash.length), where BaseKey is this server_handshake_traffic_
    // secret).
    add     x0, x19, #TLS_HANDSHAKE_SECRET
    adr_l   x1, khs_label_s_hs_traffic
    mov     x2, #12
    mov     x3, x20
    mov     x4, #32
    add     x5, x19, #TLS_SERVER_HS_TRAFFIC_SECRET
    mov     x6, #32
    bl      hkdf_expand_label

    add     x0, x19, #TLS_SERVER_HS_TRAFFIC_SECRET
    adr_l   x1, khs_label_key
    mov     x2, #3
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_SERVER_HS_KEY
    mov     x6, #16
    bl      hkdf_expand_label

    add     x0, x19, #TLS_SERVER_HS_TRAFFIC_SECRET
    adr_l   x1, khs_label_iv
    mov     x2, #2
    mov     x3, #0
    mov     x4, #0
    add     x5, x19, #TLS_SERVER_HS_IV
    mov     x6, #12
    bl      hkdf_expand_label

    // ── dHS = Derive-Secret(Handshake Secret, "derived", "") ─────────
    add     x0, x19, #TLS_HANDSHAKE_SECRET
    adr_l   x1, khs_label_derived
    mov     x2, #7
    adr_l   x3, khs_empty_hash
    mov     x4, #32
    add     x5, sp, #160                // dHS
    mov     x6, #32
    bl      hkdf_expand_label

    // ── Master Secret = HKDF-Extract(dHS, ikm=32 zeros) ──────────────
    add     x0, sp, #160
    mov     x1, #32
    add     x2, sp, #32                 // zeros32, still intact
    mov     x3, #32
    add     x4, x19, #TLS_MASTER_SECRET
    bl      hkdf_extract

    ldp     x19, x20, [sp]
    ldr     x30, [sp, #16]
    add     sp, sp, #192
    ret
