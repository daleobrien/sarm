// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/server_hello.S — ServerHello generation
//   (RFC 8446 §4.1.3, PLAN.MD Phase 13)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.data
.align 4
// RFC 7748 §5: the X25519 base point, u = 9, little-endian, 32 bytes.
x25519_basepoint9:
    .byte 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_server_hello_write
//
// Description: Serialize the ServerHello handshake message (RFC 8446
//   §4.1.3) — the 4-byte handshake header followed by the body — from
//   fields already sitting in tls_state: server_random
//   (TLS_SERVER_RANDOM), the legacy_session_id echo
//   (TLS_SESSION_ID_LEN/TLS_SESSION_ID, filled in by
//   tls_parse_client_hello) and the server's X25519 public key
//   (TLS_SERVER_KEY_SHARE). Purely a wire-format writer — it does no
//   key generation, which makes it testable independently of the RNG
//   (see tls_build_server_hello below, which fills those fields first).
//
//   Everything else is fixed, since this server supports exactly one
//   TLS 1.3 configuration:
//     legacy_version        = 0x0303 (§4.1.3 — never 0x0304 on the wire)
//     cipher_suite           = TLS_AES_128_GCM_SHA256
//     legacy_compression_method = 0
//     extensions              = supported_versions(0x0304), key_share(X25519)
//
// Input/Arguments:
//   x0 — pointer to the output buffer (>= 4 + 86 + 32 = 122 bytes,
//        the max when legacy_session_id is the full 32 bytes)
//
// Output/Returns:
//   x0 — total message length (4 + body length), including the
//        handshake header
//
// Clobbered Registers:
//   x0, x1, x9-x15 (x9 = cursor, x10 = body length, x11 = session ID
//   length, x12 = tls_state base — persist across the whole function;
//   x13-x15 are free scratch)
//
// Stack Usage:
//   none — leaf function, no calls out
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_server_hello_write
tls_server_hello_write:
    adr_l   x12, tls_state
    mov     x9, x0                          // cursor
    ldr     x11, [x12, #TLS_SESSION_ID_LEN] // 0..32

    // ── handshake header: type(1) + length(3), big-endian ───────────
    mov     w13, #TLS_HS_SERVER_HELLO
    strb    w13, [x9]
    add     x10, x11, #86                   // body length = 86 + session ID
    lsr     w13, w10, #16
    strb    w13, [x9, #1]
    lsr     w13, w10, #8
    strb    w13, [x9, #2]
    strb    w10, [x9, #3]
    add     x9, x9, #4

    // ── legacy_version (§4.1.3 — always 0x0303 on the wire) ─────────
    mov     w13, #TLS_VERSION_1_2
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    add     x9, x9, #2

    // ── random(32) ────────────────────────────────────────────────
    add     x0, x12, #TLS_SERVER_RANDOM
    ldp     x14, x15, [x0]
    stp     x14, x15, [x9]
    ldp     x14, x15, [x0, #16]
    stp     x14, x15, [x9, #16]
    add     x9, x9, #32

    // ── legacy_session_id_echo<0..32> (§4.1.3) ───────────────────────
    strb    w11, [x9]
    add     x9, x9, #1
    add     x0, x12, #TLS_SESSION_ID
    mov     x1, #0
.Lsh_sid_copy:
    cmp     x1, x11
    b.hs    .Lsh_sid_done
    ldrb    w13, [x0, x1]
    strb    w13, [x9, x1]
    add     x1, x1, #1
    b       .Lsh_sid_copy
.Lsh_sid_done:
    add     x9, x9, x11

    // ── cipher_suite = TLS_AES_128_GCM_SHA256 ────────────────────────
    mov     w13, #TLS_CIPHER_AES_128_GCM_SHA256
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    add     x9, x9, #2

    // ── legacy_compression_method = 0 ────────────────────────────────
    strb    wzr, [x9]
    add     x9, x9, #1

    // ── extensions<6..2^16-1>: supported_versions + key_share ───────
    mov     w13, #46                        // 6 + 40, see below
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    add     x9, x9, #2

    // supported_versions: type(2) + length(2)=2 + selected_version(2)
    mov     w13, #TLS_EXT_SUPPORTED_VERSIONS
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    strb    wzr, [x9, #2]
    mov     w13, #2
    strb    w13, [x9, #3]
    mov     w13, #TLS_VERSION_1_3
    lsr     w14, w13, #8
    strb    w14, [x9, #4]
    strb    w13, [x9, #5]
    add     x9, x9, #6

    // key_share (KeyShareServerHello, §4.2.8): type(2) + length(2)=36 +
    // one KeyShareEntry: group(2) + key_exchange_length(2)=32 + key(32)
    mov     w13, #TLS_EXT_KEY_SHARE
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    mov     w13, #36
    lsr     w14, w13, #8
    strb    w14, [x9, #2]
    strb    w13, [x9, #3]
    mov     w13, #NAMED_GROUP_X25519
    lsr     w14, w13, #8
    strb    w14, [x9, #4]
    strb    w13, [x9, #5]
    strb    wzr, [x9, #6]
    mov     w13, #32
    strb    w13, [x9, #7]
    add     x0, x12, #TLS_SERVER_KEY_SHARE
    ldp     x14, x15, [x0]
    stp     x14, x15, [x9, #8]
    ldp     x14, x15, [x0, #16]
    stp     x14, x15, [x9, #24]
    add     x9, x9, #40

    add     x0, x10, #4                     // total message length
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_build_server_hello
//
// Description: Generate the ephemeral X25519 key pair and shared
//   secret (PLAN.MD Phase 13), then write the ServerHello. Requires
//   tls_parse_client_hello to have already run (tls_client_key_share
//   and the session ID echo must be populated).
//
//   The ephemeral private scalar lives only on this function's own
//   stack frame and is wiped before returning — it is never stored in
//   tls_state, since nothing past this call needs it again (the shared
//   secret is what the key schedule consumes, Phase 10).
//
// Input/Arguments:
//   x0 — pointer to the output buffer (see tls_server_hello_write)
//
// Output/Returns:
//   carry clear (success):
//     x0 — total message length. tls_state's server_random,
//          server_key_share and shared_secret are filled in.
//   carry set (failure):
//     x0 — TLS_ALERT_INTERNAL_ERROR (the RNG failed — see
//          crypto_random_bytes)
//
// Clobbered Registers:
//   x0-x15, x19, x30 (x19, x30 saved/restored), NZCV
//
// Stack Usage:
//   48 bytes: x19, x30, and a 32-byte ephemeral scalar buffer
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_build_server_hello
tls_build_server_hello:
    sub     sp, sp, #48
    str     x19, [sp]
    str     x30, [sp, #8]
    mov     x19, x0                         // out buffer, saved across calls

    adr_l   x12, tls_state
    add     x0, x12, #TLS_SERVER_RANDOM
    mov     x1, #TLS_RANDOM_LEN
    bl      crypto_random_bytes
    b.cs    .Lbsh_rng_fail

    // ── ephemeral X25519 scalar ──────────────────────────────────
    add     x0, sp, #16
    mov     x1, #32
    bl      crypto_random_bytes
    b.cs    .Lbsh_rng_fail

    adr_l   x12, tls_state                  // x12 is caller-saved — reload
    add     x0, x12, #TLS_SERVER_KEY_SHARE
    add     x1, sp, #16                     // scalar
    adr_l   x2, x25519_basepoint9
    bl      x25519

    adr_l   x12, tls_state
    add     x0, x12, #TLS_SHARED_SECRET
    add     x1, sp, #16                     // scalar
    add     x2, x12, #TLS_CLIENT_KEY_SHARE
    bl      x25519

    // wipe the ephemeral private scalar
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]

    mov     x0, x19
    bl      tls_server_hello_write
    cmn     xzr, xzr                        // success — carry clear
    ldr     x19, [sp]
    ldr     x30, [sp, #8]
    add     sp, sp, #48
    ret

.Lbsh_rng_fail:
    stp     xzr, xzr, [sp, #16]
    stp     xzr, xzr, [sp, #32]
    mov     x0, #TLS_ALERT_INTERNAL_ERROR
    cmp     xzr, xzr                        // failure — carry set
    ldr     x19, [sp]
    ldr     x30, [sp, #8]
    add     sp, sp, #48
    ret
