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

#include "../../../defs.S"

.text
.align 2
FUNC tls_server_hello_write
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
ENDFUNC tls_server_hello_write
