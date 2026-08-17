// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_build_server_hello
//
// Description: Generate the ephemeral X25519 key pair and shared
//   secret, then write the ServerHello. Requires
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
//   x0-x17, NZCV (x19, x30 saved/restored)
//
// Stack Usage:
//   48 bytes: x19, x30, and a 32-byte ephemeral scalar buffer
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

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
