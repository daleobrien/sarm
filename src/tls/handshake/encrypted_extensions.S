// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/encrypted_extensions.S — EncryptedExtensions
//   generation (RFC 8446 §4.3.1)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_encrypted_extensions_write
//
// Description: Serialize the EncryptedExtensions handshake message (RFC
//   8446 §4.3.1) — the 4-byte handshake header followed by the
//   extensions block — echoing back the ALPN protocol
//   tls_parse_client_hello already negotiated (TLS_ALPN_LEN/TLS_ALPN in
//   tls_state, RFC 7301 §3.1). This server sends exactly one extension:
//   ALPN is the only one this handshake ever negotiates, so no
//   extension-selection logic is needed. Pure serializer — no key
//   material or randomness involved, so it needs no failure mode; the
//   caller is responsible for encrypting the result under the
//   handshake traffic keys (tls_derive_handshake_secrets,
//   tls_record_encrypt) before it goes on the wire, since RFC 8446
//   §4.3.1 requires this to be the first message protected under the
//   server's handshake traffic key.
//
// Input/Arguments:
//   x0 — pointer to the output buffer (>= 4 + 9 + 32 = 45 bytes, the
//        max when the negotiated ALPN name is the longest this server
//        ever records, TLS_ALPN_BUF - 1)
//
// Output/Returns:
//   x0 — total message length (4 + body length), including the
//        handshake header
//
// Clobbered Registers:
//   x0, x1, x9-x14 (x9 = cursor, x10 = body length, x11 = ALPN length,
//   x12 = tls_state base — persist across the whole function; x13, x14
//   are free scratch)
//
// Stack Usage:
//   none — leaf function, no calls out
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_encrypted_extensions_write
    adr_l   x12, tls_state
    mov     x9, x0                          // cursor
    ldr     x11, [x12, #TLS_ALPN_LEN]

    // ── handshake header: type(1) + length(3), big-endian ────────────
    mov     w13, #TLS_HS_ENCRYPTED_EXTENSIONS
    strb    w13, [x9]
    add     x10, x11, #9                    // body = extensions(2) +
                                             //   ALPN ext(7 + alpn_len)
    lsr     w13, w10, #16
    strb    w13, [x9, #1]
    lsr     w13, w10, #8
    strb    w13, [x9, #2]
    strb    w10, [x9, #3]
    add     x9, x9, #4

    // ── extensions<0..2^16-1>: length = body - 2 ──────────────────────
    sub     x14, x10, #2
    lsr     w13, w14, #8
    strb    w13, [x9]
    strb    w14, [x9, #1]
    add     x9, x9, #2

    // ── ALPN extension: type(2) + length(2) = 3 + alpn_len ───────────
    mov     w13, #TLS_EXT_ALPN
    lsr     w14, w13, #8
    strb    w14, [x9]
    strb    w13, [x9, #1]
    add     x14, x11, #3
    lsr     w13, w14, #8
    strb    w13, [x9, #2]
    strb    w14, [x9, #3]
    add     x9, x9, #4

    // ── ProtocolNameList<2..2^16-1> length = 1 + alpn_len ────────────
    add     x14, x11, #1
    lsr     w13, w14, #8
    strb    w13, [x9]
    strb    w14, [x9, #1]
    add     x9, x9, #2

    // ── ProtocolName: length(1) + the negotiated name ────────────────
    strb    w11, [x9]
    add     x9, x9, #1
    add     x0, x12, #TLS_ALPN
    mov     x1, #0
.Lee_alpn_copy:
    cmp     x1, x11
    b.hs    .Lee_alpn_done
    ldrb    w13, [x0, x1]
    strb    w13, [x9, x1]
    add     x1, x1, #1
    b       .Lee_alpn_copy
.Lee_alpn_done:
    add     x9, x9, x11

    add     x0, x10, #4                     // total message length
    ret
ENDFUNC tls_encrypted_extensions_write
