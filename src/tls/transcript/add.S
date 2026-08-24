// ─────────────────────────────────────────────────────────────────────
// File: src/tls/transcript/add.S — feed one handshake message into the transcript
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_transcript_add
//
// Description: Feed one complete handshake message into the transcript
//   in its wire form: the 1-octet HandshakeType, the 3-octet big-endian
//   length (the body length, RFC 8446 §4), then the message body (RFC
//   8446 §4.4.1). The record-layer header is not part of the
//   transcript. Messages must be fed in the exact order they are
//   exchanged — the transcript is order-sensitive by construction.
//
//   The header is synthesised here so every caller hashes the message
//   exactly as it appears on the wire; a caller that already holds the
//   header+body bytes in one buffer may equally pass type + the body
//   pointer. len must fit the uint24 length field (<= 16,777,215), the
//   RFC 8446 §4 bound on handshake message length; len == 0 is valid
//   (empty body, msg is then ignored).
//
// Input/Arguments:
//   x0 — HandshakeType octet (e.g. TLS_HS_CLIENT_HELLO)
//   x1 — pointer to the message body (ignored when len == 0)
//   x2 — body length in bytes (0..0xFFFFFF)
//
// Output/Returns:
//   none (void) - the transcript is updated in place
//
// Clobbered Registers:
//   x0-x7, x19-x22 (saved/restored), x30 (saved/restored), v0-v7, v16,
//   v18, v19, NZCV — everything sha256_update clobbers
//
// Stack Usage:
//   32 bytes - x19 (msg) + x20 (len) + x30, plus the 4-byte header
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_transcript_add
    sub     sp, sp, #32
    stp     x19, x20, [sp]
    str     x30, [sp, #16]

    mov     x19, x1                     // msg — live across the header update
    mov     x20, x2                     // len — live across the header update

    // ── wire header: HandshakeType(1) || uint24 length(3), big-endian ──
    strb    w0, [sp, #24]               // type
    lsr     x3, x20, #16
    strb    w3, [sp, #25]               // length >> 16
    lsr     x3, x20, #8
    strb    w3, [sp, #26]               // length >> 8
    strb    w20, [sp, #27]              // length & 0xff

    adr_l   x0, tls_transcript_ctx
    add     x1, sp, #24
    mov     x2, #4
    bl      sha256_update               // absorb the 4-byte header

    // ── the message body ──
    adr_l   x0, tls_transcript_ctx
    mov     x1, x19
    mov     x2, x20
    bl      sha256_update               // len == 0: no-op, msg ignored

    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #32
    ret
ENDFUNC tls_transcript_add
