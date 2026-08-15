// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// File: transcript.S — TLS 1.3 handshake transcript (PLAN.MD Phase 9)
//
// The transcript is the running SHA-256 over every handshake message in
// the exact order they are exchanged, each in its wire form:
//
//     transcript = SHA256( msg1 || msg2 || ... || msgN )
//     msg_i      = HandshakeType(1) || uint24 length(3) || body
//
// RFC 8446 §4.4.1 — the handshake message headers are included; the
// 5-byte TLS record header is not. The state lives in the
// per-connection global tls_transcript_ctx (src/tls/data.S, a
// SHA256_CTX laid out by the SHA256_CTX_* offsets in defs.S). Like
// tls_state it is a process-global: a connection handler is one
// process, so there is exactly one handshake per process.
//
// Three entry points:
//
//   tls_transcript_init  — start a fresh transcript (PLAN.MD §9.1);
//                          call once per handshake before the
//                          ClientHello arrives.
//   tls_transcript_add   — feed one complete handshake message: the
//                          type octet, the 3-byte big-endian length,
//                          then the body.
//   tls_transcript_hash  — snapshot the current transcript hash into a
//                          32-byte buffer *without* disturbing the
//                          running transcript (PLAN.MD §9.2). The TLS
//                          1.3 key schedule needs the hash at several
//                          points — e.g. hash(ClientHello) for the
//                          handshake secret, then hash(ClientHello ||
//                          ServerHello) for the traffic secrets (RFC
//                          8446 §7.1) — so a snapshot must not destroy
//                          the transcript.
//
// Built on the streaming sha256_init / sha256_update / sha256_final
// from src/crypto/sha256.S; no libc or external crypto required.
//
// Exported Symbols:
//   tls_transcript_init — tls_transcript_init()
//   tls_transcript_add  — tls_transcript_add(type=x0, msg=x1, len=x2)
//   tls_transcript_hash — tls_transcript_hash(out=x0)
//
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_transcript_init
//
// Description: Start a fresh handshake transcript: seed tls_transcript_ctx
//   with the FIPS 180-4 IV and zero the counters (PLAN.MD §9.1). Call
//   before the first handshake message of a connection; any previous
//   transcript is discarded.
//
// Input/Arguments:
//   none
//
// Output/Returns:
//   none (void)
//
// Clobbered Registers:
//   x0, x1, v0, v1 — everything sha256_init clobbers
//
// Stack Usage:
//   none - tail call, no frame
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_transcript_init
tls_transcript_init:
    adrp    x0, tls_transcript_ctx@PAGE
    add     x0, x0, tls_transcript_ctx@PAGEOFF
    b       sha256_init                 // tail call: seed the context

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

.align 2
.global tls_transcript_add
tls_transcript_add:
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

    adrp    x0, tls_transcript_ctx@PAGE
    add     x0, x0, tls_transcript_ctx@PAGEOFF
    add     x1, sp, #24
    mov     x2, #4
    bl      sha256_update               // absorb the 4-byte header

    // ── the message body ──
    adrp    x0, tls_transcript_ctx@PAGE
    add     x0, x0, tls_transcript_ctx@PAGEOFF
    mov     x1, x19
    mov     x2, x20
    bl      sha256_update               // len == 0: no-op, msg ignored

    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #32
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_transcript_hash
//
// Description: Snapshot the current transcript hash (PLAN.MD §9.2): the
//   SHA-256 digest of everything fed so far, written as 32 big-endian
//   bytes to [x0]. The running transcript is *not* touched — the digest
//   is computed by finalising a scratch copy of tls_transcript_ctx — so
//   the handshake can take the hash at several points (e.g.
//   hash(ClientHello) for the handshake secret, then hash(ClientHello
//   || ServerHello) for the server traffic keys, RFC 8446 §7.1) and
//   keep feeding afterwards.
//
// Input/Arguments:
//   x0 — pointer to a 32-byte digest output buffer
//
// Output/Returns:
//   none (void) - 32 digest bytes written to [x0]
//
// Clobbered Registers:
//   x0-x5, x19 (saved/restored), x30 (saved/restored), v0, v1, NZCV —
//   everything sha256_final clobbers
//
// Stack Usage:
//   144 bytes - x19 (out) + x30, plus a 112-byte scratch copy of the
//   SHA256_CTX (SHA256_CTX_SIZE), 16-aligned
// ─────────────────────────────────────────────────────────────────────

.align 2
.global tls_transcript_hash
tls_transcript_hash:
    sub     sp, sp, #144
    stp     x19, x30, [sp]

    mov     x19, x0                     // out — live across the copy
    add     x1, sp, #16                 // scratch ctx (16-aligned)

    // ── copy tls_transcript_ctx into the scratch (14 x 8-byte pairs) ──
    adrp    x2, tls_transcript_ctx@PAGE
    add     x2, x2, tls_transcript_ctx@PAGEOFF
    ldp     x3, x4, [x2, #0]
    stp     x3, x4, [x1, #0]
    ldp     x3, x4, [x2, #16]
    stp     x3, x4, [x1, #16]
    ldp     x3, x4, [x2, #32]
    stp     x3, x4, [x1, #32]
    ldp     x3, x4, [x2, #48]
    stp     x3, x4, [x1, #48]
    ldp     x3, x4, [x2, #64]
    stp     x3, x4, [x1, #64]
    ldp     x3, x4, [x2, #80]
    stp     x3, x4, [x1, #80]
    ldp     x3, x4, [x2, #96]
    stp     x3, x4, [x1, #96]

    // ── finalise the copy; the real context is untouched ──
    mov     x0, x1
    mov     x1, x19
    bl      sha256_final

    ldp     x19, x30, [sp]
    add     sp, sp, #144
    ret
