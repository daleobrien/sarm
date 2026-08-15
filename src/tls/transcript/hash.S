// ─────────────────────────────────────────────────────────────────────
// File: src/tls/transcript/hash.S — snapshot the current transcript hash
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

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

.text
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
