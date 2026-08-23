// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/write.S — TLS plaintext record writing (RFC 8446 §5.1)
// ─────────────────────────────────────────────────────────────────────
#include "../../defs.S"


// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_write
//
// Description: Generate one plaintext TLS record: the
//   5-byte header — type, legacy_record_version 0x0303, big-endian
//   length — followed by a copy of the fragment. The fragment must be
//   at most 2^14 bytes; a zero-length handshake fragment is rejected
//   (RFC 8446 §5.1 — senders MUST NOT emit one).
//
// Input/Arguments:
//   x0 — content type (20..23)
//   x1 — pointer to the fragment (ignored when frag_len == 0)
//   x2 — fragment length in bytes (0..TLS_MAX_PLAINTEXT)
//   x3 — pointer to the output buffer (>= 5 + frag_len bytes)
//
// Output/Returns:
//   carry clear (success): x0 — total record length (5 + frag_len)
//   carry set (failure):   x0 — TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
//
// Clobbered Registers:
//   x0-x4, NZCV (x19, x20, x30 saved/restored)
//
// Stack Usage:
//   32 bytes - x19 (out) + x20 (frag_len) + x30
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_record_write
tls_record_write:
    sub     sp, sp, #32
    stp     x19, x20, [sp]
    str     x30, [sp, #16]
    mov     x19, x3                 // out — live across the fragment copy
    mov     x20, x2                 // frag_len

    sub     w4, w0, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w4, #4
    b.hs    .Lrec_write_type
    cmp     x20, #TLS_MAX_PLAINTEXT
    b.hi    .Lrec_write_length
    cbz     x20, .Lrec_write_zero
    b       .Lrec_write_go
.Lrec_write_zero:
    cmp     w0, #TLS_RECORD_HANDSHAKE
    b.eq    .Lrec_write_empty
.Lrec_write_go:
    strb    w0, [x19]               // type
    mov     w4, #0x03
    strb    w4, [x19, #1]
    strb    w4, [x19, #2]           // legacy_record_version = 0x0303
    lsr     x4, x20, #8
    strb    w4, [x19, #3]
    strb    w20, [x19, #4]          // length, big-endian
    add     x0, x19, #TLS_RECORD_HEADER_LEN
    bl      memcpy                  // copy the fragment (x1, x2 live)
    add     x0, x20, #TLS_RECORD_HEADER_LEN
    cmn     xzr, xzr                // success — carry clear
    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #32
    ret
.Lrec_write_type:
    mov     x0, #TLS_RECORD_ERR_TYPE
    b       .Lrec_write_fail
.Lrec_write_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrec_write_fail
.Lrec_write_empty:
    mov     x0, #TLS_RECORD_ERR_EMPTY
.Lrec_write_fail:
    cmp     xzr, xzr                // failure — carry set
    ldr     x30, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #32
    ret
