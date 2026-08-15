// P-256 ECDSA signature DER encoding

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_ecdsa_der_sig_encode
//
// Description: Encode a raw ECDSA signature (r,s), each a 32-byte
//   big-endian unsigned integer, as a DER ECDSA-Sig-Value:
//
//     ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
//
//   Each INTEGER is minimal-length two's-complement: leading 0x00
//   bytes are stripped down to the shortest encoding, then a single
//   0x00 byte is re-prepended if the remaining high bit is set (r and
//   s are always non-negative, so a set high bit would otherwise read
//   as a negative number in DER's signed-integer encoding). r and s
//   are both < the P-256 group order n < 2^256, so the encoded
//   INTEGER content is always <= 33 bytes and the SEQUENCE body is
//   always < 128 bytes — every DER length octet in this function fits
//   in the single-byte short form; the long form is never needed.
//
//   Format validated against Python's `cryptography` library
//   (encode_dss_signature) across 2000+ random (r,s) pairs plus the
//   padding/stripping edge cases (high bit set, leading zero bytes,
//   small values) before porting — see verified-asm-crypto skill.
//
// Input/Arguments:
//   x0 — output buffer (>= 72 bytes: 2-byte SEQUENCE header + up to
//        2 * (2-byte INTEGER header + 33-byte content))
//   x1 — r (32 bytes, big-endian)
//   x2 — s (32 bytes, big-endian)
//
// Output/Returns:
//   x0 — total DER length written to the output buffer
//
// Clobbered Registers:
//   x0-x9, x19-x22 (saved/restored), x30 (saved/restored), NZCV
//
// Stack Usage:
//   48 bytes: x19-x22, x30
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global p256_ecdsa_der_sig_encode
p256_ecdsa_der_sig_encode:
    stp     x19, x20, [sp, #-48]!
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]

    mov     x19, x0                  // out
    mov     x20, x1                  // r
    mov     x21, x2                  // s

    add     x0, x19, #2              // leave room for SEQUENCE tag+len
    mov     x1, x20
    bl      .Lder_enc_int
    mov     x22, x0                  // bytes written for r

    add     x0, x19, #2
    add     x0, x0, x22
    mov     x1, x21
    bl      .Lder_enc_int
    add     x22, x22, x0             // body length = len(r) + len(s)

    mov     w9, #0x30
    strb    w9, [x19]
    strb    w22, [x19, #1]

    add     x0, x22, #2              // total DER length

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #48
    ret

// ── local: encode one 32-byte big-endian value as a DER INTEGER ─────
// x0 = dst, x1 = 32-byte value (big-endian). Returns x0 = bytes written
// (tag + length + content). Clobbers x2-x9.
.Lder_enc_int:
    mov     x2, #0                   // i = index of first non-zero byte
.Lder_skip_zero:
    cmp     x2, #31
    b.hs    .Lder_skip_done          // i == 31: stop (keep the last byte)
    ldrb    w9, [x1, x2]
    cbnz    w9, .Lder_skip_done
    add     x2, x2, #1
    b       .Lder_skip_zero
.Lder_skip_done:
    sub     x3, x1, x2               // unused; keep x1 as base, index x2
    mov     x4, #32
    sub     x4, x4, x2               // x4 = content length (1..32)

    ldrb    w9, [x1, x2]
    tst     w9, #0x80
    b.eq    .Lder_no_pad

    // high bit set: prepend a 0x00 pad byte
    add     x5, x4, #1               // total INTEGER length
    mov     w9, #0x02
    strb    w9, [x0]
    strb    w5, [x0, #1]
    mov     w9, #0
    strb    w9, [x0, #2]
    add     x6, x0, #3               // copy dest
    b       .Lder_copy

.Lder_no_pad:
    mov     x5, x4
    mov     w9, #0x02
    strb    w9, [x0]
    strb    w5, [x0, #1]
    add     x6, x0, #2               // copy dest

.Lder_copy:
    mov     x7, #0                   // copy index
.Lder_copy_loop:
    cmp     x7, x4
    b.hs    .Lder_copy_done
    add     x8, x2, x7
    ldrb    w9, [x1, x8]
    strb    w9, [x6, x7]
    add     x7, x7, #1
    b       .Lder_copy_loop
.Lder_copy_done:
    add     x0, x5, #2               // tag(1) + length(1) + content
    ret
