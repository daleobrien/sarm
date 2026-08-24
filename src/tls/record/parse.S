// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/parse.S — TLS record parsing (RFC 8446 §5.1)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_parse
//
// Description: Parse one TLS record (RFC 8446 §5.1) from the front of a
//   buffer with strict bounds checking: the 1-octet content type, the
//   2-octet legacy_record_version and the 2-octet fragment length are
//   validated before the fragment pointer is handed out, and the
//   fragment is never allowed to run past the end of the buffer. A
//   plaintext record (type 20/21/22) may carry at most 2^14 fragment
//   bytes; an application_data record (type 23 — the outer type of
//   every ciphertext) may carry up to the 2^14 + 256 wire limit
//   (§5.2). Multiple coalesced records in one buffer are handled by
//   the caller: x3 reports the total record length to consume.
//
// Input/Arguments:
//   x0 — pointer to the buffer holding the record
//   x1 — number of bytes available in the buffer
//
// Output/Returns:
//   carry clear (success):
//     x0 — content type (20..23)
//     x1 — pointer to the fragment (buf + TLS_RECORD_HEADER_LEN)
//     x2 — fragment length in bytes
//     x3 — total record length (header + fragment)
//   carry set (failure):
//     x0 — TLS_RECORD_ERR_SHORT / _TYPE / _VERSION / _LENGTH / _BOUNDS
//
// Clobbered Registers:
//   x0-x3 (results), x5-x7, x9, x10, NZCV
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_record_parse
    cmp     x1, #TLS_RECORD_HEADER_LEN
    b.lo    .Lrec_parse_short
    mov     x9, x0                  // buf — live across the header checks
    mov     x10, x1                 // buf_len
    ldrb    w5, [x9]                // content type
    sub     w6, w5, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w6, #4                  // 20 <= type <= 23?
    b.hs    .Lrec_parse_type
    ldrb    w6, [x9, #1]
    ldrb    w7, [x9, #2]
    orr     w6, w7, w6, lsl #8      // legacy_record_version (big-endian)
    cmp     w6, #TLS_VERSION_1_2    // 0x0303 — every record but the first
    b.eq    .Lrec_parse_len
    cmp     w6, #TLS_VERSION_1_0    // 0x0301 — an initial ClientHello only
    b.ne    .Lrec_parse_version
.Lrec_parse_len:
    ldrb    w6, [x9, #3]
    ldrb    w7, [x9, #4]
    orr     w6, w7, w6, lsl #8      // fragment length (big-endian)
    // The 2^14 plaintext limit applies to types 20-22; type 23 (the
    // outer type of every ciphertext) may reach the wire limit.
    cmp     w5, #TLS_RECORD_APPLICATION_DATA
    b.eq    .Lrec_parse_ct_max
    cmp     w6, #TLS_MAX_PLAINTEXT
    b.hi    .Lrec_parse_length
    b       .Lrec_parse_bounds
.Lrec_parse_ct_max:
    mov     w7, #TLS_MAX_CIPHERTEXT
    cmp     w6, w7
    b.hi    .Lrec_parse_length
.Lrec_parse_bounds:
    add     x7, x6, #TLS_RECORD_HEADER_LEN
    cmp     x7, x10
    b.hi    .Lrec_parse_bounds_err
    mov     x0, x5                  // content type
    add     x1, x9, #TLS_RECORD_HEADER_LEN  // fragment
    mov     x2, x6                  // fragment length
    add     x3, x6, #TLS_RECORD_HEADER_LEN  // total record length
    cmn     xzr, xzr                // success — carry clear
    ret
.Lrec_parse_short:
    mov     x0, #TLS_RECORD_ERR_SHORT
    cmp     xzr, xzr                // failure — carry set
    ret
.Lrec_parse_type:
    mov     x0, #TLS_RECORD_ERR_TYPE
    cmp     xzr, xzr
    ret
.Lrec_parse_version:
    mov     x0, #TLS_RECORD_ERR_VERSION
    cmp     xzr, xzr
    ret
.Lrec_parse_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    cmp     xzr, xzr
    ret
.Lrec_parse_bounds_err:
    mov     x0, #TLS_RECORD_ERR_BOUNDS
    cmp     xzr, xzr
    ret
ENDFUNC tls_record_parse
