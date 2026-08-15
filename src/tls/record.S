// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// File: record.S — TLS 1.3 record layer (PLAN.MD Phase 11)
//
// The record layer (RFC 8446 §5) sits between the transport and the
// handshake/application protocols. Every TLS message crosses the wire
// inside a record:
//
//     TLSPlaintext:
//       type(1) || legacy_record_version(2) || length(2) || fragment
//
// Before the handshake keys exist records are written in the clear
// (tls_record_parse / tls_record_write). Once record protection is
// active every record is a TLSCiphertext (RFC 8446 §5.2): outer type
// 23 (application_data), with the plaintext `content || type ||
// padding` protected by AES-128-GCM — tls_record_encrypt /
// tls_record_decrypt. The per-record nonce is the 12-byte write IV
// XORed with the 64-bit record sequence number left-padded to 12 bytes
// (§5.3), and the AEAD additional data is the 5-byte record header
// itself (§5.2), so the header is authenticated.
//
// Sequence numbers are per-connection and per-direction, kept in
// tls_state as tls_client_seq / tls_server_seq (src/tls/data.S, offsets
// TLS_CLIENT_SEQ / TLS_SERVER_SEQ). The caller takes one per record
// with tls_record_next_client_seq / tls_record_next_server_seq — which
// increment the stored counter exactly once — and passes it to
// encrypt/decrypt. The RFC requires the sequence to reset to zero at
// the start of a connection and on every key change (§5.3); the key
// schedule (Phase 10+) writes 0 to the tls_*_seq fields when it
// installs new keys.
//
// Conventions:
//   * every function signals failure with the carry flag set and a
//     TLS_RECORD_ERR_* code (defs.S) in x0;
//   * bounds are checked strictly — nothing reads past the supplied
//     buffer, and the length checks mirror RFC 8446 §5.1/§5.2
//     (plaintext ≤ 2^14, ciphertext ≤ 2^14 + 256 on the wire);
//   * the record-layer legacy_record_version is accepted as 0x0303
//     (every record) or 0x0301 (an initial ClientHello, §5.1);
//   * zero-length handshake fragments are rejected on write/encrypt
//     (§5.1, §5.4).
//
// Exported Symbols:
//   tls_record_parse           — tls_record_parse(buf=x0, buf_len=x1)
//   tls_record_write           — tls_record_write(type=x0, frag=x1,
//                                frag_len=x2, out=x3)
//   tls_record_nonce           — tls_record_nonce(iv=x0, seq=x1, out=x2)
//   tls_record_encrypt         — tls_record_encrypt(type=x0, pt=x1,
//                                pt_len=x2, key=x3, iv=x4, seq=x5,
//                                out=x6)
//   tls_record_decrypt         — tls_record_decrypt(rec=x0, rec_len=x1,
//                                key=x2, iv=x3, seq=x4, out=x5)
//   tls_record_next_client_seq — tls_record_next_client_seq()
//   tls_record_next_server_seq — tls_record_next_server_seq()
//
// ─────────────────────────────────────────────────────────────────────

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
.global tls_record_parse
tls_record_parse:
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

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_write
//
// Description: Generate one plaintext TLS record (PLAN.MD §11.2): the
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
//   x0-x4, x19, x20 (saved/restored), x30 (saved/restored), NZCV
//
// Stack Usage:
//   32 bytes - x19 (out) + x20 (frag_len) + x30
// ─────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_nonce
//
// Description: Build the TLS 1.3 per-record nonce (RFC 8446 §5.3): the
//   static write IV XORed with the 64-bit record sequence number
//   encoded big-endian and left-padded with four zero bytes:
//
//       nonce = iv XOR ( 0x00000000 || seq )
//
//   The first four bytes of the output equal the first four IV bytes;
//   the last eight are iv[4..11] XOR seq(big-endian). Exposed for
//   testing and so the handshake can verify the construction.
//
// Input/Arguments:
//   x0 — pointer to the 12-byte write IV
//   x1 — the 64-bit record sequence number
//   x2 — pointer to the 12-byte nonce output buffer
//
// Output/Returns:
//   none (void) - 12 nonce bytes written to [x2]
//
// Clobbered Registers:
//   x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.align 2
.global tls_record_nonce
tls_record_nonce:
    rev     x3, x1                  // sequence number, big-endian
    ldr     x4, [x0, #4]            // iv[4..11]
    eor     x3, x3, x4              // iv[4..11] XOR seq
    ldr     x4, [x0]                // iv[0..7]
    str     x4, [x2]                // out[0..7] = iv[0..7]
    str     x3, [x2, #4]            // out[4..11] = iv[4..11] XOR seq
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_encrypt
//
// Description: Seal one plaintext fragment into a TLS 1.3
//   TLSCiphertext record (PLAN.MD §11.3, RFC 8446 §5.2): the outer
//   header is `23 03 03 len(2)` with length = pt_len + 1 + 16, the
//   AEAD plaintext is `fragment || inner_content_type` (no padding is
//   ever added), the additional data is the 5-byte header itself, and
//   the nonce is the write IV XORed with the record sequence number
//   (tls_record_nonce). The ciphertext and 16-byte tag are written
//   after the header, in place over the plaintext, so the output
//   buffer needs 5 + pt_len + 1 + 16 bytes. A zero-length handshake or
//   alert content is rejected (§5.4 — the inner type byte alone would
//   have nothing to label).
//
// Input/Arguments:
//   x0 — inner content type (20..23)
//   x1 — pointer to the plaintext fragment (ignored when pt_len == 0)
//   x2 — fragment length in bytes (0..TLS_MAX_PLAINTEXT)
//   x3 — pointer to the 16-byte AES-128 write key
//   x4 — pointer to the 12-byte write IV
//   x5 — the 64-bit record sequence number
//   x6 — pointer to the output buffer (>= 5 + pt_len + 17 bytes)
//
// Output/Returns:
//   carry clear (success): x0 — total record length (5 + pt_len + 17)
//   carry set (failure):   x0 — TLS_RECORD_ERR_TYPE / _LENGTH / _EMPTY
//
// Clobbered Registers:
//   x0-x12, x19-x24 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   80 bytes - x19-x24 + x30, plus a 16-byte nonce scratch
// ─────────────────────────────────────────────────────────────────────

.align 2
.global tls_record_encrypt
tls_record_encrypt:
    sub     sp, sp, #80
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0                 // inner content type
    mov     x20, x2                 // plaintext length
    mov     x21, x3                 // key
    mov     x22, x4                 // write IV
    mov     x23, x5                 // sequence number
    mov     x24, x6                 // output buffer

    // ── validate: type in {20..23}, length within the plaintext
    //    limit, zero-length handshake/alert content is forbidden ──
    sub     w5, w19, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w5, #4
    b.hs    .Lrec_enc_type
    cmp     x20, #TLS_MAX_PLAINTEXT
    b.hi    .Lrec_enc_length
    cbz     x20, .Lrec_enc_zero
    b       .Lrec_enc_go
.Lrec_enc_zero:
    cmp     w19, #TLS_RECORD_HANDSHAKE
    b.eq    .Lrec_enc_empty
    cmp     w19, #TLS_RECORD_ALERT
    b.eq    .Lrec_enc_empty
.Lrec_enc_go:
    // ── outer header: type 23, version 0x0303, length = pt_len + 17 ──
    mov     w5, #TLS_RECORD_APPLICATION_DATA
    strb    w5, [x24]
    mov     w5, #0x03
    strb    w5, [x24, #1]
    strb    w5, [x24, #2]
    add     x5, x20, #(TLS_INNER_TYPE_LEN + TLS_TAG_LEN)
    lsr     x6, x5, #8
    strb    w6, [x24, #3]
    strb    w5, [x24, #4]

    // ── copy the fragment to out+5 (the plaintext, in place) ──
    add     x0, x24, #TLS_RECORD_HEADER_LEN
    bl      memcpy                  // x1 = pt, x2 = pt_len still live

    // ── append the inner content type to the plaintext ──
    add     x5, x24, x20
    add     x5, x5, #TLS_RECORD_HEADER_LEN
    strb    w19, [x5]

    // ── per-record nonce at [sp, #56] ──
    mov     x0, x22
    mov     x1, x23
    add     x2, sp, #56
    bl      tls_record_nonce

    // ── seal in place; aad = the 5-byte header just written ──
    mov     x0, x21                 // key
    add     x1, sp, #56             // nonce
    mov     x2, x24                 // aad = record header
    mov     x3, #TLS_RECORD_HEADER_LEN
    add     x4, x24, #TLS_RECORD_HEADER_LEN   // pt / ct (in place)
    add     x5, x20, #TLS_INNER_TYPE_LEN      // pt_len + 1
    mov     x6, x4                  // ct == pt (in place is safe)
    add     x7, x4, x5              // tag at out + 5 + pt_len + 1
    bl      aes_gcm_encrypt

    add     x0, x20, #(TLS_RECORD_HEADER_LEN + TLS_INNER_TYPE_LEN + TLS_TAG_LEN)
    cmn     xzr, xzr                // success — carry clear
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
.Lrec_enc_type:
    mov     x0, #TLS_RECORD_ERR_TYPE
    b       .Lrec_enc_fail
.Lrec_enc_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrec_enc_fail
.Lrec_enc_empty:
    mov     x0, #TLS_RECORD_ERR_EMPTY
.Lrec_enc_fail:
    cmp     xzr, xzr                // failure — carry set
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_decrypt
//
// Description: Open one TLS 1.3 TLSCiphertext record (RFC 8446 §5.2):
//   the AEAD is checked with the 5-byte record header as additional
//   data and the nonce from the read IV and the sequence number; only
//   on a successful tag check is the plaintext written, so a bad tag
//   leaves the output untouched and returns TLS_RECORD_ERR_MAC (the
//   RFC 8446 "bad_record_mac" condition). The inner plaintext is
//   `content || type || zeros(padding)`: the last non-zero octet is
//   the content type and everything after it is padding, which is
//   zero by construction (§5.4). An all-zero plaintext — the malformed
//   case of Appendix C.3 — is rejected as TLS_RECORD_ERR_INNER, as is
//   an inner content type outside 20..23. The record must carry at
//   least 17 fragment bytes (the tag plus the inner type byte) and at
//   most TLS_MAX_AEAD (the AES-128-GCM bound). The outer header type
//   and version are not re-validated here: the caller parses them
//   first (tls_record_parse), and the header bytes are consumed
//   verbatim as the AEAD additional data, which binds them.
//
// Input/Arguments:
//   x0 — pointer to the record buffer (header + ciphertext + tag)
//   x1 — number of bytes available in the buffer
//   x2 — pointer to the 16-byte AES-128 read key
//   x3 — pointer to the 12-byte read IV
//   x4 — the 64-bit record sequence number
//   x5 — pointer to the plaintext output buffer (>= len - 16 bytes)
//
// Output/Returns:
//   carry clear (success):
//     x0 — content length in bytes (padding and the type byte removed)
//     x1 — inner content type (20..23)
//   carry set (failure):
//     x0 — TLS_RECORD_ERR_SHORT / _LENGTH / _BOUNDS / _MAC / _INNER
//
// Clobbered Registers:
//   x0-x12, x19-x24 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, NZCV
//
// Stack Usage:
//   80 bytes - x19-x24 + x30, plus a 16-byte nonce scratch
// ─────────────────────────────────────────────────────────────────────

.align 2
.global tls_record_decrypt
tls_record_decrypt:
    sub     sp, sp, #80
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0                 // record buffer (header + ct + tag)
    mov     x20, x5                 // plaintext output
    mov     x21, x2                 // key
    mov     x22, x3                 // read IV
    mov     x23, x4                 // sequence number

    cmp     x1, #TLS_RECORD_HEADER_LEN
    b.lo    .Lrec_dec_short
    ldrb    w6, [x19, #3]
    ldrb    w7, [x19, #4]
    orr     w6, w7, w6, lsl #8      // TLSCiphertext.length (big-endian)
    // length = ct + tag; the smallest valid record is the tag plus the
    // inner type byte, and the largest is the AES-128-GCM bound.
    cmp     w6, #(TLS_TAG_LEN + TLS_INNER_TYPE_LEN)
    b.lo    .Lrec_dec_length
    mov     w7, #TLS_MAX_AEAD
    cmp     w6, w7
    b.hi    .Lrec_dec_length
    add     x7, x6, #TLS_RECORD_HEADER_LEN
    cmp     x7, x1
    b.hi    .Lrec_dec_bounds
    sub     x24, x6, #TLS_TAG_LEN   // plaintext length (content + type)

    // ── per-record nonce at [sp, #56] ──
    mov     x0, x22
    mov     x1, x23
    add     x2, sp, #56
    bl      tls_record_nonce

    // ── open; aad = the 5-byte header, tag is the last 16 bytes ──
    mov     x0, x21                 // key
    add     x1, sp, #56             // nonce
    mov     x2, x19                 // aad = record header
    mov     x3, #TLS_RECORD_HEADER_LEN
    add     x4, x19, #TLS_RECORD_HEADER_LEN   // ciphertext
    mov     x5, x24                 // ct_len
    add     x6, x4, x5              // tag
    mov     x7, x20                 // plaintext output
    bl      aes_gcm_decrypt         // x0 = 1 verified, 0 bad tag

    cbz     x0, .Lrec_dec_mac

    // ── find the inner content type: scan from the end for the first
    //    non-zero octet; everything after it is padding (§5.4) ──
    add     x5, x20, x24            // one past the last plaintext byte
    mov     x6, x24                 // plaintext length remaining
.Lrec_dec_scan:
    cbz     x6, .Lrec_dec_inner     // scanned the whole plaintext: zeros
    ldrb    w7, [x5, #-1]!
    sub     x6, x6, #1
    cbz     w7, .Lrec_dec_scan
    sub     w7, w7, #TLS_RECORD_CHANGE_CIPHER_SPEC
    cmp     w7, #4                  // inner type in 20..23?
    b.hs    .Lrec_dec_inner
    mov     x0, x6                  // content length (bytes before the type)
    ldrb    w1, [x5]                // inner content type
    cmn     xzr, xzr                // success — carry clear
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret
.Lrec_dec_short:
    mov     x0, #TLS_RECORD_ERR_SHORT
    b       .Lrec_dec_fail
.Lrec_dec_length:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrec_dec_fail
.Lrec_dec_bounds:
    mov     x0, #TLS_RECORD_ERR_BOUNDS
    b       .Lrec_dec_fail
.Lrec_dec_mac:
    mov     x0, #TLS_RECORD_ERR_MAC
    b       .Lrec_dec_fail
.Lrec_dec_inner:
    mov     x0, #TLS_RECORD_ERR_INNER
.Lrec_dec_fail:
    cmp     xzr, xzr                // failure — carry set
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #80
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_next_client_seq / tls_record_next_server_seq
//
// Description: Take the next record sequence number for one direction
//   (PLAN.MD §11.4): return the current value of the per-connection
//   counter (tls_client_seq / tls_server_seq in src/tls/data.S) and
//   increment that counter exactly once. RFC 8446 §5.3: the sequence
//   starts at zero and is incremented after every record read or
//   written under the current keys, independently per direction — so
//   the caller does `bl tls_record_next_server_seq; bl
//   tls_record_encrypt` with the returned value once per record. On a
//   key change the key schedule resets the counter to zero.
//
// Input/Arguments:
//   none
//
// Output/Returns:
//   x0 — the current sequence number (the counter now holds seq + 1)
//
// Clobbered Registers:
//   x0-x2
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.align 2
.global tls_record_next_client_seq
tls_record_next_client_seq:
    adr_l   x1, tls_client_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret

.align 2
.global tls_record_next_server_seq
tls_record_next_server_seq:
    adr_l   x1, tls_server_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret
