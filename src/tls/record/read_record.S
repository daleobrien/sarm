// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/read_record.S — read one full TLS record off a
//   file descriptor (RFC 8446 §5.1)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.extern raw_read_exact
.extern tls_record_parse

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_read_record
//
// Description: The network-level counterpart to tls_record_parse: read
//   one complete TLS record off a file descriptor into a caller
//   buffer, then hand it to tls_record_parse for the real validation.
//   tls_record_parse only ever sees an already-fully-buffered record —
//   it has no way to know how many more bytes to pull off the wire —
//   so this function does exactly that: read the fixed 5-byte header
//   with raw_read_exact (which blocks until all 5 bytes arrive or the
//   connection ends), read the fragment_length field out of it to know
//   how many more bytes the fragment holds, read exactly that many
//   more bytes, then delegate to tls_record_parse for type/version/
//   length validation and to hand back the parsed fields. Used both
//   for the handshake (reading the ClientHello and later the client's
//   Finished, tls_server_handshake) and by
//   transport_read's own TRANSPORT_TLS branch to pull the next
//   application_data record off the wire post-handshake.
//
//   Deliberately built on raw_read_exact rather than transport_read:
//   transport_read dispatches on transport_mode, and once a connection
//   is TLS-protected that dispatch lands right back in the branch that
//   calls this function — going through transport_read here would
//   recurse. raw_read_exact is the mode-independent primitive both
//   transport_read's PLAIN path and this function build on.
//
// Input/Arguments:
//   x0 — file descriptor
//   x1 — pointer to the destination buffer
//   x2 — destination buffer capacity in bytes (must be
//        >= TLS_RECORD_HEADER_LEN; records whose total length exceeds
//        this are rejected without being fully read off the wire)
//
// Output/Returns:
//   carry clear (success):
//     x0 — content type (20..23)
//     x1 — pointer to the fragment (buf + TLS_RECORD_HEADER_LEN)
//     x2 — fragment length in bytes
//     x3 — total record length (header + fragment)
//   carry set (failure):
//     x0 — TLS_RECORD_ERR_SHORT (I/O error or EOF while reading) /
//          _LENGTH (record too large for the destination buffer) /
//          _TYPE / _VERSION / _BOUNDS (from tls_record_parse, once the
//          full record is in memory)
//
// Clobbered Registers:
//   x0-x3, x5-x7, x9-x10, x16, NZCV (x19-x22, x30 saved/restored)
//
// Stack Usage:
//   48 bytes: x19-x22, x30 (padded)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_read_record
tls_read_record:
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x19, x0                     // fd
    mov     x20, x1                     // buf
    mov     x21, x2                     // buf_cap

    mov     x0, x19
    mov     x1, x20
    mov     x2, #TLS_RECORD_HEADER_LEN
    bl      raw_read_exact
    b.cs    .Lrr_ioerr

    ldrb    w9, [x20, #3]
    ldrb    w10, [x20, #4]
    orr     w9, w10, w9, lsl #8         // fragment length (big-endian)
    add     x22, x9, #TLS_RECORD_HEADER_LEN  // total record length
    cmp     x22, x21
    b.hi    .Lrr_toolong

    mov     x0, x19
    add     x1, x20, #TLS_RECORD_HEADER_LEN
    mov     x2, x9
    bl      raw_read_exact
    b.cs    .Lrr_ioerr

    mov     x0, x20
    mov     x1, x22
    bl      tls_record_parse           // carry/x0..x3 propagate as-is

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
.Lrr_toolong:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrr_fail
.Lrr_ioerr:
    mov     x0, #TLS_RECORD_ERR_SHORT
.Lrr_fail:
    cmp     xzr, xzr                    // failure — carry set
    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_read_record_prefilled
//
// Description: Same job as tls_read_record, for callers where some of
//   this record's bytes are already sitting at the front of the
//   destination buffer instead of still on the wire (Plan.md Phase 2,
//   Step 9: main.S's real first read, which replaced the old MSG_PEEK,
//   may already have pulled some or all of the ClientHello record off
//   the socket before tls_server_handshake gets to run). Reads only
//   the shortfall — the header bytes not already present, then the
//   fragment bytes not already present — instead of blocking to read
//   bytes that already arrived.
//
//   Scope note: this exists for the ClientHello read only (the one
//   place bytes can already be buffered before any TLS code has run).
//   A conforming TLS 1.3 client's first flight is exactly one
//   ClientHello record — nothing else arrives before the server sends
//   its ServerHello (RFC 8446 §4.1.2) — so x3 bytes already present
//   amounting to more than this one record is treated as a protocol
//   error (TLS_RECORD_ERR_LENGTH) rather than threading a general
//   leftover-bytes mechanism through the rest of the handshake and
//   transport_read's TLS branch.
//
// Input/Arguments:
//   x0 — file descriptor
//   x1 — pointer to the destination buffer
//   x2 — destination buffer capacity in bytes
//   x3 — bytes already present at buf[0..x3) (0 behaves exactly like
//        tls_read_record)
//
// Output/Returns:
//   same as tls_read_record; additionally carry set / x0 =
//   TLS_RECORD_ERR_LENGTH if buf[0..x3) held more than this one record
//
// Clobbered Registers:
//   x0-x3, x5-x7, x9-x10, x16, NZCV (x19-x23, x30 saved/restored)
//
// Stack Usage:
//   48 bytes: x19-x23 (x23 alone in an 8 B slot), x30
// ─────────────────────────────────────────────────────────────────────

.global tls_read_record_prefilled
tls_read_record_prefilled:
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x23, [sp, #32]
    str     x30, [sp, #40]
    mov     x19, x0                     // fd
    mov     x20, x1                     // buf
    mov     x21, x2                     // buf_cap
    mov     x23, x3                     // bytes already present in buf

    cmp     x23, #TLS_RECORD_HEADER_LEN
    b.hs    1f
    mov     x0, x19
    add     x1, x20, x23
    mov     x2, #TLS_RECORD_HEADER_LEN
    sub     x2, x2, x23                 // header shortfall
    bl      raw_read_exact
    b.cs    .Lrrp_ioerr
    mov     x23, #TLS_RECORD_HEADER_LEN
1:
    ldrb    w9, [x20, #3]
    ldrb    w10, [x20, #4]
    orr     w9, w10, w9, lsl #8         // fragment length (big-endian)
    add     x22, x9, #TLS_RECORD_HEADER_LEN  // total record length
    cmp     x22, x21
    b.hi    .Lrrp_toolong

    cmp     x23, x22
    b.eq    2f
    b.hi    .Lrrp_toolong               // more already-present bytes than
                                         //   this one record holds
    mov     x0, x19
    add     x1, x20, x23
    sub     x2, x22, x23                // fragment shortfall
    bl      raw_read_exact
    b.cs    .Lrrp_ioerr
2:
    mov     x0, x20
    mov     x1, x22
    bl      tls_record_parse           // carry/x0..x3 propagate as-is

    ldr     x30, [sp, #40]
    ldr     x23, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
.Lrrp_toolong:
    mov     x0, #TLS_RECORD_ERR_LENGTH
    b       .Lrrp_fail
.Lrrp_ioerr:
    mov     x0, #TLS_RECORD_ERR_SHORT
.Lrrp_fail:
    cmp     xzr, xzr                    // failure — carry set
    ldr     x30, [sp, #40]
    ldr     x23, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
