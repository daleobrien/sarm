// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/client_hello.S — ClientHello parser
//   (RFC 8446 §4.1.2)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// requirement flags — internal to this file only (never returned to
// the caller; the public result is success/failure + a TLS_ALERT_*).
.equ CH_TLS13,      1   // §12.1 — supported_versions offered TLS 1.3
.equ CH_CIPHER,      2   // §12.2 — TLS_AES_128_GCM_SHA256 offered
.equ CH_GROUP,       4   // §12.3 — supported_groups offered X25519
.equ CH_KEYSHARE,    8   // §12.3 — key_share carried an X25519 entry
.equ CH_ALPN,        16  // §12.4 — ALPN offered "h2"
.equ CH_SNI_SEEN,    32  // §12.5 — server_name extension present
.equ CH_SNI_MATCH,   64  // §12.5 — it matched tls_sni_hostname
.equ CH_REQUIRED,    (CH_GROUP + CH_KEYSHARE)

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_parse_client_hello
//
// Description: Parse and validate a TLS 1.3 ClientHello body (RFC 8446
//   §4.1.2) — everything from legacy_version through the end of
//   extensions, i.e. the handshake message *after* its 4-byte
//   type+length header (TLS_HS_HEADER_LEN). Bounds are checked
//   strictly throughout: every variable-length field must fit inside
//   what came before it, and the extensions block must exactly fill
//   the remainder of the buffer, matching the style of
//   src/tls/record/parse.S.
//
//   On success, client_random (§4.1.2), the legacy_session_id (§4.1.3
//   — ServerHello must echo it verbatim even though this server does no
//   resumption with it), and the client's X25519 public key (from the
//   key_share extension, §4.2.8) are copied into tls_state, and the
//   negotiated ALPN protocol ("h2") is recorded there too (§14 will
//   echo it back in EncryptedExtensions). legacy_version and
//   compression methods are structurally validated then discarded.
//
//   Five requirements are enforced, each mapped to the RFC 8446 §6.2
//   alert a real TLS stack would expect:
//     12.1 — supported_versions must offer TLS 1.3 (0x0304), else
//            protocol_version.
//     12.2 — cipher_suites must offer TLS_AES_128_GCM_SHA256 (0x1301),
//            else handshake_failure.
//     12.3 — supported_groups must offer X25519 (0x001D) *and*
//            key_share must carry an X25519 entry, else
//            handshake_failure.
//     12.4 — the ALPN extension must offer "h2", else
//            no_application_protocol.
//     12.5 — if a server_name extension is present, its host_name
//            entry must match tls_sni_hostname, else unrecognized_name.
//            Absent SNI is accepted (no virtual hosts to disambiguate).
//   legacy_compression_methods is also checked against §4.1.2: a TLS
//   1.3 ClientHello MUST carry exactly one byte, value 0 — anything
//   else is illegal_parameter. Any other structural malformation
//   (truncated fields, lengths that don't fit, an extensions block
//   that under/overruns the buffer) is decode_error, checked before
//   any requirement above.
//
// Input/Arguments:
//   x0 — pointer to the ClientHello body (starts at legacy_version)
//   x1 — body length in bytes
//
// Output/Returns:
//   carry clear (success):
//     x0 — 0. tls_client_random, tls_session_id_len, tls_session_id,
//          tls_client_key_share, tls_alpn_len and tls_alpn are filled
//          in (src/tls/data.S).
//   carry set (failure):
//     x0 — TLS_ALERT_DECODE_ERROR / _ILLEGAL_PARAMETER /
//          _PROTOCOL_VERSION / _HANDSHAKE_FAILURE /
//          _NO_APPLICATION_PROTOCOL /
//          _UNRECOGNIZED_NAME
//
// Clobbered Registers:
//   x0-x15 (x9 = cursor, x10 = body end, x11 = requirement flags,
//   x12 = tls_state base, x13 = extensions end — persist across the
//   whole function; x0-x8/x14/x15 are free scratch per field/extension)
//
// Stack Usage:
//   none — leaf function, no calls out
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC tls_parse_client_hello
    // legacy_version(2) + random(32) + session_id length(1) — the
    // fixed-size prefix before any variable-length field.
    cmp     x1, #35
    b.lo    .Lch_decode_error
    add     x10, x0, x1             // end of the ClientHello body
    mov     x9, x0                  // cursor
    mov     x11, #0                 // requirement flags
    adr_l   x12, tls_state

    add     x9, x9, #2              // skip legacy_version — negotiation
                                     // happens via supported_versions

    // ── client_random (§4.1.2): 32 bytes, copied verbatim ──────────
    add     x0, x12, #TLS_CLIENT_RANDOM
    ldp     x14, x15, [x9]
    stp     x14, x15, [x0]
    ldp     x14, x15, [x9, #16]
    stp     x14, x15, [x0, #16]
    add     x9, x9, #TLS_RANDOM_LEN

    // ── legacy_session_id<0..32> — copied into tls_state, then
    // skipped: §4.1.3 requires the ServerHello to echo it verbatim,
    // but this server does no session resumption with it.
    ldrb    w14, [x9]
    add     x9, x9, #1
    cmp     w14, #32
    b.hi    .Lch_decode_error
    add     x0, x9, x14
    cmp     x0, x10
    b.hi    .Lch_decode_error
    str     x14, [x12, #TLS_SESSION_ID_LEN]
    add     x1, x12, #TLS_SESSION_ID
    mov     x2, x9                  // src
    mov     x3, #0                  // copied so far
.Lch_sid_copy:
    cmp     x3, x14
    b.hs    .Lch_sid_done
    ldrb    w4, [x2, x3]
    strb    w4, [x1, x3]
    add     x3, x3, #1
    b       .Lch_sid_copy
.Lch_sid_done:
    mov     x9, x0

    // ── cipher_suites<2..2^16-2> (§12.2) ────────────────────────────
    add     x0, x9, #2
    cmp     x0, x10
    b.hi    .Lch_decode_error
    ldrb    w14, [x9]
    ldrb    w15, [x9, #1]
    orr     w14, w15, w14, lsl #8    // cipher_suites length
    add     x9, x9, #2
    cmp     w14, #2
    b.lo    .Lch_decode_error
    tst     x14, #1
    b.ne    .Lch_decode_error        // odd length — not whole entries
    add     x0, x9, x14
    cmp     x0, x10
    b.hi    .Lch_decode_error
    mov     x1, x9                   // p
    mov     x2, x14                  // remaining
.Lch_cs_scan:
    cbz     x2, .Lch_cs_done
    ldrb    w4, [x1]
    ldrb    w5, [x1, #1]
    orr     w4, w5, w4, lsl #8
    mov     w6, #TLS_CIPHER_AES_128_GCM_SHA256
    cmp     w4, w6
    b.ne    .Lch_cs_next
    orr     x11, x11, #CH_CIPHER
.Lch_cs_next:
    add     x1, x1, #2
    sub     x2, x2, #2
    b       .Lch_cs_scan
.Lch_cs_done:
    add     x9, x9, x14

    // ── legacy_compression_methods (§4.1.2) — a TLS 1.3 ClientHello
    // MUST carry exactly one byte, value 0 ("null"); anything else is
    // illegal_parameter, not merely a decode error.
    cmp     x9, x10
    b.hs    .Lch_decode_error
    ldrb    w14, [x9]                // compression_methods length
    add     x9, x9, #1
    add     x0, x9, x14
    cmp     x0, x10
    b.hi    .Lch_decode_error
    cmp     w14, #1
    b.ne    .Lch_err_compression
    ldrb    w14, [x9]
    cbnz    w14, .Lch_err_compression
    add     x9, x9, #1

    // ── extensions<8..2^16-1> — optional, but must fill the rest ───
    cmp     x9, x10
    b.eq    .Lch_ext_none
    add     x0, x9, #2
    cmp     x0, x10
    b.hi    .Lch_decode_error
    ldrb    w14, [x9]
    ldrb    w15, [x9, #1]
    orr     w14, w15, w14, lsl #8    // extensions length
    add     x9, x9, #2
    add     x13, x9, x14             // extensions end
    cmp     x13, x10
    b.ne    .Lch_decode_error        // must exactly fill the body
    b       .Lch_ext_loop
.Lch_ext_none:
    mov     x13, x9                  // no extensions — loop runs 0 times

    // ── extensions loop: Extension { type(2) len(2) data[len] } ────
.Lch_ext_loop:
    cmp     x9, x13
    b.hs    .Lch_ext_done
    add     x0, x9, #4
    cmp     x0, x13
    b.hi    .Lch_decode_error
    ldrb    w14, [x9]
    ldrb    w15, [x9, #1]
    orr     w14, w15, w14, lsl #8    // w14 = extension type
    ldrb    w0, [x9, #2]
    ldrb    w15, [x9, #3]
    orr     w15, w15, w0, lsl #8     // x15 = extension_data length
    add     x9, x9, #4               // x9 = extension_data
    add     x0, x9, x15
    cmp     x0, x13
    b.hi    .Lch_decode_error

    cmp     w14, #TLS_EXT_SUPPORTED_VERSIONS
    b.eq    .Lch_ext_versions
    cmp     w14, #TLS_EXT_SUPPORTED_GROUPS
    b.eq    .Lch_ext_groups
    cmp     w14, #TLS_EXT_KEY_SHARE
    b.eq    .Lch_ext_keyshare
    cmp     w14, #TLS_EXT_ALPN
    b.eq    .Lch_ext_alpn
    cmp     w14, #TLS_EXT_SERVER_NAME
    b.eq    .Lch_ext_sni
    b       .Lch_ext_advance         // unrecognized — skip (§4.2)

    // ── supported_versions (§12.1): list<1..255> of ProtocolVersion ─
.Lch_ext_versions:
    cmp     x15, #3
    b.lo    .Lch_decode_error
    ldrb    w0, [x9]                 // list length
    add     w1, w0, #1
    cmp     w1, w15
    b.ne    .Lch_decode_error
    tst     w0, #1
    b.ne    .Lch_decode_error
    add     x2, x9, #1               // p
    mov     x3, x0                   // remaining
.Lch_ver_scan:
    cbz     x3, .Lch_ext_advance
    ldrb    w4, [x2]
    ldrb    w5, [x2, #1]
    orr     w4, w5, w4, lsl #8
    cmp     w4, #TLS_VERSION_1_3
    b.ne    .Lch_ver_next
    orr     x11, x11, #CH_TLS13
.Lch_ver_next:
    add     x2, x2, #2
    sub     x3, x3, #2
    b       .Lch_ver_scan

    // ── supported_groups (§12.3): NamedGroupList<2..2^16-1> ─────────
.Lch_ext_groups:
    cmp     x15, #2
    b.lo    .Lch_decode_error
    ldrb    w0, [x9]
    ldrb    w1, [x9, #1]
    orr     w0, w1, w0, lsl #8       // list length
    add     w1, w0, #2
    cmp     w1, w15
    b.ne    .Lch_decode_error
    tst     w0, #1
    b.ne    .Lch_decode_error
    add     x2, x9, #2               // p
    mov     x3, x0                   // remaining
.Lch_grp_scan:
    cbz     x3, .Lch_ext_advance
    ldrb    w4, [x2]
    ldrb    w5, [x2, #1]
    orr     w4, w5, w4, lsl #8
    cmp     w4, #NAMED_GROUP_X25519
    b.ne    .Lch_grp_next
    orr     x11, x11, #CH_GROUP
.Lch_grp_next:
    add     x2, x2, #2
    sub     x3, x3, #2
    b       .Lch_grp_scan

    // ── key_share (§12.3): KeyShareEntry list, extract X25519 key ──
.Lch_ext_keyshare:
    cmp     x15, #2
    b.lo    .Lch_decode_error
    ldrb    w0, [x9]
    ldrb    w1, [x9, #1]
    orr     w0, w1, w0, lsl #8       // client_shares length
    add     w1, w0, #2
    cmp     w1, w15
    b.ne    .Lch_decode_error
    add     x2, x9, #2               // p
    mov     x3, x0                   // remaining
.Lch_ks_scan:
    cbz     x3, .Lch_ext_advance
    cmp     x3, #4
    b.lo    .Lch_decode_error
    ldrb    w4, [x2]
    ldrb    w5, [x2, #1]
    orr     w4, w5, w4, lsl #8       // group
    ldrb    w6, [x2, #2]
    ldrb    w7, [x2, #3]
    orr     w6, w7, w6, lsl #8       // key_exchange length
    add     x8, x2, #4               // key_exchange ptr
    add     x0, x8, x6               // end of this entry
    sub     x7, x0, x2               // bytes consumed (4 + key_len)
    cmp     x7, x3
    b.hi    .Lch_decode_error
    cmp     w4, #NAMED_GROUP_X25519
    b.ne    .Lch_ks_next
    cmp     x6, #TLS_KEY_SHARE_LEN
    b.ne    .Lch_decode_error        // malformed X25519 key
    ldp     x4, x5, [x8]
    add     x6, x12, #TLS_CLIENT_KEY_SHARE
    stp     x4, x5, [x6]
    ldp     x4, x5, [x8, #16]
    stp     x4, x5, [x6, #16]
    orr     x11, x11, #CH_KEYSHARE
.Lch_ks_next:
    sub     x3, x3, x7
    mov     x2, x0
    b       .Lch_ks_scan

    // ── ALPN (§12.4): ProtocolNameList<2..2^16-1> of opaque<1..255> ─
.Lch_ext_alpn:
    cmp     x15, #2
    b.lo    .Lch_decode_error
    ldrb    w0, [x9]
    ldrb    w1, [x9, #1]
    orr     w0, w1, w0, lsl #8       // protocol name list length
    add     w1, w0, #2
    cmp     w1, w15
    b.ne    .Lch_decode_error
    add     x2, x9, #2               // p
    mov     x3, x0                   // remaining
.Lch_alpn_scan:
    cbz     x3, .Lch_ext_advance
    cmp     x3, #1
    b.lo    .Lch_decode_error
    ldrb    w4, [x2]                 // name length
    add     x5, x4, #1               // consumed
    cmp     x5, x3
    b.hi    .Lch_decode_error
    cmp     w4, #TLS_ALPN_H2_LEN
    b.ne    .Lch_alpn_next
    ldrb    w6, [x2, #1]
    ldrb    w7, [x2, #2]
    cmp     w6, #'h'
    b.ne    .Lch_alpn_next
    cmp     w7, #'2'
    b.ne    .Lch_alpn_next
    orr     x11, x11, #CH_ALPN
.Lch_alpn_next:
    add     x2, x2, x5
    sub     x3, x3, x5
    b       .Lch_alpn_scan

    // ── server_name (§12.5): only the first host_name entry matters ─
.Lch_ext_sni:
    cmp     x15, #2
    b.lo    .Lch_decode_error
    ldrb    w0, [x9]
    ldrb    w1, [x9, #1]
    orr     w0, w1, w0, lsl #8       // server_name_list length
    add     w1, w0, #2
    cmp     w1, w15
    b.ne    .Lch_decode_error
    cbz     w0, .Lch_ext_advance     // empty list — treat as absent
    cmp     x0, #3
    b.lo    .Lch_decode_error        // name_type(1) + name_len(2)
    add     x2, x9, #2               // first ServerName entry
    ldrb    w4, [x2]                 // name_type
    ldrb    w5, [x2, #1]
    ldrb    w6, [x2, #2]
    orr     w5, w6, w5, lsl #8       // name length
    add     x6, x5, #3
    cmp     x6, x0
    b.hi    .Lch_decode_error
    cmp     w4, #0                   // host_name (RFC 6066 §3)
    b.ne    .Lch_ext_advance         // unknown NameType — ignore
    orr     x11, x11, #CH_SNI_SEEN
    add     x2, x2, #3               // -> hostname bytes
    cmp     x5, #TLS_SNI_HOSTNAME_LEN
    b.ne    .Lch_ext_advance         // length differs — not a match
    adr_l   x6, tls_sni_hostname
    mov     x7, #0
.Lch_sni_cmp:
    cmp     x7, x5
    b.hs    .Lch_sni_match
    ldrb    w8, [x2, x7]
    ldrb    w14, [x6, x7]
    cmp     w8, w14
    b.ne    .Lch_ext_advance
    add     x7, x7, #1
    b       .Lch_sni_cmp
.Lch_sni_match:
    orr     x11, x11, #CH_SNI_MATCH

.Lch_ext_advance:
    add     x9, x9, x15              // -> next extension header
    b       .Lch_ext_loop

    // ── requirements (§12.1-§12.5), checked in plan order ───────────
.Lch_ext_done:
    tst     x11, #CH_TLS13
    b.eq    .Lch_err_version
    tst     x11, #CH_CIPHER
    b.eq    .Lch_err_cipher
    mov     x0, #CH_REQUIRED         // group + key_share, both required
    and     x1, x11, x0
    cmp     x1, x0
    b.ne    .Lch_err_cipher
    tst     x11, #CH_ALPN
    b.eq    .Lch_err_alpn
    tst     x11, #CH_SNI_SEEN
    b.eq    .Lch_ok
    tst     x11, #CH_SNI_MATCH
    b.eq    .Lch_err_sni
    b       .Lch_ok

.Lch_ok:
    // negotiated ALPN: "h2" (§14 sends this back in EncryptedExtensions)
    add     x0, x12, #TLS_ALPN_LEN
    mov     x1, #TLS_ALPN_H2_LEN
    str     x1, [x0]
    adr_l   x2, tls_alpn_h2
    ldrb    w3, [x2]
    ldrb    w4, [x2, #1]
    add     x0, x12, #TLS_ALPN
    strb    w3, [x0]
    strb    w4, [x0, #1]
    mov     x0, #0
    cmn     xzr, xzr                 // success — carry clear
    ret

.Lch_err_version:
    mov     x0, #TLS_ALERT_PROTOCOL_VERSION
    b       .Lch_fail
.Lch_err_cipher:
    mov     x0, #TLS_ALERT_HANDSHAKE_FAILURE
    b       .Lch_fail
.Lch_err_alpn:
    mov     x0, #TLS_ALERT_NO_APPLICATION_PROTOCOL
    b       .Lch_fail
.Lch_err_sni:
    mov     x0, #TLS_ALERT_UNRECOGNIZED_NAME
    b       .Lch_fail
.Lch_err_compression:
    mov     x0, #TLS_ALERT_ILLEGAL_PARAMETER
    b       .Lch_fail
.Lch_decode_error:
    mov     x0, #TLS_ALERT_DECODE_ERROR
.Lch_fail:
    cmp     xzr, xzr                 // failure — carry set
    ret
ENDFUNC tls_parse_client_hello
