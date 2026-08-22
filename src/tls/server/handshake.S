// ─────────────────────────────────────────────────────────────────────
// File: src/tls/server/handshake.S — drive one full TLS 1.3 server
//   handshake over a live connection (RFC 8446 §2, PLAN.MD Phase 20)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.extern tls_transcript_init
.extern tls_read_record
.extern tls_read_record_prefilled
.extern memcpy
.extern tls_transcript_add
.extern tls_parse_client_hello
.extern tls_build_server_hello
.extern tls_record_write
.extern tls_transcript_hash
.extern tls_derive_handshake_secrets
.extern tls_encrypted_extensions_write
.extern tls_certificate_write
.extern tls_certificate_verify_write
.extern tls_finished_write
.extern tls_record_encrypt
.extern tls_record_decrypt
.extern tls_record_next_server_seq
.extern tls_record_next_client_seq
.extern tls_finished_key
.extern tls_finished_verify_data
.extern tls_derive_application_secrets
.extern transport_write

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_server_handshake
//
// Description: Run the entire server side of a TLS 1.3 1-RTT handshake
//   (RFC 8446 §2, Figure 1) over an already-accepted, still-plaintext
//   connection: read and parse the ClientHello, send ServerHello, run
//   the key schedule, send the encrypted server flight
//   (EncryptedExtensions, Certificate, CertificateVerify, Finished),
//   verify the client's own Finished, derive the application traffic
//   keys, and mark the connection TLS_HS_CONNECTED. Every message this
//   server sends was already implemented and unit-tested in isolation
//   (Phases 12-19); this function is the glue that sequences them
//   against a real socket and a running transcript hash, which is
//   exactly the "external TLS implementation completes the handshake"
//   acceptance criterion those phases deferred.
//
//   Two scope notes, both deliberate:
//     - A client's optional middlebox-compatibility change_cipher_spec
//       record (RFC 8446 Appendix D.4) is tolerated while reading the
//       client's Finished: it is a content-free marker with no effect
//       on keys or the transcript, so it is simply discarded and the
//       next record read again.
//     - No error alert is ever sent back to the client on failure —
//       this function just reports carry-set to its caller, who closes
//       the connection. Structured alerts belong to PLAN.MD Phase 23
//       (TLS negative tests); Phase 20's job is the happy path that
//       gets the existing HTTP/2 stack running over real TLS bytes.
//
// Input/Arguments:
//   x0 — the connection's file descriptor (still TRANSPORT_PLAIN)
//   x1 — pointer to bytes already read off the wire for this connection
//        (Plan.md Phase 2, Step 9 — main.S's real first read, which
//        replaced the old MSG_PEEK); ignored when x2 == 0
//   x2 — length of those already-read bytes (0 if none)
//
// Output/Returns:
//   carry clear (success): tls_hs_state == TLS_HS_CONNECTED,
//     transport_mode == TRANSPORT_TLS, tls_state's application traffic
//     keys/IVs are live and both record sequence counters read 0
//   carry set (failure): x0 = TLS_RECORD_ERR_* / a generic 1 for a
//     protocol-level mismatch (wrong message type, Finished
//     verification failure). tls_hs_state is left at TLS_HS_FAILED;
//     transport_mode is untouched (still PLAIN). This function does no
//     socket cleanup — the caller closes the fd either way.
//
// Clobbered Registers:
//   x0-x17, x19-x26, x30 (x19-x26, x30 saved/restored), v0-v11,
//   v16-v21, NZCV — everything every callee above clobbers. x19-x26
//   are safe to use as this function's own long-lived scratch across
//   every call it makes: none of the above either touch them without
//   saving/restoring, or (client_hello.S, server_hello/write.S,
//   certificate.S, encrypted_extensions.S) don't touch them at all.
//
// Stack Usage:
//   192 bytes: x19-x26 (64, four stp) + x30 (padded to 16) = 80, then
//   three 32-byte named scratch slots (running transcript-hash
//   snapshot, the client's finished_key, its expected verify_data —
//   the hash slot is reused for every snapshot in turn, never live at
//   the same time as the other two) plus an 8-byte (padded 16) slot
//   the local send-helper uses to save its own x30
// ─────────────────────────────────────────────────────────────────────

.equ HS_HASH,   80   // 32 B — transcript-hash snapshot scratch
.equ HS_FK,     112  // 32 B — client finished_key
.equ HS_EXP,    144  // 32 B — expected verify_data
.equ HS_HELPER_X30, 176  // 8 B (padded 16) — send-helper's own x30

.text
.align 2
.global tls_server_handshake
tls_server_handshake:
    sub     sp, sp, #192
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    str     x30, [sp, #64]

    mov     x19, x0                     // fd
    mov     x23, x1                     // bytes already read off the wire (Step 9)
    mov     x24, x2                     // ... and how many

    bl      tls_transcript_init

    // RFC 8446 §5.3: sequence numbers reset "at the beginning of a
    // connection and whenever the key changes." tls_derive_application_
    // secrets resets both counters for the app-traffic epoch later in
    // this function, but that's the *second* reset a connection needs
    // — the handshake epoch's own messages (EncryptedExtensions
    // .. Finished below, and the client's Finished) need them zeroed
    // right now too. Without this, every connection after the first
    // one handled by this process inherits whatever the previous
    // connection's application traffic left the counters at, and the
    // handshake messages below get encrypted/decrypted against the
    // wrong nonce.
    adr_l   x9, tls_client_seq
    str     xzr, [x9]
    adr_l   x9, tls_server_seq
    str     xzr, [x9]

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_START
    str     w10, [x9]

    // ── ClientHello ───────────────────────────────────────────────
    // Step 9: main.S's real first read may already have pulled some
    // (or all) of the ClientHello record off the wire, into its own
    // buffer rather than tls_hs_record_buf -- copy those bytes over
    // first, then let tls_read_record_prefilled read only whatever
    // wasn't already there.
    cbz     x24, .Lhs_ch_no_prefill
    adr_l   x0, tls_hs_record_buf
    mov     x1, x23
    mov     x2, x24
    bl      memcpy
.Lhs_ch_no_prefill:
    mov     x0, x19
    adr_l   x1, tls_hs_record_buf
    mov     x2, #BUF_SIZE
    mov     x3, x24
    bl      tls_read_record_prefilled
    b.cs    .Lhs_fail
    cmp     x0, #TLS_RECORD_HANDSHAKE
    b.ne    .Lhs_fail_generic
    // A handshake record whose fragment is shorter than the 4-byte
    // handshake header carries no message at all. Both uses below
    // subtract TLS_HS_HEADER_LEN from this length, and the subtraction
    // is unsigned: without this check a five-byte record (type 22,
    // fragment length 0) makes tls_transcript_add hash 2^64-4 bytes
    // and walk off the end of memory, before anything about the peer
    // has been authenticated. Found in Step 7 by the handshake fuzzer
    // (docs/security/fuzzing.md).
    cmp     x2, #TLS_HS_HEADER_LEN
    b.lo    .Lhs_fail_generic
    mov     x20, x1                     // ClientHello: header+body ptr
    mov     x21, x2                     // ClientHello: header+body len

    mov     x0, #TLS_HS_CLIENT_HELLO
    add     x1, x20, #TLS_HS_HEADER_LEN
    sub     x2, x21, #TLS_HS_HEADER_LEN
    bl      tls_transcript_add

    add     x0, x20, #TLS_HS_HEADER_LEN
    sub     x1, x21, #TLS_HS_HEADER_LEN
    bl      tls_parse_client_hello
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_CH_RECEIVED
    str     w10, [x9]

    // ── ServerHello ──────────────────────────────────────────────
    adr_l   x0, tls_hs_msg_buf
    bl      tls_build_server_hello
    b.cs    .Lhs_fail
    mov     x20, x0                     // ServerHello length

    mov     x0, #TLS_HS_SERVER_HELLO
    adr_l   x1, tls_hs_msg_buf
    add     x1, x1, #TLS_HS_HEADER_LEN  // body only — transcript_add
    sub     x2, x20, #TLS_HS_HEADER_LEN //   synthesizes its own header
    bl      tls_transcript_add

    mov     x0, #TLS_RECORD_HANDSHAKE
    adr_l   x1, tls_hs_msg_buf
    mov     x2, x20
    adr_l   x3, tls_hs_record_buf
    bl      tls_record_write
    b.cs    .Lhs_fail
    mov     x21, x0                     // record length

    mov     x0, x19
    adr_l   x1, tls_hs_record_buf
    mov     x2, x21
    bl      transport_write
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_SH_SENT
    str     w10, [x9]

    // ── key schedule: handshake traffic keys (CH..SH) ───────────────
    add     x0, sp, #HS_HASH
    bl      tls_transcript_hash
    add     x0, sp, #HS_HASH
    bl      tls_derive_handshake_secrets

    // ── EncryptedExtensions (encrypted under the server hs key) ─────
    adr_l   x0, tls_hs_msg_buf
    bl      tls_encrypted_extensions_write
    mov     x20, x0
    mov     x0, #TLS_HS_ENCRYPTED_EXTENSIONS
    adr_l   x1, tls_hs_msg_buf
    add     x1, x1, #TLS_HS_HEADER_LEN
    sub     x2, x20, #TLS_HS_HEADER_LEN
    bl      tls_transcript_add
    bl      .Lhs_send_encrypted_current
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_EE_SENT
    str     w10, [x9]

    // ── Certificate ──────────────────────────────────────────────
    adr_l   x0, tls_hs_msg_buf
    bl      tls_certificate_write
    mov     x20, x0
    mov     x0, #TLS_HS_CERTIFICATE
    adr_l   x1, tls_hs_msg_buf
    add     x1, x1, #TLS_HS_HEADER_LEN
    sub     x2, x20, #TLS_HS_HEADER_LEN
    bl      tls_transcript_add
    bl      .Lhs_send_encrypted_current
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_CERT_SENT
    str     w10, [x9]

    // ── CertificateVerify (signs the transcript through Certificate) ─
    add     x0, sp, #HS_HASH
    bl      tls_transcript_hash
    adr_l   x0, tls_hs_msg_buf
    add     x1, sp, #HS_HASH
    bl      tls_certificate_verify_write
    b.cs    .Lhs_fail
    mov     x20, x0
    mov     x0, #TLS_HS_CERTIFICATE_VERIFY
    adr_l   x1, tls_hs_msg_buf
    add     x1, x1, #TLS_HS_HEADER_LEN
    sub     x2, x20, #TLS_HS_HEADER_LEN
    bl      tls_transcript_add
    bl      .Lhs_send_encrypted_current
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_CV_SENT
    str     w10, [x9]

    // ── Finished (MACs the transcript through CertificateVerify) ────
    add     x0, sp, #HS_HASH
    bl      tls_transcript_hash
    adr_l   x0, tls_hs_msg_buf
    add     x1, sp, #HS_HASH
    bl      tls_finished_write
    mov     x20, x0                     // always 36, no failure mode
    mov     x0, #TLS_HS_FINISHED
    adr_l   x1, tls_hs_msg_buf
    add     x1, x1, #TLS_HS_HEADER_LEN
    sub     x2, x20, #TLS_HS_HEADER_LEN
    bl      tls_transcript_add
    bl      .Lhs_send_encrypted_current
    b.cs    .Lhs_fail

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_FIN_SENT
    str     w10, [x9]

    // ── read the client's Finished, skipping any middlebox-compat
    //    change_cipher_spec record first (RFC 8446 Appendix D.4) ─────
    //
    // Deliberately NOT deriving the application traffic keys yet, even
    // though the CH..server-Finished transcript hash they need is
    // already available: tls_client_seq is the same physical counter
    // for both the handshake epoch and the application epoch (RFC 8446
    // §5.3 resets sequence numbers "at the beginning of a connection
    // and whenever the key changes"), and the client's Finished below
    // is still the handshake epoch's one and only client->server
    // message, consuming its seq 0. Deriving application secrets
    // first — which also resets both sequence counters to 0 for the
    // new epoch — before reading this record would let it steal the
    // application epoch's seq 0, so the client's real first
    // application_data record (whatever it sends next) would then be
    // decrypted against the wrong nonce and fail with a bad tag.
.Lhs_read_client_next:
    mov     x0, x19
    adr_l   x1, tls_hs_record_buf
    mov     x2, #BUF_SIZE
    bl      tls_read_record
    b.cs    .Lhs_fail
    cmp     x0, #TLS_RECORD_CHANGE_CIPHER_SPEC
    b.eq    .Lhs_read_client_next
    // the outer wire type of ANY encrypted record — including the
    // client's Finished — is always application_data (RFC 8446 §5.2:
    // "the outer type of every ciphertext"); the real inner type only
    // appears after tls_record_decrypt below.
    cmp     x0, #TLS_RECORD_APPLICATION_DATA
    b.ne    .Lhs_fail_generic
    mov     x23, x3                     // total record length (tls_hs_record_buf holds
                                         //   the raw record already)

    bl      tls_record_next_client_seq
    mov     x9, x0

    adr_l   x0, tls_hs_record_buf
    mov     x1, x23
    adr_l   x2, tls_client_hs_key
    adr_l   x3, tls_client_hs_iv
    mov     x4, x9
    adr_l   x5, tls_hs_msg_buf
    bl      tls_record_decrypt
    b.cs    .Lhs_fail
    cmp     x1, #TLS_RECORD_HANDSHAKE
    b.ne    .Lhs_fail_generic
    cmp     x0, #(TLS_HS_HEADER_LEN + 32)
    b.ne    .Lhs_fail_generic

    adr_l   x9, tls_hs_msg_buf
    ldrb    w10, [x9]
    cmp     w10, #TLS_HS_FINISHED
    b.ne    .Lhs_fail_generic

    // ── verify the client's verify_data ──────────────────────────
    adr_l   x0, tls_client_hs_traffic_secret
    add     x1, sp, #HS_FK
    bl      tls_finished_key

    // The transcript hasn't changed since the CH..server-Finished
    // snapshot above (the client's Finished is never fed into it —
    // nothing past this point needs another hash), so it's safe and
    // cheap to recompute the same hash here rather than having kept
    // the earlier snapshot alive across every step since.
    add     x0, sp, #HS_HASH
    bl      tls_transcript_hash

    add     x0, sp, #HS_FK
    add     x1, sp, #HS_HASH
    add     x2, sp, #HS_EXP
    bl      tls_finished_verify_data

    adr_l   x9, tls_hs_msg_buf
    add     x0, x9, #TLS_HS_HEADER_LEN  // received verify_data
    add     x1, sp, #HS_EXP
    bl      .Lhs_memcmp32
    cbnz    x0, .Lhs_fail_generic

    // ── application traffic keys (CH..server-Finished) — only now,
    //    with the client's handshake-epoch Finished already consumed
    //    (see the comment above) ──────────────────────────────────
    add     x0, sp, #HS_HASH
    bl      tls_transcript_hash
    add     x0, sp, #HS_HASH
    bl      tls_derive_application_secrets

    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_CONNECTED
    str     w10, [x9]
    adr_l   x9, transport_mode
    mov     x10, #TRANSPORT_TLS
    str     x10, [x9]

    // transport_read's TLS-mode stage buffer (src/transport/data.S) is
    // a single global, not per-connection — this server handles one
    // connection at a time, but the *previous* connection may have
    // left unread staged plaintext behind (e.g. its last decrypted
    // record held more than the caller ever read before the
    // connection ended). Zero it here, at the one moment a fresh TLS
    // session actually begins, so the new connection can never start
    // by draining leftover bytes that were encrypted under a
    // different connection's keys entirely.
    adr_l   x9, tls_read_stage_len
    str     xzr, [x9]
    adr_l   x9, tls_read_stage_pos
    str     xzr, [x9]

    cmn     xzr, xzr                    // success — carry clear
    b       .Lhs_ret

.Lhs_fail_generic:
    mov     x0, #1
.Lhs_fail:
    cmp     xzr, xzr                    // failure — carry set
    adr_l   x9, tls_hs_state
    mov     w10, #TLS_HS_FAILED
    str     w10, [x9]
.Lhs_ret:
    ldr     x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #192
    ret

// local helper: seal tls_hs_msg_buf[0..x20) under the server hs key,
// using the next server sequence number, into tls_hs_record_buf, and
// send it. x20 =
// plaintext length (set by the caller just before branching here).
// Carry propagates to the caller of tls_server_handshake.
.Lhs_send_encrypted_current:
    str     x30, [sp, #HS_HELPER_X30]
    bl      tls_record_next_server_seq
    mov     x9, x0

    mov     x0, #TLS_RECORD_HANDSHAKE
    adr_l   x1, tls_hs_msg_buf
    mov     x2, x20
    adr_l   x3, tls_server_hs_key
    adr_l   x4, tls_server_hs_iv
    mov     x5, x9
    adr_l   x6, tls_hs_record_buf
    bl      tls_record_encrypt
    b.cs    .Lhs_sec_ret
    mov     x9, x0                      // record length

    mov     x0, x19
    adr_l   x1, tls_hs_record_buf
    mov     x2, x9
    bl      transport_write
.Lhs_sec_ret:
    ldr     x30, [sp, #HS_HELPER_X30]
    ret

// local helper: 32-byte compare. x0 = a, x1 = b -> x0 = 0 if equal,
// nonzero otherwise. Not constant-time — MAC-timing hardening is
// PLAN.MD Phase 25's job, not Phase 20's.
.Lhs_memcmp32:
    mov     x9, #0
    mov     x10, #0
.Lhs_memcmp32_loop:
    cmp     x10, #32
    b.eq    .Lhs_memcmp32_done
    ldrb    w11, [x0, x10]
    ldrb    w12, [x1, x10]
    eor     w11, w11, w12
    orr     w9, w9, w11
    add     x10, x10, #1
    b       .Lhs_memcmp32_loop
.Lhs_memcmp32_done:
    mov     x0, x9
    ret
