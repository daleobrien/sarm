#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: TLS module state
//
// Description: Per-connection TLS 1.3 state. A
//   connection handler starts from these initial values and the
//   handshake phases (9-19) fill the rest. The fixed layout is the
//   contract: the TLS_* offsets in defs.S are what the handshake and
//   record-layer code will use, and each field below is also exported
//   under a tls_* label so the unit test (test_tls.c) can verify every
//   offset against real storage.
//
// Exported Symbols:
//   tls_state          — the TLS connection state block
//   tls_fd .. tls_alpn — one label per field (offset checks + direct
//                        access); the transcript-hash field is
//                        tls_transcript_hash_field because
//                        tls_transcript_hash is the snapshot function
//
//   tls_client_gcm_ctx — the AES-128-GCM key context for each direction
//   tls_server_gcm_ctx   (round keys + H), rebuilt at each key change
//
//   tls_alpn_h2        — the "h2" ALPN identifier (RFC 7301), 16-aligned
//   tls_transcript_ctx — the running handshake-transcript SHA-256
//                        context, SHA256_CTX layout
//                        plus one tls_transcript_ctx_* label per field
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
.global tls_state
.global tls_fd
.global tls_hs_state
.global tls_client_random
.global tls_server_random
.global tls_client_key_share
.global tls_server_key_share
.global tls_shared_secret
.global tls_transcript_hash_field
.global tls_handshake_secret
.global tls_master_secret
.global tls_client_hs_key
.global tls_client_hs_iv
.global tls_server_hs_key
.global tls_server_hs_iv
.global tls_client_app_key
.global tls_client_app_iv
.global tls_server_app_key
.global tls_server_app_iv
.global tls_client_seq
.global tls_server_seq
.global tls_alpn_len
.global tls_alpn
.global tls_session_id_len
.global tls_session_id
.global tls_server_hs_traffic_secret
.global tls_client_hs_traffic_secret
.global tls_hs_msg_buf
.global tls_hs_record_buf
.global tls_client_gcm_ctx
.global tls_server_gcm_ctx

// tls_state — one block per connection (a connection handler is one
// process, so the global is per-connection, like request/response).
// Scalar fields take explicit initial values; byte arrays are zeroed
// by .skip until the handshake fills them.
tls_state:
tls_fd:                .quad -1            // TLS_FD — no connection yet
tls_hs_state:          .quad TLS_HS_START  // TLS_HS_STATE
tls_client_random:     .skip TLS_RANDOM_LEN
tls_server_random:     .skip TLS_RANDOM_LEN
tls_client_key_share:  .skip TLS_KEY_SHARE_LEN
tls_server_key_share:  .skip TLS_KEY_SHARE_LEN
tls_shared_secret:     .skip TLS_KEY_SHARE_LEN  // 32 B X25519 shared secret
tls_transcript_hash_field:   .skip TLS_DIGEST_LEN
tls_handshake_secret:  .skip TLS_SECRET_LEN
tls_master_secret:     .skip TLS_SECRET_LEN
tls_client_hs_key:     .skip TLS_KEY_LEN
tls_client_hs_iv:      .skip TLS_IV_STRIDE  // 12 B IV + 4 B pad (TLS_IV_LEN + pad)
tls_server_hs_key:     .skip TLS_KEY_LEN
tls_server_hs_iv:      .skip TLS_IV_STRIDE
tls_client_app_key:    .skip TLS_KEY_LEN
tls_client_app_iv:     .skip TLS_IV_STRIDE
tls_server_app_key:    .skip TLS_KEY_LEN
tls_server_app_iv:     .skip TLS_IV_STRIDE
tls_client_seq:        .quad 0             // TLS_CLIENT_SEQ — record seqs start at 0
tls_server_seq:        .quad 0             // TLS_SERVER_SEQ
tls_alpn_len:          .quad 0             // TLS_ALPN_LEN — nothing negotiated yet
tls_alpn:              .skip TLS_ALPN_BUF  // TLS_ALPN
tls_session_id_len:    .quad 0             // TLS_SESSION_ID_LEN — the
                                            //   client's legacy_session_id
                                            //   length, echoed in ServerHello
tls_session_id:        .skip 32            // TLS_SESSION_ID
tls_server_hs_traffic_secret: .skip TLS_SECRET_LEN  // TLS_SERVER_HS_TRAFFIC_SECRET
tls_client_hs_traffic_secret: .skip TLS_SECRET_LEN  // TLS_CLIENT_HS_TRAFFIC_SECRET

// tls_client_gcm_ctx / tls_server_gcm_ctx — the AES-128-GCM key
// contexts the record layer seals and opens with, one per direction.
// Each holds the round-key schedule and GHASH's H for the key currently
// installed in that direction (see GCM_CTX_* in defs.S).
//
// These are derived state, not protocol state: everything in them is a
// pure function of tls_*_hs_key / tls_*_app_key, rebuilt by
// aes_gcm_ctx_init whenever those change — at the handshake epoch
// (tls_derive_handshake_secrets) and again at the application epoch
// (tls_derive_application_secrets). Keeping them here rather than
// recomputing them inside every aes_gcm_encrypt/decrypt call is the
// whole point: the schedule and H cost one key expansion and one AES
// block each, and they were being paid per record, in both directions,
// for a key fixed for the epoch.
//
// Deliberately outside the fixed tls_state layout, like tls_hs_msg_buf
// below: nothing addresses them by a persistent field contract, and
// test_tls.c's offset sweep covers tls_state's protocol fields, not
// caches derived from them.
.align 4
tls_client_gcm_ctx: .skip GCM_CTX_SIZE
tls_server_gcm_ctx: .skip GCM_CTX_SIZE

// tls_hs_msg_buf — scratch buffer for constructing one plaintext
// handshake message body at a time during tls_server_handshake (Phase
// 20). Not part of the fixed tls_state layout (no TLS_* offset, no
// offset test) since nothing addresses it by a persistent field
// contract — it's pure scratch, reused sequentially for each message
// the way src/data.S's `buf` is reused across HTTP requests. Sized
// well past the largest message this server ever builds (Certificate,
// at 13 + the embedded DER certificate's length, comfortably under
// 1 KB for a P-256 cert).
.align 4
tls_hs_msg_buf: .skip 2048

// tls_hs_record_buf — scratch buffer for one whole TLS record (header
// + fragment) at a time during tls_server_handshake: reading the
// ClientHello and the client's Finished off the wire, and wrapping
// each outgoing handshake message in its record header before
// sending. Deliberately separate from src/data.S's `buf` (the HTTP
// request/response buffer) — the TLS module has no business depending
// on the HTTP layer's scratch space, and every test binary that links
// any part of the TLS module would otherwise need to link src/data.S
// too. Sized to the largest record this server ever needs to hold:
// header(5) + TLS_MAX_PLAINTEXT + tag(16), rounded.
.align 4
tls_hs_record_buf: .skip 16448

// tls_alpn_h2 — the ALPN identifier this server offers: "h2" (2 bytes,
// 16-aligned like every string in the tree).
.align 4
.global tls_alpn_h2
tls_alpn_h2:
    .ascii "h2"

// tls_sni_hostname — the one hostname the ClientHello parser matches
// server_name extensions against. No virtual-host
// infrastructure exists yet, so this is a single compile-time value
// rather than a field in tls_state.
.align 4
.global tls_sni_hostname
tls_sni_hostname:
    .ascii "localhost"

// tls_transcript_ctx — the running SHA-256 context of the handshake
// transcript. SHA256_CTX_SIZE bytes laid out by the
// SHA256_CTX_* offsets in defs.S (the same contract as sha256_ctx in
// src/crypto/data.S); each field is also exported under a
// tls_transcript_ctx_* label so the unit test (test_tls_transcript.c)
// can verify every offset against real storage. Not a valid context
// until tls_transcript_init seeds it — the zero bytes below are just
// initial storage, exactly like sha256_ctx.
.align 4
.global tls_transcript_ctx
.global tls_transcript_ctx_state
.global tls_transcript_ctx_bitlen
.global tls_transcript_ctx_buf
.global tls_transcript_ctx_buflen

tls_transcript_ctx:
tls_transcript_ctx_state:   .skip 32        // SHA256_CTX_STATE — set by tls_transcript_init
tls_transcript_ctx_bitlen:  .quad 0         // SHA256_CTX_BITLEN
tls_transcript_ctx_buf:     .skip 64        // SHA256_CTX_BUF
tls_transcript_ctx_buflen:  .quad 0         // SHA256_CTX_BUFLEN
