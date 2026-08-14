#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: TLS module state
//
// Description: Per-connection TLS 1.3 state (PLAN.MD §2.2). A
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
//                        access)
//   tls_alpn_h2        — the "h2" ALPN identifier (RFC 7301), 16-aligned
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
.global tls_transcript_hash
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
tls_transcript_hash:   .skip TLS_DIGEST_LEN
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

// tls_alpn_h2 — the ALPN identifier this server offers: "h2" (2 bytes,
// 16-aligned like every string in the tree).
.align 4
.global tls_alpn_h2
tls_alpn_h2:
    .ascii "h2"
