// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/common.S — shared definitions for record layer
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
// ─────────────────────────────────────────────────────────────────────

#include "_constants.S"
