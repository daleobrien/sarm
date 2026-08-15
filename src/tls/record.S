// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record.S — TLS 1.3 record layer (PLAN.MD Phase 11)
//
// This file is maintained for documentation and backward compatibility.
// The record layer implementation has been split into separate modules
// in src/tls/record/ for better code organization:
//   - src/tls/record/parse.S     — tls_record_parse
//   - src/tls/record/write.S     — tls_record_write
//   - src/tls/record/nonce.S     — tls_record_nonce
//   - src/tls/record/encrypt.S   — tls_record_encrypt
//   - src/tls/record/decrypt.S   — tls_record_decrypt
//   - src/tls/record/seq.S       — tls_record_next_*_seq
//
// Each module is compiled as a separate object file.
// ─────────────────────────────────────────────────────────────────────
