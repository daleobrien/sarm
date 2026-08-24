#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: SHA-256 streaming context
//
// Description: A ready-made streaming SHA-256 context.
//   Like tls_state, it is a fixed-layout global: sha256_init seeds the
//   state with the FIPS 180-4 IV and zeroes the counters, sha256_update
//   absorbs bytes (compressing whole blocks through `sha256`), and
//   sha256_final pads, compresses, and writes the 32-byte digest. Call
//   sha256_init before use — the zero initial values below are not a
//   valid context.
//
// Exported Symbols:
//   sha256_ctx          — the streaming context (SHA256_CTX_SIZE bytes)
//   sha256_ctx_state    — H0..H7 (32 B, native u32s holding big-endian
//                         values)
//   sha256_ctx_bitlen   — u64 total message bits (FIPS 180-4 length
//                         field)
//   sha256_ctx_buf      — 64 B partial-block buffer
//   sha256_ctx_buflen   — u64 valid bytes in buf (0..63)
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
.global sha256_ctx

sha256_ctx:
OBJECT sha256_ctx_state
                     .skip 32        // SHA256_CTX_STATE — set by sha256_init
ENDOBJ sha256_ctx_state
OBJECT sha256_ctx_bitlen
                     .quad 0         // SHA256_CTX_BITLEN — set by sha256_init
ENDOBJ sha256_ctx_bitlen
OBJECT sha256_ctx_buf
                     .skip 64        // SHA256_CTX_BUF — partial block
ENDOBJ sha256_ctx_buf
OBJECT sha256_ctx_buflen
                     .quad 0         // SHA256_CTX_BUFLEN — set by sha256_init
ENDOBJ sha256_ctx_buflen
