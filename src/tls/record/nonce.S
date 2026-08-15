// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/nonce.S — TLS per-record nonce (RFC 8446 §5.3)
// ─────────────────────────────────────────────────────────────────────
#include "../../defs.S"


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

.text
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
