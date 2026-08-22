// ─────────────────────────────────────────────────────────────────────
// File: src/tls/transcript/init.S — start a fresh handshake transcript
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_transcript_init
//
// Description: Start a fresh handshake transcript: seed tls_transcript_ctx
//   with the FIPS 180-4 IV and zero the counters (PLAN.MD §9.1). Call
//   before the first handshake message of a connection; any previous
//   transcript is discarded.
//
// Input/Arguments:
//   none
//
// Output/Returns:
//   none (void)
//
// Clobbered Registers:
//   x0, x1, v0, v1 — everything sha256_init clobbers
//
// Stack Usage:
//   none - tail call, no frame
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_transcript_init
tls_transcript_init:
    adr_l   x0, tls_transcript_ctx
    b       sha256_init                 // tail call: seed the context
