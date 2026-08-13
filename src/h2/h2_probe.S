#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_probe
//
// Description: Protocol detection — is this an HTTP/2 client? (Phase 16,
//   Option B). Compare buf[0..n) against the start of the 24-byte
//   HTTP/2 connection preface. Returns 1 when the bytes are a (possibly
//   partial) prefix of the preface — the connection loop then takes
//   over, finishes reading the preface and verifies it in full — and 0
//   for anything else, in which case the caller keeps the bytes and
//   parses HTTP/1. The buffer is never consumed, so both paths see the
//   same data. An empty buffer is never the preface.
//
// Input/Arguments:
//   x0 — buffer, x1 — bytes available
//
// Output/Returns:
//   x0 — 1 (preface prefix) or 0
//
// Clobbered Registers:
//   x0-x5, x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_probe
h2_probe:
    cbz x1, .Lh2probe_no
    mov x2, #H2_PREFACE_LEN
    cmp x1, x2
    csel x2, x1, x2, lo     // x2 = min(n, 24)
    adr_l x9, h2_preface
    mov x3, #0
1:
    cmp x3, x2
    b.hs .Lh2probe_yes
    ldrb w4, [x0, x3]
    ldrb w5, [x9, x3]
    cmp w4, w5
    b.ne .Lh2probe_no
    add x3, x3, #1
    b 1b
.Lh2probe_yes:
    mov x0, #1
    ret
.Lh2probe_no:
    mov x0, #0
    ret
