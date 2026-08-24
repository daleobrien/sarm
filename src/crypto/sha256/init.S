// SHA-256 streaming context initialization

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: sha256_init
//
// Description: Initialise a SHA-256 streaming context: load the FIPS
//   180-4 IV into ctx->state, zero the bit counter and the partial-block
//   buffer. Call before sha256_update / sha256_final.
//
// Input/Arguments:
//   x0 — pointer to a SHA256_CTX_SIZE-byte context
//
// Output/Returns:
//   none (void) - the context is initialised in place
//
// Clobbered Registers:
//   x1, v0, v1
//
// Stack Usage:
//   none - leaf function
// ─────────────────────────────────────────────────────────────────────

.text
.align 2

FUNC sha256_init
    adr_l   x1, sha256_h256
    ld1     {v0.4s, v1.4s}, [x1]              // FIPS 180-4 IV (H0..H7)
    st1     {v0.4s, v1.4s}, [x0]              // ctx->state

    str     xzr, [x0, #SHA256_CTX_BITLEN]     // total message bits = 0
    stp     xzr, xzr, [x0, #SHA256_CTX_BUF]   // zero the 64-byte partial
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 16)]  //   block buffer...
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 32)]
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 48)]
    str     xzr, [x0, #SHA256_CTX_BUFLEN]     // nothing buffered yet
    ret
ENDFUNC sha256_init
