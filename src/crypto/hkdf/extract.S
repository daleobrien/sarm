// ─────────────────────────────────────────────────────────────────────
// Function Name: hkdf_extract
//
// Description: RFC 5869 §2.2 — PRK = HMAC-SHA256(salt, IKM). When
//   saltlen == 0 the salt defaults to a string of 32 zero octets (the
//   RFC's "salt not provided" case; also the TLS 1.3 early-secret
//   extraction). The IKM pointer is ignored when ikmlen == 0.
//
// Input/Arguments:
//   x0 — pointer to the salt (ignored when saltlen == 0)
//   x1 — salt length in bytes (0 = absent, defaults to 32 zeros)
//   x2 — pointer to the input keying material
//   x3 — IKM length in bytes (0 is valid)
//   x4 — pointer to the 32-byte PRK output buffer
//
// Output/Returns:
//   none (void) - 32 PRK bytes written to [x4].
//
// Clobbered Registers:
//   x0-x7, v0-v7, v16, v18, v19, NZCV — everything
//   hmac_sha256 clobbers
//
// Stack Usage:
//   48 bytes (x19 + x30) plus a 32-byte zero-salt block, only on the
//   saltlen == 0 path; the saltlen != 0 path is a tail call
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.text
.align 2
.global hkdf_extract
hkdf_extract:
    cbnz    x1, .Lextract_hmac     // salt provided: tail-call straight
                                   //   into hmac_sha256 (x0..x4 are
                                   //   already its exact arguments)
    // ── absent salt -> 32 zero octets (RFC 5869 §2.2) ──
    stp     x19, x30, [sp, #-48]!
    add     x19, sp, #16           // 32-byte zero salt (16-aligned)
    stp     xzr, xzr, [x19]
    stp     xzr, xzr, [x19, #16]
    mov     x0, x19
    mov     x1, #32
    // x2 (ikm), x3 (ikmlen), x4 (prk) are untouched
    bl      hmac_sha256
    ldp     x19, x30, [sp], #48
    ret

.Lextract_hmac:
    b       hmac_sha256            // tail call: PRK = HMAC(salt, IKM)
