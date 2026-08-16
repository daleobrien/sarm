// ─────────────────────────────────────────────────────────────────────
// File: src/tls/handshake/finished/finished_key.S — the Finished
//   MAC key (RFC 8446 §4.4.4, PLAN.MD Phase 18)
// ─────────────────────────────────────────────────────────────────────

#include "../../../defs.S"

.data
.align 4
// The bare "finished" label (no "tls13 " prefix — hkdf_expand_label
// adds that, same convention as key_schedule.S's khs_label_* set).
fk_label_finished:
    .ascii "finished"

// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_finished_key
//
// Description: Derive the Finished MAC key (RFC 8446 §4.4.4):
//
//     finished_key = HKDF-Expand-Label(BaseKey, "finished", "", 32)
//
//   BaseKey is whichever handshake traffic secret the caller is
//   producing a Finished message for — this server only ever sends
//   its own Finished, so tls_finished_write always passes
//   TLS_SERVER_HS_TRAFFIC_SECRET, but the key derivation itself
//   doesn't care which secret it's handed, so it's left as an
//   argument rather than hardcoded (the same split as
//   tls_certificate_verify_sign_with_k, which takes its nonce as an
//   argument instead of reaching into global state).
//
// Input/Arguments:
//   x0 — pointer to the 32-byte BaseKey (a handshake traffic secret)
//   x1 — pointer to the 32-byte output buffer
//
// Output/Returns:
//   none (void) - 32 key bytes written to [x1]
//
// Clobbered Registers:
//   x0-x10, x13, w11, v0-v7, v16, v18, v19, NZCV, x19-x26
//   (saved/restored) — everything hkdf_expand_label clobbers
//
// Stack Usage:
//   16 bytes — just x30, saved across the call to hkdf_expand_label
//   (which itself saves/restores its own x30, but that only protects
//   ITS caller's return address at the point of the call, i.e. the
//   value x30 holds mid-function here — not this function's own
//   entry return address, which must be preserved separately)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global tls_finished_key
tls_finished_key:
    str     x30, [sp, #-16]!

    mov     x9, x0                      // BaseKey
    mov     x10, x1                     // out

    mov     x0, x9                      // secret
    adr_l   x1, fk_label_finished       // label
    mov     x2, #8                      // label length
    mov     x3, xzr                     // context (unused, len == 0)
    mov     x4, #0                      // context length
    mov     x5, x10                     // out
    mov     x6, #32                     // outlen
    bl      hkdf_expand_label

    ldr     x30, [sp], #16
    ret
