// GHASH authentication tag

#include "data.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: ghash
//
// Description: GHASH (NIST SP 800-38D §6.4) of the GCM input string
//   A || 0^pad || C || 0^pad || [len(A)]_64 || [len(C)]_64 (bit lengths,
//   big-endian) — exactly the construction the GCM tag is built on
//. H = E_K(0^128) must be supplied by the caller.
//
//   **Test-only.** Nothing in the server calls this: aes_gcm_encrypt and
//   aes_gcm_decrypt reach the same core (.Lgcm_ghash_run and
//   .Lgcm_ghash_lengths) directly, so the tag never goes through this
//   entry point on a live connection. It exists because it is the one
//   place the GHASH construction is exposed on its own, which is what
//   lets tests/security/test_diff_gcm.c sweep it against an independent
//   reference without an AES layer in the way. That is worth an export
//   and ~100 bytes of unreachable text in the shipped binary
//   (docs/SECURITY.md §9, observation 10).
//
// Input/Arguments:
//   x0 — pointer to the 16-byte hash subkey H
//   x1 — pointer to the additional authenticated data (ignored when
//        aad_len == 0)
//   x2 — AAD length in bytes
//   x3 — pointer to the ciphertext (ignored when ct_len == 0)
//   x4 — ciphertext length in bytes
//   x5 — pointer to the 16-byte GHASH result buffer (must not overlap
//        the inputs)
//
// Output/Returns:
//   none (void) - 16 result bytes written to [x5]
//
// Clobbered Registers:
//   x9-x12, x19-x28 (saved/restored), x30 (saved/restored), v0-v7,
//   v16-v21, v22-v30, NZCV
//
//   Unlike the live path, this entry point has no key context to read
//   the GHASH subkey powers from, so it derives them itself — once,
//   here, rather than inside .Lgcm_ghash_run as it used to. Callers
//   with fewer than four blocks now pay for powers they will not use;
//   that is a test-only path and not worth a branch.
//
// Stack Usage:
//   96 bytes - 88 for x19-x28 + x30, 8 slack (the bit-length block
//   has its own frame, in .Lgcm_ghash_lengths)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global ghash

ghash:
    sub     sp, sp, #96
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    str     x30, [sp, #80]

    mov     x19, x0                    // h
    mov     x20, x1                    // aad
    mov     x21, x2                    // aad_len
    mov     x22, x3                    // ct
    mov     x23, x4                    // ct_len
    mov     x24, x5                    // out

    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    ld1     {v19.16b}, [x19]           // H
    gcm_rbit v19.16b, v19.16b          // H' in the natural domain
    bl      .Lgcm_ghash_powers         // H^2..H^4 + cross terms, v22-v28
    movi    v20.16b, #0                // Y' = 0

    mov     x27, x20                   // feed AAD blocks
    mov     x28, x21
    bl      .Lgcm_ghash_run
    mov     x27, x22                   // feed ciphertext blocks
    mov     x28, x23
    bl      .Lgcm_ghash_run

    // [len(A)]_64 || [len(C)]_64, bit lengths, big-endian
    mov     x9, x21
    mov     x10, x23
    bl      .Lgcm_ghash_lengths

    gcm_rbit v20.16b, v0.16b           // back to GCM wire order
    st1     {v0.16b}, [x24]

    ldr     x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #96
    ret
