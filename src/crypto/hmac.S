// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// File: hmac.S — HMAC-SHA256 for sarm (PLAN.MD Phase 4)
//
// One-shot HMAC-SHA256 (RFC 2104 / FIPS 198-1, hash from RFC 4231),
// built on the streaming SHA-256 API from sha256.S. No libc or external
// crypto library required.
//
//   hmac_sha256 — computes the 32-byte HMAC-SHA256 authenticator of a
//                 message under a key: SHA256((K0 ^ opad) || SHA256(
//                 (K0 ^ ipad) || data)), where K0 is the key zero-
//                 padded to the 64-byte block size, and keys longer
//                 than one block are replaced by their SHA-256 digest
//                 first (RFC 2104 §2). All scratch state (the padded
//                 key block, a SHA-256 context, the hashed-key and
//                 inner digests) is allocated on the stack, so the
//                 function is re-entrant and needs no global context.
//
// Exported Symbols:
//   hmac_sha256 — one-shot authenticator (see the function doc block
//                 below for the calling convention)
//
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// Function Name: hmac_sha256
//
// Description: Compute the 32-byte HMAC-SHA256 authenticator (RFC 4231)
//   of data[0..datalen) under key[0..keylen), following RFC 2104:
//
//     if keylen > 64:  key = SHA256(key), keylen = 32
//     K0   = key zero-padded to 64 bytes
//     ipad = K0 ^ 0x36 (repeated),  opad = K0 ^ 0x5c (repeated)
//     hmac = SHA256(opad || SHA256(ipad || data))
//
//   Built on the streaming API from sha256.S (sha256_init / sha256_update
//   / sha256_final); a single context is reused for the inner and outer
//   hash. A zero-length key or data is valid (the empty message hashes
//   to the empty-string SHA-256 digest), and a NULL data pointer is
//   ignored when datalen == 0.
//
// Input/Arguments:
//   x0 — pointer to the key
//   x1 — key length in bytes (0..2^61; > 64 is hashed first per
//        RFC 2104)
//   x2 — pointer to the message data (ignored when datalen == 0)
//   x3 — message length in bytes (0 is valid)
//   x4 — pointer to the 32-byte digest output buffer
//
// Output/Returns:
//   none (void) - 32 digest bytes written to [x4]. The digest buffer may
//                 alias the key or data buffers; both are fully read
//                 before the digest is written.
//
// Clobbered Registers:
//   x0-x7, x19-x27 (saved/restored), x30 (saved/restored), v0-v7, v16,
//   v18, v19, NZCV — everything the sha256_* calls clobber plus the
//   local .Lhmac_xor64 helper (v0-v4)
//
// Stack Usage:
//   320 bytes - 80 for x19-x27 + x30, 64 for the padded key block K0,
//   112 for the SHA256_CTX_SIZE context, 32 for the hashed long key,
//   32 for the inner digest (all scratch is 16-byte aligned)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global hmac_sha256
hmac_sha256:
    stp     x19, x20, [sp, #-320]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x30, [sp, #64]

    mov     x19, x0                     // key
    mov     x20, x1                     // keylen
    mov     x21, x2                     // data
    mov     x22, x3                     // datalen
    mov     x23, x4                     // digest
    add     x24, sp, #80                // k0: 64-byte padded key block
    add     x25, sp, #144               // ctx: SHA256_CTX_SIZE context
    add     x26, sp, #256               // kh: 32-byte hashed long key
    add     x27, sp, #288               // inner: 32-byte inner digest

    // ── 1. keys longer than one block are replaced by their digest ──
    cmp     x20, #64
    b.ls    .Lhmac_zero_pad
    mov     x0, x25
    bl      sha256_init
    mov     x0, x25
    mov     x1, x19
    mov     x2, x20
    bl      sha256_update
    mov     x0, x25
    mov     x1, x26                     // hashed key lands in kh
    bl      sha256_final
    mov     x19, x26                    // key = kh
    mov     x20, #32                    // keylen = 32

    // ── 2. zero-pad the key into the 64-byte block ──
.Lhmac_zero_pad:
    stp     xzr, xzr, [x24]
    stp     xzr, xzr, [x24, #16]
    stp     xzr, xzr, [x24, #32]
    stp     xzr, xzr, [x24, #48]
    mov     x0, x24                     // dst = k0
    mov     x1, x19                     // src = key
    mov     x2, x20                     // n = keylen
    bl      .Lhmac_memcpy

    // ── 3. inner hash: SHA256((K0 ^ 0x36) || data) ──
    mov     w1, #0x36                   // ipad pad byte
    mov     x0, x24
    bl      .Lhmac_xor64                // k0 ^= 0x36
    mov     x0, x25
    bl      sha256_init
    mov     x0, x25
    mov     x1, x24
    mov     x2, #64
    bl      sha256_update               // absorb ipad
    mov     x0, x25
    mov     x1, x21
    mov     x2, x22
    bl      sha256_update               // absorb data
    mov     x0, x25
    mov     x1, x27
    bl      sha256_final                // inner = SHA256(ipad || data)

    // ── 4. outer hash: SHA256((K0 ^ 0x5c) || inner) ──
    mov     w1, #0x6a                   // 0x36 ^ 0x5c: ipad -> opad
    mov     x0, x24
    bl      .Lhmac_xor64                // k0 ^= 0x5c
    mov     x0, x25
    bl      sha256_init
    mov     x0, x25
    mov     x1, x24
    mov     x2, #64
    bl      sha256_update               // absorb opad
    mov     x0, x25
    mov     x1, x27
    mov     x2, #32
    bl      sha256_update               // absorb inner digest
    mov     x0, x25
    mov     x1, x23
    bl      sha256_final                // digest = SHA256(opad || inner)

    ldp     x27, x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #320
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lhmac_memcpy (private, leaf)
//
// Description: Byte copy used to place the key (or hashed key) into the
//   zeroed 64-byte K0 block.
//
// Input/Arguments:
//   x0 — destination pointer
//   x1 — source pointer
//   x2 — byte count (0 = no-op)
//
// Output/Returns:
//   none (void)
//
// Clobbered Registers:
//   x0, x1, x2, w3, NZCV
//
// Stack Usage:
//   none - leaf function
// ─────────────────────────────────────────────────────────────────────

.Lhmac_memcpy:
    cbz     x2, .Lhmac_memcpy_done
.Lhmac_memcpy_loop:
    ldrb    w3, [x1], #1
    strb    w3, [x0], #1
    subs    x2, x2, #1
    b.ne    .Lhmac_memcpy_loop
.Lhmac_memcpy_done:
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lhmac_xor64 (private, leaf)
//
// Description: XOR the 64 bytes at [x0] with the byte pattern in w1,
//   repeated across the block (Neon dup + eor, 4 x 16-byte lanes).
//
// Input/Arguments:
//   x0 — pointer to the 64-byte block, updated in place
//   w1 — the byte pattern to XOR with
//
// Output/Returns:
//   none (void) - the block is XORed in place
//
// Clobbered Registers:
//   v0-v4
//
// Stack Usage:
//   none - leaf function
// ─────────────────────────────────────────────────────────────────────

.Lhmac_xor64:
    dup     v0.16b, w1
    ld1     {v1.16b, v2.16b, v3.16b, v4.16b}, [x0]
    eor     v1.16b, v1.16b, v0.16b
    eor     v2.16b, v2.16b, v0.16b
    eor     v3.16b, v3.16b, v0.16b
    eor     v4.16b, v4.16b, v0.16b
    st1     {v1.16b, v2.16b, v3.16b, v4.16b}, [x0]
    ret
