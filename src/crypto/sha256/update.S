// SHA-256 streaming update

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: sha256_update
//
// Description: Absorb len bytes of input into the context. Bytes are
//   accumulated in ctx->buf; whenever a full 64-byte block is available
//   it is compressed into ctx->state via `sha256`. ctx->bitlen tracks
//   the total message length in bits (FIPS 180-4's 64-bit length field,
//   mod 2^64) and includes buffered-but-not-yet-compressed bytes.
//   A zero-length update is a no-op.
//
// Input/Arguments:
//   x0 — pointer to the context (initialised by sha256_init)
//   x1 — pointer to the input data (ignored when len == 0)
//   x2 — number of bytes to absorb
//
// Output/Returns:
//   none (void) - the context is updated in place
//
// Clobbered Registers:
//   x0, x3, x4, x5, x6, w7, plus everything `sha256` clobbers
//   (x1-x4, v0-v7, v16, v18, v19, NZCV)
//
// Stack Usage:
//   48 bytes - x19..x22 saved (ctx, data, len, buflen) + x30 (return
//   address; `bl` inside this function would clobber it otherwise)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global sha256_update

sha256_update:
    cbz     x2, .Lsha256_update_done          // len == 0: no-op
    stp     x19, x20, [sp, #-48]!
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]                    // save return address

    mov     x19, x0                           // ctx
    mov     x20, x1                           // data cursor
    mov     x21, x2                           // len remaining
    ldr     x22, [x19, #SHA256_CTX_BUFLEN]    // bytes currently buffered

    cbz     x22, .Lsha256_update_blocks       // buffer empty: skip straight
                                              //   to whole-block loop

    // ── top up the partial block ──
    mov     x3, #64
    sub     x3, x3, x22                       // fill = 64 - buflen
    cmp     x3, x21
    csel    x3, x3, x21, ls                   // n = min(fill, len)
    add     x4, x19, #SHA256_CTX_BUF
    add     x4, x4, x22                       // dst = buf + buflen
    mov     x5, x20                           // src = data
    mov     x6, x3                            // count = n
    bl      .Lsha256_memcpy

    add     x22, x22, x3                      // buflen += n
    str     x22, [x19, #SHA256_CTX_BUFLEN]
    ldr     x5, [x19, #SHA256_CTX_BITLEN]
    lsl     x6, x3, #3
    add     x5, x5, x6
    str     x5, [x19, #SHA256_CTX_BITLEN]     // bitlen += n * 8
    add     x20, x20, x3                      // data += n
    sub     x21, x21, x3                      // len -= n

    cmp     x22, #64
    b.ne    .Lsha256_update_restore           // still partial: done for now

    // the block just filled — compress it
    mov     x0, x19
    add     x1, x19, #SHA256_CTX_BUF
    mov     x2, #1
    bl      sha256
    str     xzr, [x19, #SHA256_CTX_BUFLEN]    // buflen = 0

    // ── whole blocks straight from the input ──
.Lsha256_update_blocks:
    cmp     x21, #64
    b.lo    .Lsha256_update_tail
    mov     x0, x19
    mov     x1, x20
    mov     x2, #1
    bl      sha256
    ldr     x5, [x19, #SHA256_CTX_BITLEN]
    add     x5, x5, #512
    str     x5, [x19, #SHA256_CTX_BITLEN]     // bitlen += 64 * 8
    add     x20, x20, #64
    sub     x21, x21, #64
    b       .Lsha256_update_blocks

    // ── buffer the remainder for the next call / final ──
.Lsha256_update_tail:
    cbz     x21, .Lsha256_update_restore
    add     x4, x19, #SHA256_CTX_BUF
    mov     x5, x20
    mov     x6, x21
    bl      .Lsha256_memcpy
    str     x21, [x19, #SHA256_CTX_BUFLEN]
    ldr     x5, [x19, #SHA256_CTX_BITLEN]
    lsl     x6, x21, #3
    add     x5, x5, x6
    str     x5, [x19, #SHA256_CTX_BITLEN]     // bitlen += len * 8

.Lsha256_update_restore:
    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #48
.Lsha256_update_done:
    ret

// ─────────────────────────────────────────────────────────────────────
// Private byte copy: dst = x4, src = x5, count = x6. Leaf; clobbers
// x4, x5, x6, w7 only, so the streaming callers can keep their live
// values in x19..x22 across it.
// ─────────────────────────────────────────────────────────────────────
.Lsha256_memcpy:
    cbz     x6, .Lsha256_memcpy_done
.Lsha256_memcpy_loop:
    ldrb    w7, [x5], #1
    strb    w7, [x4], #1
    subs    x6, x6, #1
    b.ne    .Lsha256_memcpy_loop
.Lsha256_memcpy_done:
    ret
