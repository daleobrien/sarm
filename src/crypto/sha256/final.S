// SHA-256 streaming finalization

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: sha256_final
//
// Description: Finish a streaming SHA-256: append the FIPS 180-4
//   padding (0x80 byte, zero fill, 64-bit big-endian total bit length),
//   compress the final block(s) into ctx->state, and write the state as
//   the 32-byte big-endian digest. The context is left holding the
//   digest words in ctx->state; call sha256_init to reuse it.
//
// Input/Arguments:
//   x0 — pointer to the context
//   x1 — pointer to the 32-byte digest output buffer
//
// Output/Returns:
//   none (void) - 32 digest bytes written to [x1]
//
// Clobbered Registers:
//   x0, x3, x5, v0, v1, plus everything `sha256` clobbers
//   (x1-x4, v0-v7, v16, v18, v19, NZCV)
//
// Stack Usage:
//   48 bytes - x19..x22 saved (ctx, digest, buf, buflen) + x30 (return
//   address; `bl` inside this function would clobber it otherwise)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2

FUNC sha256_final
    stp     x19, x20, [sp, #-48]!
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]                    // save return address

    mov     x19, x0                           // ctx
    mov     x20, x1                           // digest
    add     x21, x19, #SHA256_CTX_BUF         // buf
    ldr     x22, [x19, #SHA256_CTX_BUFLEN]    // buflen

    // 1. append the 0x80 pad byte
    mov     w3, #0x80
    strb    w3, [x21, x22]
    add     x22, x22, #1

    // 2. if the length field no longer fits (buflen > 56), pad to the
    //    end of this block, compress it, and restart padding on a
    //    fresh block.
    cmp     x22, #56
    b.ls    .Lsha256_final_pad_zeros
    mov     x3, x22
.Lsha256_final_zero_to_end:
    cmp     x3, #64
    b.eq    .Lsha256_final_compress_block
    strb    wzr, [x21, x3]
    add     x3, x3, #1
    b       .Lsha256_final_zero_to_end
.Lsha256_final_compress_block:
    mov     x0, x19
    mov     x1, x21
    mov     x2, #1
    bl      sha256
    mov     x22, xzr                          // buflen = 0, fresh block

    // 3. zero-fill the padding up to byte 56
.Lsha256_final_pad_zeros:
    cmp     x22, #56
    b.eq    .Lsha256_final_store_len
    strb    wzr, [x21, x22]
    add     x22, x22, #1
    b       .Lsha256_final_pad_zeros

    // 4. total message length in bits, big-endian, at buf[56..64)
.Lsha256_final_store_len:
    ldr     x5, [x19, #SHA256_CTX_BITLEN]
    rev     x5, x5
    str     x5, [x21, #56]

    // 5. compress the final block
    mov     x0, x19
    mov     x1, x21
    mov     x2, #1
    bl      sha256

    // 6. serialise the state as 32 big-endian digest bytes: byte-swap
    //    each 32-bit lane, then store.
    ld1     {v0.4s, v1.4s}, [x19]
    rev32   v0.16b, v0.16b
    rev32   v1.16b, v1.16b
    st1     {v0.4s, v1.4s}, [x20]

    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #48
    ret
ENDFUNC sha256_final
