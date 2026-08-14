// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// File: sha256.S — SHA-256 for ymawky (PLAN.MD Phase 3)
//
// Two layers, no libc or external crypto library required:
//
//   sha256      — the compression function, built on the ARMv8 SHA2
//                 Crypto Extensions (SHA256H, SHA256H2, SHA256SU0,
//                 SHA256SU1). Processes whole 64-byte message blocks and
//                 folds them into the 32-byte digest state at [x0].
//                 Padding the message (0x80 byte, zero pad, 64-bit
//                 big-endian bit length) is *not* its job.
//
//   sha256_init / sha256_update / sha256_final — the streaming API
//                 (PLAN.MD §3.2). sha256_init seeds a context (layout
//                 in defs.S: SHA256_CTX_*) with the FIPS 180-4 IV;
//                 sha256_update absorbs arbitrary-length input, feeding
//                 whole blocks to `sha256`; sha256_final appends the
//                 FIPS 180-4 padding, runs the last block(s), and
//                 serialises the state as the 32-byte big-endian digest.
//
// Exported Symbols:
//   K256        — the 64 round constants (file-local)
//   sha256_h256 — the FIPS 180-4 initial hash state (8 x u32)
//   sha256      — compression: sha256(state=x0, data=x1, nblocks=x2)
//   sha256_init    — sha256_init(ctx=x0)
//   sha256_update  — sha256_update(ctx=x0, data=x1, len=x2)
//   sha256_final   — sha256_final(ctx=x0, digest=x1)
//
// ─────────────────────────────────────────────────────────────────────

// Function Name: sha256
//
// Description: SHA-256 compression function (see file header). Processes
//   one or more 64-byte message blocks and folds them into the 32-byte
//   digest state at [x0].
//
// Input/Arguments:
//   x0 — pointer to 32-byte state {H0..H7}, stored as two 16-byte
//        vectors: ABCD (bytes 0-15) and EFGH (bytes 16-31), each word
//        big-endian-value-in-native-u32 (i.e. plain host u32s)
//   x1 — pointer to input message; length must be a multiple of 64 bytes
//   x2 — number of 64-byte blocks to process (0 = no-op, returns early)
//
// Output/Returns:
//   none (void) - the updated 32-byte state is written back to [x0]
//                 in place
//
// Clobbered Registers:
//   x1, x2, x3, x4, v0-v7, v16, v18, v19, NZCV
//
// Stack Usage:
//   none - leaf function, no stack frame allocated
//
// ─────────────────────────────────────────────────────────────────────

.text
.align 4
.global sha256

// ---- SHA-256 round constants (FIPS 180-4), 64 x 32-bit words ----
.align 4
K256:
.word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
.word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
.word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
.word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
.word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
.word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
.word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
.word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
.word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
.word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
.word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
.word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
.word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
.word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
.word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
.word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

// ---- Initial hash state H0..H7, for a fresh context ----
.align 4
.global sha256_h256
sha256_h256:
.word 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
.word 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

// ------------------------------------------------------------------
// void sha256(uint32_t state[8], const void *data, size_t nblocks)
// ------------------------------------------------------------------
sha256:
    cbz     x2, .Ldone

    ld1     {v0.4s, v1.4s}, [x0]      // v0 = ABCD, v1 = EFGH  (current state)
    adrp    x3, K256@PAGE
    add     x3, x3, K256@PAGEOFF

.Lblock_loop:
    mov     x4, x3                     // reset K pointer to start of table each block
    ld1     {v4.4s-v7.4s}, [x1], #64   // load W0..W15 (this block's 16 message words)

    // Message words arrive as raw bytes; SHA-256 treats each 32-bit
    // word as big-endian, so byte-swap each lane.
    rev32   v4.16b, v4.16b
    rev32   v5.16b, v5.16b
    rev32   v6.16b, v6.16b
    rev32   v7.16b, v7.16b

    mov     v2.16b, v0.16b             // v2/v3 = copy of state, added back at the end
    mov     v3.16b, v1.16b

    // 16 groups of 4 rounds = 64 rounds total.
    // Groups 0-3 consume W0..W15 directly.
    // Groups 4-15 first expand new message words via SHA256SU0/SU1.

    // ---- group 0 (W0..W3) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v4.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s

    // ---- group 1 (W4..W7) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v5.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s

    // ---- group 2 (W8..W11) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v6.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s

    // ---- group 3 (W12..W15) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v7.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s

    // ---- groups 4..15: same pattern, cycling through v4,v5,v6,v7 as
    // the rolling message-schedule window. The .rept 3 below expands to
    // 12 groups (48 rounds), completing rounds 16..63. Each group:
    //   1. ld1 next 4 round constants
    //   2. add K + W(current)
    //   3. sha256h / sha256h2 against saved ABCD
    //   4. sha256su0 / sha256su1 to compute W(current+16) in place
    //
    // One .rept iteration = groups 4-7 (W16..W31). Each further
    // iteration's W indices shift by +16 (groups 8-11: W32..W47,
    // groups 12-15: W48..W63).

    .rept 3

    // ---- group (v4 window: W16..W19, W32..W35, W48..W51) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v4.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s

    // ---- group (v5 window: W20..W23, W36..W39, W52..W55) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v5.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s

    // ---- group (v6 window: W24..W27, W40..W43, W56..W59) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v6.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s

    // ---- group (v7 window: W28..W31, W44..W47, W60..W63) ----
    ld1     {v16.4s}, [x4], #16
    add     v18.4s, v16.4s, v7.4s
    mov     v19.16b, v0.16b
    sha256h q0, q1, v18.4s
    sha256h2 q1, q19, v18.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s

    .endr

    add     v0.4s, v0.4s, v2.4s        // fold this block's changes into running state
    add     v1.4s, v1.4s, v3.4s

    subs    x2, x2, #1
    b.ne    .Lblock_loop

    st1     {v0.4s, v1.4s}, [x0]

.Ldone:
    ret

// ==================================================================
// Streaming SHA-256 (PLAN.MD §3.2)
//
// All three functions take a context pointer in x0. The context is
// SHA256_CTX_SIZE bytes laid out per the SHA256_CTX_* offsets in
// defs.S; src/crypto/data.S provides a ready-made global (sha256_ctx).
// sha256_init must be called before the first update, and again to
// reuse a context after sha256_final.
// ==================================================================

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

.align 2
.global sha256_init
sha256_init:
    adrp    x1, sha256_h256@PAGE
    add     x1, x1, sha256_h256@PAGEOFF
    ld1     {v0.4s, v1.4s}, [x1]              // FIPS 180-4 IV (H0..H7)
    st1     {v0.4s, v1.4s}, [x0]              // ctx->state

    str     xzr, [x0, #SHA256_CTX_BITLEN]     // total message bits = 0
    stp     xzr, xzr, [x0, #SHA256_CTX_BUF]   // zero the 64-byte partial
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 16)]  //   block buffer...
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 32)]
    stp     xzr, xzr, [x0, #(SHA256_CTX_BUF + 48)]
    str     xzr, [x0, #SHA256_CTX_BUFLEN]     // nothing buffered yet
    ret

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
//   x3, x4, x5, x6, w7, plus everything `sha256` clobbers
//   (x1-x4, v0-v7, v16, v18, v19, NZCV)
//
// Stack Usage:
//   48 bytes - x19..x22 saved (ctx, data, len, buflen) + x30 (return
//   address; `bl` inside this function would clobber it otherwise)
// ─────────────────────────────────────────────────────────────────────

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

// Private byte copy: dst = x4, src = x5, count = x6. Leaf; clobbers
// x4, x5, x6, w7 only, so the streaming callers can keep their live
// values in x19..x22 across it.
.Lsha256_memcpy:
    cbz     x6, .Lsha256_memcpy_done
.Lsha256_memcpy_loop:
    ldrb    w7, [x5], #1
    strb    w7, [x4], #1
    subs    x6, x6, #1
    b.ne    .Lsha256_memcpy_loop
.Lsha256_memcpy_done:
    ret

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
//   x3, x5, v0, v1, plus everything `sha256` clobbers
//   (x1-x4, v0-v7, v16, v18, v19, NZCV)
//
// Stack Usage:
//   48 bytes - x19..x22 saved (ctx, digest, buf, buflen) + x30 (return
//   address; `bl` inside this function would clobber it otherwise)
// ─────────────────────────────────────────────────────────────────────

.align 2
.global sha256_final
sha256_final:
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
