// ─────────────────────────────────────────────────────────────────────
// Function Name: sha256
//
// Description: SHA-256 compression function using the ARMv8 SHA2 Crypto
//   Extensions (SHA256H, SHA256H2, SHA256SU0, SHA256SU1). Processes one
//   or more 64-byte message blocks and folds them into the 32-byte digest
//   state at [x0]. No libc or external crypto library required.
//
//   This is *only* the compression function: padding the message to a
//   multiple of 64 bytes (0x80 byte, zero pad, 64-bit big-endian bit
//   length) is a separate, non-crypto-extension step.
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
