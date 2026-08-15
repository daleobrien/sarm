// ====================================================================
// ARM64 (AArch64) Neon Assembly Implementation of AES-128 (PLAN.MD 6)
// File: aes128.S
//
//   aes128_key_expand — FIPS-197 §5.2 key schedule (176-byte RK0..RK10)
//   aes128_encrypt    — FIPS-197 §5.1 block cipher, one 16-byte block
//
// Both are built on the ARMv8 Crypto Extensions: AESE/AESMC for the
// block cipher, and AESE (SubWord) + TBL (RotWord/ShiftRows fold-in)
// for the key schedule — no S-box table lives in this binary.
// ====================================================================

#include "../defs.S"

.text
.align 4

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes128_key_expand
//
// Description: Expand a 16-byte AES-128 key into the FIPS-197 §5.2
//   round-key schedule — 11 consecutive 16-byte keys (RK0..RK10, 176
//   bytes total), exactly the layout aes128_encrypt consumes. C proto:
//   void aes128_key_expand(const uint8_t *key, uint8_t *round_keys);
//
//   The schedule is generated one word at a time:
//
//     w[0..3]  = the key (RK0)
//     g(w)     = SubWord(RotWord(w)) ^ Rcon[i/4]   (when i % 4 == 0)
//     w[i]     = w[i-4] ^ w[i-1]
//
//   SubWord is computed with the ARMv8 AESE instruction instead of an
//   S-box table: AESE with a zero round key applies SubBytes then
//   ShiftRows. RotWord is folded into a single TBL lookup (.Laes128_tbl)
//   that also scatters the four bytes onto the state positions which
//   ShiftRows maps back into one 32-bit lane, so the whole g() costs one
//   TBL + one AESE + one scalar Rcon XOR per round. The four output
//   words are then formed by the standard XOR chain in scalar registers.
//   The output buffer must hold 176 bytes and must not overlap the key
//   (the key is only read at the very start, so an alias is harmless as
//   long as the buffer is big enough).
//
// Input/Arguments:
//   x0 — pointer to the 16-byte AES-128 key
//   x1 — pointer to the 176-byte round-key output buffer (RK0..RK10)
//
// Output/Returns:
//   none (void) - 176 schedule bytes written to [x1]
//
// Clobbered Registers:
//   x0-x4, w5-w8, w10, w11, v0-v4, NZCV
//
// Stack Usage:
//   0 bytes — leaf function, no stack frame
// ─────────────────────────────────────────────────────────────────────

.global aes128_key_expand
aes128_key_expand:
    ld1     {v0.16b}, [x0]          // v0 = RK0 = the key itself
    st1     {v0.16b}, [x1], #16     // RK0 -> schedule

    adr_l   x2, .Laes128_rcon       // x2 = Rcon byte table
    adr_l   x3, .Laes128_tbl        // x3 = TBL index vector
    ld1     {v3.16b}, [x3]          // v3 = TBL index vector
    movi    v4.16b, #0              // v4 = zero round key (AESE operand)
    mov     x4, #10                 // 10 expansion rounds

.Lkey_expand_round:
    ldrb    w11, [x2], #1           // w11 = Rcon[round] (1, 2, ..., 0x36)

    // ── g(w3) = SubWord(RotWord(w3)) ^ Rcon, via TBL + AESE ──
    // v3 scatters w3's bytes (state flats 12..15) onto the four flats
    // {12, 1, 6, 11} that ShiftRows maps back into word 3, so the AESE
    // output lane 3 is exactly [S(b1) S(b2) S(b3) S(b0)] where
    // w3 = [b0 b1 b2 b3] — i.e. SubWord(RotWord(w3)) as one word.
    tbl     v1.16b, {v0.16b}, v3.16b
    aese    v1.16b, v4.16b          // SubBytes (ShiftRows pre-compensated)
    umov    w10, v1.s[3]            // t = the g() word (native endian)
    eor     w10, w10, w11           // t ^= Rcon (lane byte 0 = word MSB)

    // ── w4 = w0^t, w5 = w1^w4, w6 = w2^w5, w7 = w3^w6 ──
    umov    w5, v0.s[0]             // w0
    umov    w6, v0.s[1]             // w1
    umov    w7, v0.s[2]             // w2
    umov    w8, v0.s[3]             // w3
    eor     w5, w5, w10             // w4 = w0 ^ t
    eor     w6, w6, w5              // w5 = w1 ^ w4
    eor     w7, w7, w6              // w6 = w2 ^ w5
    eor     w8, w8, w7              // w7 = w3 ^ w6

    ins     v2.s[0], w5
    ins     v2.s[1], w6
    ins     v2.s[2], w7
    ins     v2.s[3], w8
    st1     {v2.16b}, [x1], #16     // RKround -> schedule
    mov     v0.16b, v2.16b          // v0 = RKround for the next round

    subs    x4, x4, #1
    b.ne    .Lkey_expand_round
    ret

// ---- Rcon byte table (FIPS-197 §5.2), rounds 1..10 ----
.align 4
.Laes128_rcon:
.byte 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36

// ---- TBL index vector for the AESE SubWord ----
// AES state flats: flat(r,c) = r + 4c. ShiftRows maps input flat p to
// output flat q as:
//   q=12<-12  q=13<-1  q=14<-6  q=15<-11   (output word 3)
// so feeding w3's bytes [b0 b1 b2 b3] = flats [12 13 14 15] onto flats
// {12, 1, 6, 11} makes AESE lane 3 come out as SubWord(RotWord(w3)).
// Index bytes name the source byte of v0; 0x80 (>= 16) zeroes a lane.
.align 4
.Laes128_tbl:
.byte 0x80, 0x0e, 0x80, 0x80, 0x80, 0x80, 0x0f, 0x80
.byte 0x80, 0x80, 0x80, 0x0c, 0x0d, 0x80, 0x80, 0x80

// ─────────────────────────────────────────────────────────────────────
// Function Name: aes128_encrypt
//
// Description: Encrypts one 16-byte block with AES-128 using the ARMv8
//              Crypto Extensions (AESE/AESMC). The caller supplies the
//              FIPS-197 round-key schedule — 11 consecutive 16-byte keys
//              (RK0..RK10, 176 bytes total). C prototype:
//              void aes128_encrypt(const uint8_t *plaintext,
//                                  const uint8_t *round_keys,
//                                  uint8_t *ciphertext);
//
// Input/Arguments:
//   x0 — Pointer to the 16-byte plaintext block
//   x1 — Pointer to the 176-byte round-key schedule (RK0..RK10)
//   x2 — Pointer to the 16-byte ciphertext output buffer
//
// Output/Returns:
//   x2 - 16-byte ciphertext stored to [x2]; no register return value
//
// Clobbered Registers:
//   x0,x1,x2,v0..v11
//
// Stack Usage:
//   0 bytes — leaf function, no stack frame
//
// ──

.global aes128_encrypt
aes128_encrypt:
    // 1. Load the 16-byte input block into Neon register v0
    ld1 {v0.16b}, [x0]

    // 2. Load all 11 Round Keys (16 bytes each) into Neon registers v1 to v11
    ld1 {v1.16b, v2.16b, v3.16b, v4.16b}, [x1], #64
    ld1 {v5.16b, v6.16b, v7.16b, v8.16b}, [x1], #64
    ld1 {v9.16b, v10.16b, v11.16b}, [x1]

    // --- CRITICAL ARCHITECTURE NOTE ---
    // The ARMv8 `aese` instruction performs AddRoundKey FIRST,
    // followed by SubBytes and ShiftRows.
    // This allows us to perfectly chain the standard AES pipeline.

    // --- ROUNDS 1 - 9 ---
    // Each standard round consists of: aese (AddRoundKey + SubBytes + ShiftRows) -> aesmc (MixColumns)

    aese  v0.16b, v1.16b      // Round 1: AddRoundKey(RK0) + SubBytes + ShiftRows
    aesmc v0.16b, v0.16b      // Round 1: MixColumns

    aese  v0.16b, v2.16b      // Round 2
    aesmc v0.16b, v0.16b

    aese  v0.16b, v3.16b      // Round 3
    aesmc v0.16b, v0.16b

    aese  v0.16b, v4.16b      // Round 4
    aesmc v0.16b, v0.16b

    aese  v0.16b, v5.16b      // Round 5
    aesmc v0.16b, v0.16b

    aese  v0.16b, v6.16b      // Round 6
    aesmc v0.16b, v0.16b

    aese  v0.16b, v7.16b      // Round 7
    aesmc v0.16b, v0.16b

    aese  v0.16b, v8.16b      // Round 8
    aesmc v0.16b, v0.16b

    aese  v0.16b, v9.16b      // Round 9
    aesmc v0.16b, v0.16b

    // --- FINAL ROUND (ROUND 10) ---
    // The final AES round does NOT include MixColumns.

    aese  v0.16b, v10.16b     // Round 10: AddRoundKey(RK9) + SubBytes + ShiftRows
    eor   v0.16b, v0.16b, v11.16b // Final AddRoundKey(RK10) via standard Neon XOR

    // 3. Store the final 16-byte ciphertext block to output memory
    st1 {v0.16b}, [x2]

    ret
