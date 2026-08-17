// ====================================================================
// ARM64 (AArch64) Neon Assembly - AES-128 Block Cipher (PLAN.MD 6)
//
// aes128_encrypt — FIPS-197 §5.1 block cipher, one 16-byte block
//
// Built on ARMv8 Crypto Extensions: AESE/AESMC for the block cipher.
// ====================================================================

#include "../../defs.S"

.text
.align 4

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
//   x1, v0..v11
//
// Stack Usage:
//   0 bytes — leaf function, no stack frame
// ─────────────────────────────────────────────────────────────────────

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
