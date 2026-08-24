// Unit tests for AES-GCM decryption and authentication — src/crypto/gcm/decrypt.S
//
// The aes_gcm_decrypt symbol: AES-128-GCM open
// (key=x0, iv=x1, aad=x2, aad_len=x3, ct=x4, ct_len=x5, tag=x6, pt=x7)
// Returns 1 on verified tag (plaintext written) and 0 otherwise

#include "test_harness.h"

extern void aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv,
                            const uint8_t *aad, uint64_t aad_len,
                            const uint8_t *pt, uint64_t pt_len,
                            uint8_t *ct, uint8_t *tag)
    __asm__("aes_gcm_encrypt");
extern uint64_t aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv,
                                const uint8_t *aad, uint64_t aad_len,
                                const uint8_t *ct, uint64_t ct_len,
                                const uint8_t *tag, uint8_t *pt)
    __asm__("aes_gcm_decrypt");

// ── AES-128 reference (FIPS 197 §5) ──────────────────────────────────────

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t RCON[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static uint32_t rotl8(uint32_t w) { return (w << 8) | (w >> 24); }

static void key_expand(const uint8_t key[16], uint8_t rk[176]) {
    uint32_t w[44];
    for (int i = 0; i < 4; i++)
        w[i] = ((uint32_t)key[4 * i] << 24) |
               ((uint32_t)key[4 * i + 1] << 16) |
               ((uint32_t)key[4 * i + 2] << 8) |
               (uint32_t)key[4 * i + 3];
    for (int i = 4; i < 44; i++) {
        uint32_t t = w[i - 1];
        if ((i & 3) == 0) {
            t = rotl8(t);
            t = ((uint32_t)SBOX[(t >> 24) & 0xff] << 24) |
                ((uint32_t)SBOX[(t >> 16) & 0xff] << 16) |
                ((uint32_t)SBOX[(t >> 8) & 0xff] << 8) |
                (uint32_t)SBOX[t & 0xff];
            t ^= (uint32_t)RCON[i / 4 - 1] << 24;
        }
        w[i] = w[i - 4] ^ t;
    }
    for (int i = 0; i < 44; i++) {
        rk[4 * i + 0] = (uint8_t)(w[i] >> 24);
        rk[4 * i + 1] = (uint8_t)(w[i] >> 16);
        rk[4 * i + 2] = (uint8_t)(w[i] >> 8);
        rk[4 * i + 3] = (uint8_t)w[i];
    }
}

static void ref_encrypt(const uint8_t pt[16], const uint8_t rk[176],
                        uint8_t ct[16]) {
    uint8_t s[16], t[16];
    for (int i = 0; i < 16; i++)
        s[i] = pt[i] ^ rk[i];
    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++)
            s[i] = SBOX[s[i]];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                t[r + 4 * c] = s[r + 4 * ((c + r) & 3)];
        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = t[0 + 4 * c], a1 = t[1 + 4 * c];
                uint8_t a2 = t[2 + 4 * c], a3 = t[3 + 4 * c];
                uint8_t tmp = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                t[0 + 4 * c] = (uint8_t)(a0 ^ xtime(a0 ^ a1) ^ tmp);
                t[1 + 4 * c] = (uint8_t)(a1 ^ xtime(a1 ^ a2) ^ tmp);
                t[2 + 4 * c] = (uint8_t)(a2 ^ xtime(a2 ^ a3) ^ tmp);
                t[3 + 4 * c] = (uint8_t)(a3 ^ xtime(a3 ^ a0) ^ tmp);
            }
        }
        for (int i = 0; i < 16; i++)
            s[i] = t[i] ^ rk[16 * round + i];
    }
    for (int i = 0; i < 16; i++)
        ct[i] = s[i];
}

// ── independent C references (SP 800-38D §6.3/§6.4) ──────────────────────

static void ref_gf_mult(const uint8_t x[16], const uint8_t y[16],
                        uint8_t z[16]) {
    uint8_t v[16];
    memcpy(v, x, 16);
    memset(z, 0, 16);
    for (int i = 0; i < 128; i++) {
        if (y[i >> 3] & (0x80 >> (i & 7)))
            for (int j = 0; j < 16; j++)
                z[j] ^= v[j];
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (lsb)
            v[0] ^= 0xE1;
    }
}

static void ref_ghash_block(const uint8_t h[16], uint8_t y[16],
                            const uint8_t block[16]) {
    uint8_t t[16];
    for (int i = 0; i < 16; i++)
        t[i] = block[i] ^ y[i];
    ref_gf_mult(t, h, y);
}

static void ref_ghash(const uint8_t h[16], const uint8_t *aad,
                      uint64_t aad_len, const uint8_t *ct, uint64_t ct_len,
                      uint8_t out[16]) {
    uint8_t y[16] = {0};
    uint8_t block[16];
    for (uint64_t i = 0; i < aad_len; i += 16) {
        uint64_t n = (aad_len - i < 16) ? aad_len - i : 16;
        memset(block, 0, 16);
        memcpy(block, aad + i, (size_t)n);
        ref_ghash_block(h, y, block);
    }
    for (uint64_t i = 0; i < ct_len; i += 16) {
        uint64_t n = (ct_len - i < 16) ? ct_len - i : 16;
        memset(block, 0, 16);
        memcpy(block, ct + i, (size_t)n);
        ref_ghash_block(h, y, block);
    }
    for (int i = 0; i < 8; i++) {
        block[i] = (uint8_t)((aad_len * 8) >> (56 - 8 * i));
        block[8 + i] = (uint8_t)((ct_len * 8) >> (56 - 8 * i));
    }
    ref_ghash_block(h, y, block);
    memcpy(out, y, 16);
}

static void ref_inc32(uint8_t j[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++j[i] != 0)
            break;
    }
}

static void ref_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
                            const uint8_t *aad, uint64_t aad_len,
                            const uint8_t *pt, uint64_t pt_len,
                            uint8_t *ct, uint8_t tag[16]) {
    uint8_t rk[176], zero[16] = {0}, h[16], j0[16], j[16], mask[16], y[16];
    key_expand(key, rk);
    ref_encrypt(zero, rk, h);
    memcpy(j0, iv, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    memcpy(j, j0, 16);
    ref_inc32(j);
    for (uint64_t i = 0; i < pt_len; i += 16) {
        ref_encrypt(j, rk, mask);
        uint64_t n = (pt_len - i < 16) ? pt_len - i : 16;
        for (uint64_t k = 0; k < n; k++)
            ct[i + k] = pt[i + k] ^ mask[k];
        ref_inc32(j);
    }
    ref_encrypt(j0, rk, mask);
    ref_ghash(h, aad, aad_len, ct, pt_len, y);
    for (int i = 0; i < 16; i++)
        tag[i] = mask[i] ^ y[i];
}

static int ref_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
                           const uint8_t *aad, uint64_t aad_len,
                           const uint8_t *ct, uint64_t ct_len,
                           const uint8_t tag[16], uint8_t *pt) {
    uint8_t rk[176], zero[16] = {0}, h[16], j0[16], j[16], mask[16], y[16],
            t[16];
    key_expand(key, rk);
    ref_encrypt(zero, rk, h);
    memcpy(j0, iv, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    ref_ghash(h, aad, aad_len, ct, ct_len, y);
    ref_encrypt(j0, rk, mask);
    int diff = 0;
    for (int i = 0; i < 16; i++) {
        t[i] = mask[i] ^ y[i];
        diff |= t[i] ^ tag[i];
    }
    if (diff)
        return 0;
    memcpy(j, j0, 16);
    ref_inc32(j);
    for (uint64_t i = 0; i < ct_len; i += 16) {
        ref_encrypt(j, rk, mask);
        uint64_t n = (ct_len - i < 16) ? ct_len - i : 16;
        for (uint64_t k = 0; k < n; k++)
            pt[i + k] = ct[i + k] ^ mask[k];
        ref_inc32(j);
    }
    return 1;
}

// ── NIST SP 800-38D Appendix B test cases ────────────────────────────────

// Test Case 1
static const uint8_t TC1_KEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
static const uint8_t TC1_IV[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t TC1_AAD[] = {};
static const uint8_t TC1_CT[] = {};
static const uint8_t TC1_TAG[] = {
    0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57,
    0xa4, 0xe7, 0x45, 0x5a,
};
#define TC1_PT_LEN 0
#define TC1_AAD_LEN 0

// Test Case 2
static const uint8_t TC2_KEY[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
static const uint8_t TC2_IV[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t TC2_AAD[] = {};
static const uint8_t TC2_PT[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
static const uint8_t TC2_CT[] = {
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
    0x71, 0xb2, 0xfe, 0x78,
};
static const uint8_t TC2_TAG[] = {
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2,
    0x12, 0x57, 0xbd, 0xdf,
};
#define TC2_PT_LEN 16
#define TC2_AAD_LEN 0

// Test Case 3
static const uint8_t TC3_KEY[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
    0x67, 0x30, 0x83, 0x08,
};
static const uint8_t TC3_IV[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t TC3_AAD[] = {};
static const uint8_t TC3_PT[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    0x1a, 0xaf, 0xd2, 0x55,
};
static const uint8_t TC3_CT[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
    0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
    0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
    0x47, 0x3f, 0x59, 0x85,
};
static const uint8_t TC3_TAG[] = {
    0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd, 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd,
    0x2b, 0xa6, 0xfa, 0xb4,
};
#define TC3_PT_LEN 64
#define TC3_AAD_LEN 0

// Test Case 4
static const uint8_t TC4_KEY[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
    0x67, 0x30, 0x83, 0x08,
};
static const uint8_t TC4_IV[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
};
static const uint8_t TC4_AAD[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
};
static const uint8_t TC4_PT[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
};
static const uint8_t TC4_CT[] = {
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
    0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
    0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
    0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
};
static const uint8_t TC4_TAG[] = {
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a,
    0xe7, 0x12, 0x1a, 0x47,
};
#define TC4_PT_LEN 60
#define TC4_AAD_LEN 20

// ── independent vectors (OpenSSL via Python cryptography) ───────────────

// Independent vector 1: key=2b7e151628aed2a6abf7158809cf4f3c
// iv=000102030405060708090a0b aad=(empty), pt=0 bytes
static const uint8_t X1_KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
};
static const uint8_t X1_IV[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
};
static const uint8_t X1_AAD[] = {};
static const uint8_t X1_PT[] = {};
static const uint8_t X1_CT[] = {};
static const uint8_t X1_TAG[] = {
    0xa7, 0x15, 0xb9, 0x95, 0x67, 0xea, 0xea, 0x48, 0x06, 0xb3, 0xa9, 0x1c,
    0x78, 0x5f, 0x11, 0xcc,
};
#define X1_PT_LEN 0
#define X1_AAD_LEN 0

// Independent vector 2: 5-byte partial final block
static const uint8_t X2_KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
};
static const uint8_t X2_IV[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
};
static const uint8_t X2_AAD[] = {};
static const uint8_t X2_PT[] = {0x32, 0x37, 0x10, 0xd4, 0x1d};
static const uint8_t X2_CT[] = {0x69, 0xf8, 0x2b, 0x82, 0xa5};
static const uint8_t X2_TAG[] = {
    0xec, 0x15, 0x72, 0x52, 0x56, 0x81, 0x8c, 0xd9, 0xe5, 0x3a, 0xac, 0x58,
    0x55, 0xbd, 0x24, 0xde,
};
#define X2_PT_LEN 5
#define X2_AAD_LEN 0

// Independent vector 3: 2-byte AAD + 37-byte PT
static const uint8_t X3_KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
};
static const uint8_t X3_IV[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
};
static const uint8_t X3_AAD[] = {0xaa, 0xbb};
static const uint8_t X3_PT[] = {
    0x13, 0xec, 0xdf, 0xd2, 0x32, 0xb7, 0x9d, 0x47, 0xc9, 0x46, 0x3a, 0x01,
    0x0c, 0x2c, 0x8f, 0x31, 0x0f, 0xc5, 0xb7, 0x57, 0x2f, 0x71, 0x2f, 0xc2,
    0xb4, 0x47, 0xa4, 0x5c, 0xcf, 0x00, 0x42, 0xae, 0xef, 0x10, 0xab, 0xb2,
    0x84,
};
static const uint8_t X3_CT[] = {
    0x1b, 0x38, 0x37, 0x2e, 0x75, 0x5e, 0xa5, 0xe8, 0x62, 0x81, 0x51, 0x92,
    0x21, 0x4a, 0xcd, 0x5e, 0x51, 0xbb, 0xe4, 0x4a, 0x7d, 0x12, 0xcc, 0xde,
    0x3f, 0x3c, 0xc8, 0x7d, 0x9a, 0xee, 0x21, 0x1e, 0xe3, 0xe3, 0xff, 0x9e,
    0x84,
};
static const uint8_t X3_TAG[] = {
    0xd8, 0xef, 0xff, 0x8b, 0x59, 0x95, 0x22, 0x44, 0x95, 0x57, 0xaf, 0x8b,
    0xec, 0x88, 0x8c, 0x62,
};
#define X3_PT_LEN 37
#define X3_AAD_LEN 2

// Independent vector 4: 100-byte multi-block PT with 16-byte AAD
static const uint8_t X4_KEY[] = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
    0x03, 0x02, 0x01, 0x00,
};
static const uint8_t X4_IV[] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xf0, 0x0d, 0xfe, 0xed,
};
static const uint8_t X4_AAD[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff,
};
static const uint8_t X4_PT[] = {
    0xd7, 0xa7, 0x62, 0x58, 0xa5, 0xc2, 0x29, 0xdf, 0x57, 0x58, 0x70, 0xea,
    0x5a, 0xfd, 0xfa, 0xde, 0xe7, 0xc4, 0x00, 0x02, 0x73, 0x55, 0x28, 0x55,
    0xd3, 0x59, 0x4d, 0x0e, 0x93, 0x56, 0x6e, 0x9e, 0xf9, 0x40, 0x2e, 0xbf,
    0xa4, 0x45, 0xc3, 0xb8, 0x02, 0x65, 0x0e, 0x65, 0xa0, 0xc9, 0xf2, 0x29,
    0x88, 0x61, 0xa2, 0xc4, 0xcf, 0xc7, 0xd9, 0x5b, 0xd9, 0x27, 0x6e, 0xe2,
    0x2f, 0x0e, 0x47, 0x3b, 0x10, 0x36, 0xad, 0x82, 0x6a, 0x64, 0xc7, 0x30,
    0x90, 0x26, 0xf8, 0x64, 0x8f, 0x68, 0x03, 0x6c, 0x51, 0x4d, 0x43, 0xc7,
    0x1b, 0x7a, 0x0f, 0x6a, 0x41, 0xe3, 0x50, 0x5f, 0x08, 0xcd, 0x80, 0xc3,
    0x8c, 0xf8, 0x16, 0x1a,
};
static const uint8_t X4_CT[] = {
    0xf3, 0xfe, 0xd2, 0x90, 0x72, 0x3b, 0x65, 0xb1, 0xde, 0xba, 0x3f, 0x95,
    0xf7, 0x60, 0xbe, 0x8c, 0x73, 0x2d, 0x91, 0xa7, 0x45, 0xdc, 0x3c, 0x48,
    0x94, 0x26, 0x02, 0x04, 0x92, 0x81, 0xff, 0xa0, 0x69, 0x6f, 0xda, 0xa2,
    0x62, 0xbd, 0x17, 0xcd, 0xc8, 0xaa, 0x0d, 0x57, 0x9e, 0xd6, 0x9a, 0x92,
    0x70, 0xb2, 0x25, 0x19, 0x28, 0xe6, 0xa2, 0x56, 0x79, 0x94, 0x8d, 0x91,
    0x03, 0x15, 0xc3, 0xcc, 0xd4, 0x18, 0x5c, 0x5f, 0xae, 0xf6, 0xb0, 0x03,
    0x36, 0xf5, 0x4b, 0xfb, 0xb8, 0x6c, 0xfe, 0x6d, 0x09, 0xf9, 0x16, 0x7b,
    0x49, 0x35, 0xbc, 0x36, 0xf6, 0x13, 0x15, 0x66, 0xc3, 0xc6, 0x86, 0x26,
    0x22, 0x5f, 0x69, 0x04,
};
static const uint8_t X4_TAG[] = {
    0xc3, 0x7c, 0x34, 0xb5, 0x60, 0x03, 0xfe, 0x9a, 0xca, 0x2a, 0x70, 0xe1,
    0xbd, 0x98, 0x0e, 0xce,
};
#define X4_PT_LEN 100
#define X4_AAD_LEN 16

// ── tests ───────────────────────────────────────────────────────────────

// Run the NIST vectors through the full asm open pipeline
// (acceptance: all NIST GCM vectors pass).
static void test_gcm_decrypt_kat(void) {
    TEST_SUITE("aes_gcm_decrypt NIST SP 800-38D vectors");
    uint8_t pt[128];
    int failures = 0;

    if (aes_gcm_decrypt(TC1_KEY, TC1_IV, TC1_AAD, TC1_AAD_LEN, TC1_CT,
                        TC1_PT_LEN, TC1_TAG, pt) != 1) {
        _FAIL("TC1 open failed");
        failures++;
    }
    if (aes_gcm_decrypt(TC2_KEY, TC2_IV, TC2_AAD, TC2_AAD_LEN, TC2_CT,
                        TC2_PT_LEN, TC2_TAG, pt) != 1 ||
        memcmp(pt, TC2_PT, TC2_PT_LEN) != 0) {
        _FAIL("TC2 open failed or plaintext wrong");
        failures++;
    }
    if (aes_gcm_decrypt(TC3_KEY, TC3_IV, TC3_AAD, TC3_AAD_LEN, TC3_CT,
                        TC3_PT_LEN, TC3_TAG, pt) != 1 ||
        memcmp(pt, TC3_PT, TC3_PT_LEN) != 0) {
        _FAIL("TC3 open failed or plaintext wrong");
        failures++;
    }
    if (aes_gcm_decrypt(TC4_KEY, TC4_IV, TC4_AAD, TC4_AAD_LEN, TC4_CT,
                        TC4_PT_LEN, TC4_TAG, pt) != 1 ||
        memcmp(pt, TC4_PT, TC4_PT_LEN) != 0) {
        _FAIL("TC4 open failed or plaintext wrong");
        failures++;
    }
    ASSERT_EQ("all NIST decrypt vectors pass", 0, failures);
}

// The independent (OpenSSL-backed) vectors: seal and open both directions.
static void test_gcm_independent_vectors(void) {
    TEST_SUITE("gcm independent vectors (cryptography library)");
    struct vec {
        const uint8_t *key, *iv, *aad, *pt, *ct, *tag;
        uint64_t pt_len, aad_len;
    };
    static const struct vec vecs[] = {
        {X1_KEY, X1_IV, X1_AAD, X1_PT, X1_CT, X1_TAG, X1_PT_LEN, X1_AAD_LEN},
        {X2_KEY, X2_IV, X2_AAD, X2_PT, X2_CT, X2_TAG, X2_PT_LEN, X2_AAD_LEN},
        {X3_KEY, X3_IV, X3_AAD, X3_PT, X3_CT, X3_TAG, X3_PT_LEN, X3_AAD_LEN},
        {X4_KEY, X4_IV, X4_AAD, X4_PT, X4_CT, X4_TAG, X4_PT_LEN, X4_AAD_LEN},
    };
    uint8_t ct[128], tag[16], pt[128];
    int failures = 0;
    for (size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        const struct vec *v = &vecs[i];
        aes_gcm_encrypt(v->key, v->iv, v->aad, v->aad_len, v->pt, v->pt_len,
                        ct, tag);
        if (memcmp(ct, v->ct, v->pt_len) != 0 || memcmp(tag, v->tag, 16) != 0) {
            _FAIL("vector %zu seal mismatch", i + 1);
            failures++;
        }
        if (aes_gcm_decrypt(v->key, v->iv, v->aad, v->aad_len, v->ct,
                            v->pt_len, v->tag, pt) != 1 ||
            memcmp(pt, v->pt, v->pt_len) != 0) {
            _FAIL("vector %zu open failed", i + 1);
            failures++;
        }
    }
    ASSERT_EQ("all 4 independent vectors pass", 0, failures);
}

// The C reference implementation must pass the same NIST vectors —
// otherwise the cross-checks below would compare two equally-broken
// implementations.
static void test_gcm_reference_matches(void) {
    TEST_SUITE("plain-C reference vs NIST vectors (guard)");
    uint8_t ct[128], tag[16], pt[128];
    int failures = 0;

    ref_gcm_encrypt(TC2_KEY, TC2_IV, TC2_AAD, TC2_AAD_LEN, TC2_PT,
                    TC2_PT_LEN, ct, tag);
    if (memcmp(ct, TC2_CT, TC2_PT_LEN) != 0 || memcmp(tag, TC2_TAG, 16) != 0)
        failures++;
    ref_gcm_encrypt(TC4_KEY, TC4_IV, TC4_AAD, TC4_AAD_LEN, TC4_PT,
                    TC4_PT_LEN, ct, tag);
    if (memcmp(ct, TC4_CT, TC4_PT_LEN) != 0 || memcmp(tag, TC4_TAG, 16) != 0)
        failures++;
    if (ref_gcm_decrypt(TC3_KEY, TC3_IV, TC3_AAD, TC3_AAD_LEN, TC3_CT,
                        TC3_PT_LEN, TC3_TAG, pt) != 1 ||
        memcmp(pt, TC3_PT, TC3_PT_LEN) != 0)
        failures++;
    if (ref_gcm_decrypt(TC4_KEY, TC4_IV, TC4_AAD, TC4_AAD_LEN, TC4_CT,
                        TC4_PT_LEN, TC4_TAG, pt) != 1 ||
        memcmp(pt, TC4_PT, TC4_PT_LEN) != 0)
        failures++;
    ASSERT_EQ("reference passes the NIST vectors", 0, failures);
}

// Acceptance: valid ciphertext succeeds; modified ciphertext,
// modified AAD and modified tag all fail — and the plaintext buffer stays
// untouched on failure (the tag is verified before decryption).
static void test_gcm_auth_failures(void) {
    TEST_SUITE("gcm authentication (7.4)");
    uint8_t ct[64], tag[16], pt[64], aad[64];
    int ok = 1, fails = 0;

    memcpy(aad, TC4_AAD, TC4_AAD_LEN);
    aes_gcm_encrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, TC4_PT,
                    TC4_PT_LEN, ct, tag);
    ok &= aes_gcm_decrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, ct,
                          TC4_PT_LEN, tag, pt) == 1;
    ok &= memcmp(pt, TC4_PT, TC4_PT_LEN) == 0;
    ASSERT_TRUE("valid ciphertext/AAD/tag succeeds", ok);

    // modified ciphertext
    ct[7] ^= 0x01;
    memset(pt, 0xaa, TC4_PT_LEN);
    fails += aes_gcm_decrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, ct,
                             TC4_PT_LEN, tag, pt) != 0;
    for (int i = 0; i < (int)TC4_PT_LEN; i++)
        fails += pt[i] != 0xaa;          // plaintext untouched on failure
    ct[7] ^= 0x01;
    ASSERT_EQ("modified ciphertext rejected, pt untouched", 0, fails);

    // modified AAD
    aad[3] ^= 0x40;
    fails = aes_gcm_decrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, ct,
                            TC4_PT_LEN, tag, pt) != 0;
    aad[3] ^= 0x40;
    ASSERT_EQ("modified AAD rejected", 0, fails);

    // modified tag
    tag[15] ^= 0x01;
    fails = aes_gcm_decrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, ct,
                            TC4_PT_LEN, tag, pt) != 0;
    tag[15] ^= 0x01;
    ASSERT_EQ("modified tag rejected", 0, fails);

    // the C reference must reject these too (it shares the acceptance)
    ct[0] ^= 0x80;
    fails = ref_gcm_decrypt(TC4_KEY, TC4_IV, aad, TC4_AAD_LEN, ct,
                            TC4_PT_LEN, tag, pt) != 0;
    ct[0] ^= 0x80;
    ASSERT_EQ("reference rejects modified ciphertext too", 0, fails);
}

// The four-way CTR sweep — src/crypto/gcm/decrypt.S generates the keystream
// four blocks at a time, so correctness depends on two things the NIST
// vectors barely exercise: how many leftover full blocks (0-3) follow the
// last complete group of four, and how many bytes are in the partial
// trailing block. Every ct_len in 0..300 covers that whole grid several
// times over. Vectors come from ref_gcm_encrypt rather than a generated
// table: test_gcm_reference_matches above already pins the reference to
// NIST, so nothing here is a hand-transcribed expected value.
static void test_gcm_decrypt_ctr_sweep(void) {
    TEST_SUITE("aes_gcm_decrypt CTR length sweep (0-300 bytes)");
    uint8_t key[16], iv[12], aad[37], pt[301], ct[301], tag[16], out[301];
    int failures = 0, bad_len = -1;

    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(0x5a ^ (i * 31));
    for (int i = 0; i < 12; i++) iv[i]  = (uint8_t)(0xc3 + i * 7);
    for (int i = 0; i < 37; i++) aad[i] = (uint8_t)(i * 13 + 1);
    for (int i = 0; i < 301; i++) pt[i] = (uint8_t)(i * 197 + 5);

    for (uint64_t len = 0; len <= 300 && failures == 0; len++) {
        // AAD length is varied alongside so the GHASH split moves too.
        uint64_t aad_len = len % 38;
        ref_gcm_encrypt(key, iv, aad, aad_len, pt, len, ct, tag);
        memset(out, 0xa5, sizeof(out));
        if (aes_gcm_decrypt(key, iv, aad, aad_len, ct, len, tag, out) != 1 ||
            memcmp(out, pt, len) != 0) {
            bad_len = (int)len;
            failures++;
        }
    }
    if (failures)
        _FAIL("length %d: open failed or plaintext wrong", bad_len);
    ASSERT_EQ("every length 0-300 opens to the reference plaintext", 0,
              failures);
}

// The 4-way path loads 64 bytes of ciphertext and stores 64 bytes of
// plaintext per iteration, so in-place operation (pt == ct) has to load
// each group before it overwrites it. Lengths chosen to land on a group
// boundary, a leftover block and a partial tail.
static void test_gcm_decrypt_in_place(void) {
    TEST_SUITE("aes_gcm_decrypt in-place (pt aliases ct)");
    uint8_t key[16], iv[12], aad[16], pt[200], buf[200], tag[16];
    static const uint64_t LENS[] = {64, 80, 128, 137, 192, 200};
    int failures = 0;

    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 17 + 3);
    for (int i = 0; i < 12; i++) iv[i]  = (uint8_t)(i * 5 + 9);
    for (int i = 0; i < 16; i++) aad[i] = (uint8_t)(i * 3);
    for (int i = 0; i < 200; i++) pt[i] = (uint8_t)(i * 71 + 11);

    for (size_t i = 0; i < sizeof(LENS) / sizeof(LENS[0]); i++) {
        uint64_t len = LENS[i];
        ref_gcm_encrypt(key, iv, aad, 16, pt, len, buf, tag);
        if (aes_gcm_decrypt(key, iv, aad, 16, buf, len, tag, buf) != 1 ||
            memcmp(buf, pt, len) != 0) {
            _FAIL("in-place open wrong at length %llu",
                  (unsigned long long)len);
            failures++;
        }
    }
    ASSERT_EQ("in-place open matches the reference plaintext", 0, failures);
}

int main(void) {
    test_gcm_decrypt_kat();
    test_gcm_independent_vectors();
    test_gcm_reference_matches();
    test_gcm_auth_failures();
    test_gcm_decrypt_ctr_sweep();
    test_gcm_decrypt_in_place();
    test_summary();
    return 0;
}
