// Unit tests for AES-GCM roundtrip and corner cases
//
// Tests for full encrypt/decrypt roundtrips, alignment handling,
// in-place operations, and large messages

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

// ── NIST SP 800-38D test case 4 (used for alignment/inplace tests) ───────

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

// ── Deterministic LCG (Numerical Recipes) ─────────────────────────────────
static uint32_t rng_state = 0x9e3779b9u;
static uint32_t rng_next(void) {
    rng_state = rng_state * 1664525u + 1013904223u;
    return rng_state;
}

// ── tests ───────────────────────────────────────────────────────────────

// asm seal → asm open round-trip over a sweep of (aad_len, pt_len)
// combinations, cross-checked against the C reference.
static void test_gcm_roundtrip(void) {
    TEST_SUITE("gcm round-trip vs reference (length sweep)");
    static const uint64_t alens[] = {0, 1, 15, 16, 17, 31, 32, 33, 64};
    static const uint64_t plens[] = {0, 1, 15, 16, 17, 31, 32, 33, 64, 65, 129};
    uint8_t key[16], iv[12], aad[128], pt[256], ct[256], ref_ct[256],
            ref_tag[16], tag[16], out[256];
    for (int i = 0; i < 16; i++)
        key[i] = (uint8_t)rng_next();
    for (int i = 0; i < 12; i++)
        iv[i] = (uint8_t)rng_next();
    for (int i = 0; i < 128; i++)
        aad[i] = (uint8_t)(i * 13 + 1);
    for (int i = 0; i < 256; i++)
        pt[i] = (uint8_t)(i * 29 + 7);

    int failures = 0;
    int count = 0;
    for (size_t ai = 0; ai < sizeof(alens) / sizeof(alens[0]); ai++) {
        for (size_t pi = 0; pi < sizeof(plens) / sizeof(plens[0]); pi++) {
            uint64_t al = alens[ai], pl = plens[pi];
            aes_gcm_encrypt(key, iv, aad, al, pt, pl, ct, tag);
            ref_gcm_encrypt(key, iv, aad, al, pt, pl, ref_ct, ref_tag);
            if (memcmp(ct, ref_ct, pl) != 0 || memcmp(tag, ref_tag, 16) != 0) {
                if (failures < 3)
                    _FAIL("aad=%llu pt=%llu — seal mismatch vs reference",
                          (unsigned long long)al, (unsigned long long)pl);
                failures++;
            }
            if (aes_gcm_decrypt(key, iv, aad, al, ct, pl, tag, out) != 1 ||
                memcmp(out, pt, pl) != 0) {
                if (failures < 3)
                    _FAIL("aad=%llu pt=%llu — open failed",
                          (unsigned long long)al, (unsigned long long)pl);
                failures++;
            }
            count++;
        }
    }
    ASSERT_EQ("all 99 length combos round-trip and match", 0, failures);
    ASSERT_EQ("swept 99 combos", 99, count);
}

// The ld1/st1 and tbl paths are alignment-agnostic — verify every buffer
// at every 0..7 start offset for the TC4 vector (partial AAD + partial
// ciphertext).
static void test_gcm_alignment(void) {
    TEST_SUITE("gcm buffer alignment (offsets 0-7)");
    static uint8_t kb[16 + 8], ib[12 + 8], ab[20 + 8], pb[60 + 8];
    static uint8_t cb[60 + 8], tb[16 + 8], ob[60 + 8];
    int failures = 0;
    for (int o = 0; o <= 7; o++) {
        memcpy(kb + o, TC4_KEY, 16);
        memcpy(ib + o, TC4_IV, 12);
        memcpy(ab + o, TC4_AAD, TC4_AAD_LEN);
        memcpy(pb + o, TC4_PT, TC4_PT_LEN);
        aes_gcm_encrypt(kb + o, ib + o, ab + o, TC4_AAD_LEN, pb + o,
                        TC4_PT_LEN, cb + o, tb + o);
        if (memcmp(cb + o, TC4_CT, TC4_PT_LEN) != 0 ||
            memcmp(tb + o, TC4_TAG, 16) != 0) {
            if (failures < 3)
                _FAIL("offset %d — seal mismatch", o);
            failures++;
        }
        if (aes_gcm_decrypt(kb + o, ib + o, ab + o, TC4_AAD_LEN, cb + o,
                            TC4_PT_LEN, tb + o, ob + o) != 1 ||
            memcmp(ob + o, TC4_PT, TC4_PT_LEN) != 0) {
            if (failures < 3)
                _FAIL("offset %d — open mismatch", o);
            failures++;
        }
    }
    ASSERT_EQ("all 8 offset runs seal and open correctly", 0, failures);
}

// In-place operation: ct aliasing pt (stream cipher, safe) for both seal
// and open.
static void test_gcm_inplace(void) {
    TEST_SUITE("gcm in-place (ct == pt)");
    uint8_t buf[128], tag[16], out[128];
    memcpy(buf, TC4_PT, TC4_PT_LEN);
    aes_gcm_encrypt(TC4_KEY, TC4_IV, TC4_AAD, TC4_AAD_LEN, buf,
                    TC4_PT_LEN, buf, tag);
    if (memcmp(buf, TC4_CT, TC4_PT_LEN) != 0 ||
        memcmp(tag, TC4_TAG, 16) != 0) {
        _FAIL("in-place seal produced wrong ct/tag");
    } else {
        _PASS("in-place seal matches TC4");
    }
    memcpy(out, buf, TC4_PT_LEN);        // decrypt back in place
    if (aes_gcm_decrypt(TC4_KEY, TC4_IV, TC4_AAD, TC4_AAD_LEN, out,
                        TC4_PT_LEN, tag, out) != 1 ||
        memcmp(out, TC4_PT, TC4_PT_LEN) != 0) {
        _FAIL("in-place open failed");
    } else {
        _PASS("in-place open recovers the plaintext");
    }
}

// One large message (1024 bytes) to exercise the counter across many
// blocks, cross-checked against the reference.
static void test_gcm_large_message(void) {
    TEST_SUITE("gcm 1024-byte message");
    uint8_t key[16], iv[12], aad[33], pt[1024], ct[1024], ref_ct[1024];
    uint8_t tag[16], ref_tag[16], out[1024];
    for (int i = 0; i < 16; i++)
        key[i] = (uint8_t)rng_next();
    for (int i = 0; i < 12; i++)
        iv[i] = (uint8_t)rng_next();
    for (int i = 0; i < 33; i++)
        aad[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 1024; i++)
        pt[i] = (uint8_t)(i * 31 + 11);

    aes_gcm_encrypt(key, iv, aad, 33, pt, 1024, ct, tag);
    ref_gcm_encrypt(key, iv, aad, 33, pt, 1024, ref_ct, ref_tag);
    if (memcmp(ct, ref_ct, 1024) != 0 || memcmp(tag, ref_tag, 16) != 0) {
        _FAIL("1024-byte seal mismatch vs reference");
    } else {
        _PASS("1024-byte seal matches reference");
    }
    if (aes_gcm_decrypt(key, iv, aad, 33, ct, 1024, tag, out) != 1 ||
        memcmp(out, pt, 1024) != 0) {
        _FAIL("1024-byte open failed");
    } else {
        _PASS("1024-byte open recovers the plaintext");
    }
}

// 5000 random (aad_len, pt_len) trials biased toward the boundaries of
// .Lgcm_ghash_run's 4-block aggregated path (prompts/03-aes-gcm-throughput.md):
// 0-3 blocks (scalar-only), exactly 4/8/12 blocks (aggregation with no
// scalar remainder), N*4+{1,2,3} blocks (aggregation plus a scalar
// remainder), all with and without a trailing partial block. Every trial
// is checked against the independent bit-serial reference above.
static void test_gcm_roundtrip_fuzz(void) {
    TEST_SUITE("gcm round-trip vs reference (5000-trial random fuzz)");
    enum { MAXLEN = 4096 };
    uint8_t key[16], iv[12];
    static uint8_t aad[256], pt[MAXLEN], ct[MAXLEN], ref_ct[MAXLEN];
    static uint8_t out[MAXLEN];
    uint8_t tag[16], ref_tag[16];
    int failures = 0;

    for (int trial = 0; trial < 5000; trial++) {
        for (int i = 0; i < 16; i++)
            key[i] = (uint8_t)rng_next();
        for (int i = 0; i < 12; i++)
            iv[i] = (uint8_t)rng_next();

        uint64_t aad_len = rng_next() % 257;      // 0..256
        uint64_t blocks = rng_next() % 21;        // 0..20 full blocks
        uint64_t tail = (rng_next() % 2) ? (rng_next() % 16) : 0;
        uint64_t pt_len = blocks * 16 + tail;      // 0..335 bytes

        for (uint64_t i = 0; i < aad_len; i++)
            aad[i] = (uint8_t)rng_next();
        for (uint64_t i = 0; i < pt_len; i++)
            pt[i] = (uint8_t)rng_next();

        aes_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ct, tag);
        ref_gcm_encrypt(key, iv, aad, aad_len, pt, pt_len, ref_ct, ref_tag);
        if ((pt_len && memcmp(ct, ref_ct, pt_len) != 0) ||
            memcmp(tag, ref_tag, 16) != 0) {
            if (failures < 5)
                _FAIL("trial %d: aad=%llu pt=%llu — seal mismatch",
                      trial, (unsigned long long)aad_len,
                      (unsigned long long)pt_len);
            failures++;
            continue;
        }
        if (aes_gcm_decrypt(key, iv, aad, aad_len, ct, pt_len, tag, out) !=
                1 ||
            (pt_len && memcmp(out, pt, pt_len) != 0)) {
            if (failures < 5)
                _FAIL("trial %d: aad=%llu pt=%llu — open failed", trial,
                      (unsigned long long)aad_len,
                      (unsigned long long)pt_len);
            failures++;
        }
    }
    ASSERT_EQ("5000 random trials round-trip and match", 0, failures);
}

int main(void) {
    test_gcm_roundtrip();
    test_gcm_alignment();
    test_gcm_inplace();
    test_gcm_large_message();
    test_gcm_roundtrip_fuzz();
    test_summary();
    return 0;
}
