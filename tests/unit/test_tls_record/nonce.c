// Unit tests for tls_record_nonce (PLAN.MD Phase 11 §5.3)
#include "common.h"

// ── tests: nonce construction (§5.3) ────────────────────────────────

static void test_nonce(void) {
    TEST_SUITE("record nonce — iv XOR (0^4 || seq)");
    uint8_t nonce[12];

    // seq 0 → the nonce is the IV itself
    tls_record_nonce(RFC_CAP_IV, 0, nonce);
    ASSERT_EQ("seq 0 nonce == iv", 0, memcmp(RFC_CAP_IV, nonce, 12));

    // seq 1 flips only the last byte
    tls_record_nonce(RFC_SAP_IV, 1, nonce);
    static const uint8_t expect1[12] = {
        0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9,
        0x85,
    };
    ASSERT_EQ("server iv seq 1", 0, memcmp(expect1, nonce, 12));

    // zero IV: the nonce is the padded big-endian sequence number
    static const uint8_t zero_iv[12] = {0};
    tls_record_nonce(zero_iv, 1, nonce);
    static const uint8_t expect2[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    };
    ASSERT_EQ("zero iv seq 1", 0, memcmp(expect2, nonce, 12));

    // multi-byte sequence: big-endian encoding of 0x0102
    tls_record_nonce(zero_iv, 0x0102, nonce);
    static const uint8_t expect3[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02,
    };
    ASSERT_EQ("zero iv seq 0x0102", 0, memcmp(expect3, nonce, 12));

    // all-ones sequence
    tls_record_nonce(zero_iv, 0xFFFFFFFFFFFFFFFFull, nonce);
    static const uint8_t expect4[12] = {
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
    };
    ASSERT_EQ("zero iv seq all-ones", 0, memcmp(expect4, nonce, 12));

    // the first four IV bytes pass through untouched
    tls_record_nonce(RFC_CHS_IV, 0xDEADBEEFCAFEBABEull, nonce);
    ASSERT_EQ("iv[0..3] passthrough", 0, memcmp(RFC_CHS_IV, nonce, 4));
    ASSERT_EQ("iv[4..11] XOR seq", RFC_CHS_IV[11] ^ 0xBE, nonce[11]);
}

int main(void) {
    test_nonce();
    test_summary();
    return 0;
}
