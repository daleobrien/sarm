// Unit tests for tls_record_write (PLAN.MD Phase 11 §11.2)
#include "common.h"

// ── tests: plaintext record generation (§11.2) ──────────────────────

static void test_write(void) {
    TEST_SUITE("record write — plaintext generation");
    uint8_t out[OUT_BUF_MAX + 64];
    uint64_t carry = 0;

    // the RFC 8448 ServerHello reproduced byte-for-byte
    uint64_t n = rec_write(TLS_RECORD_HANDSHAKE,
                           RFC_SERVER_HELLO + TLS_RECORD_HEADER_LEN, 90,
                           out, &carry);
    ASSERT_EQ("ServerHello carry clear", 0, carry);
    ASSERT_EQ("ServerHello record len", 95, n);
    ASSERT_EQ("ServerHello bytes match RFC 8448", 0,
              memcmp(RFC_SERVER_HELLO, out, 95));

    // change_cipher_spec compatibility record
    static const uint8_t ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    n = rec_write(TLS_RECORD_CHANGE_CIPHER_SPEC,
                  (const uint8_t *)"\x01", 1, out, &carry);
    ASSERT_EQ("CCS carry clear", 0, carry);
    ASSERT_EQ("CCS record len", 6, n);
    ASSERT_EQ("CCS bytes match", 0, memcmp(ccs, out, 6));

    // zero-length application_data fragment (§5.1 allows it)
    n = rec_write(TLS_RECORD_APPLICATION_DATA, NULL, 0, out, &carry);
    ASSERT_EQ("empty app carry clear", 0, carry);
    ASSERT_EQ("empty app record len", 5, n);
    static const uint8_t empty[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    ASSERT_EQ("empty app bytes match", 0, memcmp(empty, out, 5));

    // a zero-length handshake fragment must be rejected (§5.1)
    n = rec_write(TLS_RECORD_HANDSHAKE, NULL, 0, out, &carry);
    ASSERT_EQ("empty handshake carry set", 1, carry);
    ASSERT_EQ("empty handshake err", TLS_RECORD_ERR_EMPTY, n);

    // invalid type
    n = rec_write(19, (const uint8_t *)"\x01", 1, out, &carry);
    ASSERT_EQ("type 19 carry set", 1, carry);
    ASSERT_EQ("type 19 err", TLS_RECORD_ERR_TYPE, n);

    // oversized fragment
    static uint8_t huge[TLS_MAX_PLAINTEXT + 1];
    n = rec_write(TLS_RECORD_APPLICATION_DATA, huge,
                  TLS_MAX_PLAINTEXT + 1, out, &carry);
    ASSERT_EQ("len 16385 carry set", 1, carry);
    ASSERT_EQ("len 16385 err", TLS_RECORD_ERR_LENGTH, n);

    // the maximum plaintext fragment is legal and header encodes 0x4000
    fill_ascending(huge, TLS_MAX_PLAINTEXT);
    n = rec_write(TLS_RECORD_APPLICATION_DATA, huge, TLS_MAX_PLAINTEXT,
                  out, &carry);
    ASSERT_EQ("max len carry clear", 0, carry);
    ASSERT_EQ("max len record", 5 + TLS_MAX_PLAINTEXT, n);
    ASSERT_EQ("header type", TLS_RECORD_APPLICATION_DATA, out[0]);
    ASSERT_EQ("header version", TLS_VERSION_1_2,
              (out[1] << 8) | out[2]);
    ASSERT_EQ("header len hi", 0x40, out[3]);
    ASSERT_EQ("header len lo", 0x00, out[4]);
    ASSERT_EQ("fragment copied", 0,
              memcmp(huge, out + TLS_RECORD_HEADER_LEN, TLS_MAX_PLAINTEXT));
}

int main(void) {
    test_write();
    test_summary();
    return 0;
}
