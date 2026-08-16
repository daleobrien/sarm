// Unit tests for tls_record_encrypt
#include "common.h"

// ── tests: encryption against RFC 8448 (§11.3) ──────────────────────

static void test_encrypt_rfc8448(void) {
    TEST_SUITE("record encrypt — RFC 8448 vectors");
    uint8_t out[OUT_BUF_MAX + 64];
    uint8_t payload[50];
    uint64_t carry = 0;
    fill_ascending(payload, sizeof(payload));

    // client application_data, seq 0
    uint64_t n = rec_encrypt(TLS_RECORD_APPLICATION_DATA, payload,
                             sizeof(payload), RFC_CAP_KEY, RFC_CAP_IV, 0,
                             out, &carry);
    ASSERT_EQ("client app carry clear", 0, carry);
    ASSERT_EQ("client app record len", 72, n);
    ASSERT_EQ("client app matches RFC 8448", 0,
              memcmp(RFC_CLIENT_APP, out, 72));

    // server application_data, seq 1
    n = rec_encrypt(TLS_RECORD_APPLICATION_DATA, payload, sizeof(payload),
                    RFC_SAP_KEY, RFC_SAP_IV, 1, out, &carry);
    ASSERT_EQ("server app carry clear", 0, carry);
    ASSERT_EQ("server app record len", 72, n);
    ASSERT_EQ("server app matches RFC 8448", 0,
              memcmp(RFC_SERVER_APP, out, 72));

    // the two records must differ (the nonce changed with the seq)
    ASSERT_EQ("seq 0 vs seq 1 differ", 1,
              memcmp(RFC_CLIENT_APP, RFC_SERVER_APP, 72) != 0 ? 1 : 0);
}

int main(void) {
    test_encrypt_rfc8448();
    test_summary();
    return 0;
}
