// Unit tests for tls_record_next_*_seq (PLAN.MD Phase 11 §11.4)
#include "common.h"

// ── tests: sequence numbers (§11.4) ─────────────────────────────────

static void test_sequence_numbers(void) {
    TEST_SUITE("record sequence numbers");
    uint8_t out[OUT_BUF_MAX + 64];
    uint8_t payload[16];
    uint64_t carry = 0;
    fill_ascending(payload, sizeof(payload));

    // the counters start at zero in src/tls/data.S; reset for repeat
    tls_client_seq = 0;
    tls_server_seq = 0;

    ASSERT_EQ("client seq 0", 0, tls_record_next_client_seq());
    ASSERT_EQ("client seq 1", 1, tls_record_next_client_seq());
    ASSERT_EQ("client seq 2", 2, tls_record_next_client_seq());
    ASSERT_EQ("client counter == 3", 3, tls_client_seq);

    // the two directions are independent
    ASSERT_EQ("server seq 0 (independent)", 0,
              tls_record_next_server_seq());
    ASSERT_EQ("server counter == 1", 1, tls_server_seq);
    ASSERT_EQ("client counter untouched", 3, tls_client_seq);

    // one take per encrypted record: two records under consecutive
    // sequence numbers produce different ciphertexts
    uint64_t s0 = tls_record_next_server_seq();
    uint64_t n0 = rec_encrypt(TLS_RECORD_APPLICATION_DATA, payload,
                              sizeof(payload), RFC_SAP_KEY, RFC_SAP_IV,
                              s0, out, &carry);
    ASSERT_EQ("first encrypt ok", 0, carry);
    uint8_t rec0[OUT_BUF_MAX + 64];
    memcpy(rec0, out, n0);
    uint64_t s1 = tls_record_next_server_seq();
    uint64_t n1 = rec_encrypt(TLS_RECORD_APPLICATION_DATA, payload,
                              sizeof(payload), RFC_SAP_KEY, RFC_SAP_IV,
                              s1, out, &carry);
    ASSERT_EQ("second encrypt ok", 0, carry);
    ASSERT_EQ("s0 == 1, s1 == 2", 1, (s1 - s0));
    ASSERT_EQ("counter advanced once per record", 3, tls_server_seq);
    ASSERT_EQ("distinct nonces → distinct records", 0,
              memcmp(rec0, out, n0) == 0 ? 1 : 0);
}

int main(void) {
    test_sequence_numbers();
    test_summary();
    return 0;
}
