// Unit tests for tls_record_parse
#include "common.h"

// ── tests: plaintext parsing (§11.1) ────────────────────────────────

static void test_parse_rfc8448_records(void) {
    TEST_SUITE("record parse — RFC 8448 vectors");
    rec_parse_result r;

    // ClientHello: handshake type inside a 0x0301 record (§5.1)
    ASSERT_EQ("ClientHello parses", 0,
              rec_parse(RFC_CLIENT_HELLO, sizeof(RFC_CLIENT_HELLO), &r));
    ASSERT_EQ("ClientHello type", TLS_RECORD_HANDSHAKE, r.type);
    ASSERT_EQ("ClientHello frag_len", 196, r.frag_len);
    ASSERT_EQ("ClientHello total", 201, r.total);
    ASSERT_EQ("ClientHello frag == buf+5", 0,
              (int64_t)(r.frag - (RFC_CLIENT_HELLO + TLS_RECORD_HEADER_LEN)));
    // dereference only on a successful parse (frag_len > 0 proves it)
    if (r.frag_len > 0)
        ASSERT_EQ("ClientHello frag byte 0 == 0x01", 0x01, r.frag[0]);

    // ServerHello: the standard 0x0303 record
    ASSERT_EQ("ServerHello parses", 0,
              rec_parse(RFC_SERVER_HELLO, sizeof(RFC_SERVER_HELLO), &r));
    ASSERT_EQ("ServerHello type", TLS_RECORD_HANDSHAKE, r.type);
    ASSERT_EQ("ServerHello frag_len", 90, r.frag_len);
    ASSERT_EQ("ServerHello total", 95, r.total);
    ASSERT_EQ("ServerHello frag[0] == 0x02", 0x02, r.frag[0]);

    // change_cipher_spec compatibility record (§5, Appendix D.4)
    static const uint8_t ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    ASSERT_EQ("CCS parses", 0, rec_parse(ccs, sizeof(ccs), &r));
    ASSERT_EQ("CCS type", TLS_RECORD_CHANGE_CIPHER_SPEC, r.type);
    ASSERT_EQ("CCS frag_len", 1, r.frag_len);
    ASSERT_EQ("CCS total", 6, r.total);

    // plaintext alert: exactly one 2-byte alert message (§5.1)
    static const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
    ASSERT_EQ("alert parses", 0, rec_parse(alert, sizeof(alert), &r));
    ASSERT_EQ("alert type", TLS_RECORD_ALERT, r.type);
    ASSERT_EQ("alert frag_len", 2, r.frag_len);

    // zero-length application_data fragment is legal (§5.1)
    static const uint8_t empty[] = {0x17, 0x03, 0x03, 0x00, 0x00};
    ASSERT_EQ("empty app record parses", 0,
              rec_parse(empty, sizeof(empty), &r));
    ASSERT_EQ("empty app type", TLS_RECORD_APPLICATION_DATA, r.type);
    ASSERT_EQ("empty app frag_len", 0, r.frag_len);
    ASSERT_EQ("empty app total", 5, r.total);

    // coalesced records: the parser reports the first record's total so
    // the caller can advance past it
    uint8_t two[sizeof(RFC_SERVER_HELLO) + 5];
    memcpy(two, RFC_SERVER_HELLO, sizeof(RFC_SERVER_HELLO));
    memcpy(two + sizeof(RFC_SERVER_HELLO), empty, 5);
    ASSERT_EQ("coalesced parses first", 0,
              rec_parse(two, sizeof(two), &r));
    ASSERT_EQ("coalesced total == 95", 95, r.total);
}

static void test_parse_errors(void) {
    TEST_SUITE("record parse — strict bounds & validation");
    rec_parse_result r;
    uint8_t buf[sizeof(RFC_SERVER_HELLO)];

    // fewer than 5 bytes available → SHORT
    for (uint64_t n = 0; n < TLS_RECORD_HEADER_LEN; n++) {
        ASSERT_EQ("len < 5 → SHORT", TLS_RECORD_ERR_SHORT,
                  rec_parse(RFC_SERVER_HELLO, n, &r));
    }

    // content type outside 20..23 → TYPE
    memcpy(buf, RFC_SERVER_HELLO, 6);
    buf[0] = 0x00;
    ASSERT_EQ("type 0 → TYPE", TLS_RECORD_ERR_TYPE,
              rec_parse(buf, 6, &r));
    buf[0] = 0x13;  // 19
    ASSERT_EQ("type 19 → TYPE", TLS_RECORD_ERR_TYPE,
              rec_parse(buf, 6, &r));
    buf[0] = 0x18;  // 24
    ASSERT_EQ("type 24 → TYPE", TLS_RECORD_ERR_TYPE,
              rec_parse(buf, 6, &r));
    buf[0] = 0xff;
    ASSERT_EQ("type 255 → TYPE", TLS_RECORD_ERR_TYPE,
              rec_parse(buf, 6, &r));

    // legacy_record_version must be 0x0303 or 0x0301 → VERSION
    memcpy(buf, RFC_SERVER_HELLO, 6);
    buf[1] = 0x03;
    buf[2] = 0x04;  // TLS 1.3 in the record layer is a compat error
    ASSERT_EQ("version 0x0304 → VERSION", TLS_RECORD_ERR_VERSION,
              rec_parse(buf, 6, &r));
    buf[1] = 0x03;
    buf[2] = 0x00;  // SSL 3.0
    ASSERT_EQ("version 0x0300 → VERSION", TLS_RECORD_ERR_VERSION,
              rec_parse(buf, 6, &r));
    buf[1] = 0x00;
    buf[2] = 0x00;
    ASSERT_EQ("version 0x0000 → VERSION", TLS_RECORD_ERR_VERSION,
              rec_parse(buf, 6, &r));

    // plaintext record with len > 2^14 → LENGTH
    buf[0] = TLS_RECORD_HANDSHAKE;
    buf[1] = 0x03;
    buf[2] = 0x03;
    buf[3] = 0x40;
    buf[4] = 0x01;  // 16385
    ASSERT_EQ("handshake len 16385 → LENGTH", TLS_RECORD_ERR_LENGTH,
              rec_parse(buf, 6, &r));

    // application_data record beyond the 2^14+256 wire limit → LENGTH
    buf[0] = TLS_RECORD_APPLICATION_DATA;
    buf[3] = 0x41;
    buf[4] = 0x01;  // 16641
    ASSERT_EQ("ciphertext len 16641 → LENGTH", TLS_RECORD_ERR_LENGTH,
              rec_parse(buf, 6, &r));

    // length that runs past the supplied buffer → BOUNDS
    memcpy(buf, RFC_SERVER_HELLO, sizeof(RFC_SERVER_HELLO));
    ASSERT_EQ("full ServerHello in buf", 0,
              rec_parse(buf, sizeof(RFC_SERVER_HELLO), &r));
    // same record, but only 100 of its 95 bytes... a short read: header
    // claims 90 fragment bytes but only 94 bytes are available
    ASSERT_EQ("truncated fragment → BOUNDS", TLS_RECORD_ERR_BOUNDS,
              rec_parse(buf, TLS_RECORD_HEADER_LEN + 89, &r));
    ASSERT_EQ("exactly header+frag → ok", 0,
              rec_parse(buf, TLS_RECORD_HEADER_LEN + 90, &r));

    // boundary cases: plaintext len 16384 ok, ciphertext len 16640 ok
    uint8_t big[TLS_RECORD_HEADER_LEN + TLS_MAX_CIPHERTEXT];
    big[0] = TLS_RECORD_APPLICATION_DATA;
    big[1] = 0x03;
    big[2] = 0x03;
    big[3] = 0x41;
    big[4] = 0x00;  // 16640
    ASSERT_EQ("ciphertext len 16640 ok", 0,
              rec_parse(big, sizeof(big), &r));
    ASSERT_EQ("len 16640 frag_len", 16640, r.frag_len);
    big[0] = TLS_RECORD_HANDSHAKE;
    big[3] = 0x40;
    big[4] = 0x00;  // 16384
    ASSERT_EQ("plaintext len 16384 ok", 0,
              rec_parse(big, TLS_RECORD_HEADER_LEN + 16384, &r));
    ASSERT_EQ("len 16384 frag_len", 16384, r.frag_len);
}

int main(void) {
    test_parse_rfc8448_records();
    test_parse_errors();
    test_summary();
    return 0;
}
