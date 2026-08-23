// Unit tests for tls_transcript_add (wire header synthesis and
// message ordering)
#include "common.h"

// ── tests ────────────────────────────────────────────────────────────

// Acceptance: known TLS transcript sequences produce the
// expected SHA-256 values. All vectors computed independently (python3
// hashlib) over the wire bytes (header || body).
static void test_transcript_known_vectors(void) {
    TEST_SUITE("known TLS transcript sequences");
    static uint8_t long_body[300];
    static const uint8_t ch_body[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t sh_body[36] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43,
    };
    static const uint8_t ee_body[2] = { 0x00, 0x00 };
    static const uint8_t cert_body[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    static const uint8_t cv_body[5] = { 0x00, 0x01, 0x02, 0x03, 0x04 };
    static const uint8_t fin_body[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    uint8_t got[32], body_only[32];

    // empty transcript
    tls_transcript_init();
    tls_transcript_hash(got);
    ASSERT_TRUE("empty transcript == SHA256(\"\")", digest_eq(KAT_EMPTY, got));

    // one ClientHello, body "abc" — and the hash must include the
    // 4-byte header, not just the body
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, (const uint8_t *)"abc", 3);
    tls_transcript_hash(got);
    ASSERT_TRUE("ClientHello(\"abc\") == KAT", digest_eq(KAT_CH_ABC, got));
    ref_digest((const uint8_t *)"abc", 3, body_only);
    ASSERT_FALSE("hash includes the 4-byte header (not body alone)",
                 digest_eq(body_only, got));

    // one ServerHello with an empty body (len == 0, NULL body)
    tls_transcript_init();
    tls_transcript_add(TLS_HS_SERVER_HELLO, NULL, 0);
    tls_transcript_hash(got);
    ASSERT_TRUE("ServerHello(empty) == KAT", digest_eq(KAT_SH_EMPTY, got));

    // a single 300-byte message — the uint24 length is 0x00012C
    for (int i = 0; i < 300; i++)
        long_body[i] = (uint8_t)i;
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, long_body, 300);
    tls_transcript_hash(got);
    ASSERT_TRUE("300-byte message (uint24 length) == KAT",
                digest_eq(KAT_LONG_300, got));

    // realistic ClientHello → Finished server transcript, one add per
    // message, in exchange order
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, ch_body, 32);
    tls_transcript_add(TLS_HS_SERVER_HELLO, sh_body, 36);
    tls_transcript_add(TLS_HS_ENCRYPTED_EXTENSIONS, ee_body, 2);
    tls_transcript_add(TLS_HS_CERTIFICATE, cert_body, 4);
    tls_transcript_add(TLS_HS_CERTIFICATE_VERIFY, cv_body, 5);
    tls_transcript_add(TLS_HS_FINISHED, fin_body, 32);
    tls_transcript_hash(got);
    ASSERT_TRUE("ClientHello..Finished sequence == KAT",
                digest_eq(KAT_HANDSHAKE, got));
}

// The transcript is order-sensitive: the same two messages in the
// opposite order must give a different hash (each still matching the
// reference of its own wire bytes).
static void test_transcript_ordering(void) {
    TEST_SUITE("message ordering matters");
    static const uint8_t bodyA[] = "abc";
    static const uint8_t bodyB[] = "xyz";
    uint8_t h_ab[32], h_ba[32];
    HsMsg ab[] = {
        { TLS_HS_CLIENT_HELLO, bodyA, 3 },
        { TLS_HS_SERVER_HELLO, bodyB, 3 },
    };
    HsMsg ba[] = {
        { TLS_HS_SERVER_HELLO, bodyB, 3 },
        { TLS_HS_CLIENT_HELLO, bodyA, 3 },
    };

    check_transcript("A then B matches reference", ab, 2);
    check_transcript("B then A matches reference", ba, 2);

    tls_transcript_init();
    tls_transcript_add(ab[0].type, ab[0].body, ab[0].len);
    tls_transcript_add(ab[1].type, ab[1].body, ab[1].len);
    tls_transcript_hash(h_ab);
    tls_transcript_init();
    tls_transcript_add(ba[0].type, ba[0].body, ba[0].len);
    tls_transcript_add(ba[1].type, ba[1].body, ba[1].len);
    tls_transcript_hash(h_ba);
    ASSERT_FALSE("SHA256(A||B) != SHA256(B||A)", digest_eq(h_ab, h_ba));
}

int main(void) {
    test_transcript_known_vectors();
    test_transcript_ordering();
    test_summary();
    return 0;
}
