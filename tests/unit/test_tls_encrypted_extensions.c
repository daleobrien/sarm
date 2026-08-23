// Unit tests for src/tls/handshake/encrypted_extensions.S
//
// tls_encrypted_extensions_write(out) -> length is a pure wire-format
// writer, driven off tls_alpn_len/tls_alpn (already filled in by
// tls_parse_client_hello, see test_tls_client_hello.c). Tested here two
// ways:
//   - byte-for-byte, the same way test_tls_server_hello.c drives
//     tls_server_hello_write
//   - end-to-end through the record layer: sealed with the server
//     handshake write key/iv from the RFC 8448 §3 trace
//     (test_tls_key_schedule.c derives the same values from
//     tls_derive_handshake_secrets), then opened again with
//     tls_record_decrypt — the message must come back byte-identical
//     and still carry the "h2" ALPN echo, exactly what a real client
//     would see after this record hits the wire.

#include "test_harness.h"

extern uint64_t tls_encrypted_extensions_write(void *out)
    __asm__("tls_encrypted_extensions_write");
extern uint64_t tls_record_encrypt(uint64_t type, const void *pt,
                                   uint64_t pt_len, const void *key,
                                   const void *iv, uint64_t seq, void *out)
    __asm__("tls_record_encrypt");
extern uint64_t tls_record_decrypt(const void *rec, uint64_t rec_len,
                                   const void *key, const void *iv,
                                   uint64_t seq, void *out)
    __asm__("tls_record_decrypt");

extern uint64_t tls_alpn_len __asm__("tls_alpn_len");
extern uint8_t tls_alpn[16] __asm__("tls_alpn");

#define TLS_RECORD_HANDSHAKE 22
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_EXT_ALPN 16

// RFC 8448 §3 server_handshake_traffic_secret -> write key/iv (see
// test_tls_key_schedule.c / test_hkdf.c for the same constants).
static const uint8_t HS_KEY[16] = {
    0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc,
};
static const uint8_t HS_IV[12] = {
    0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30,
};

// tls_record_encrypt(type=x0, pt=x1, pt_len=x2, key=x3, iv=x4, seq=x5,
// out=x6) -> x0 = record length, carry set on failure.
static uint64_t rec_encrypt(uint64_t type, const uint8_t *pt, uint64_t pt_len,
                            const uint8_t *key, const uint8_t *iv,
                            uint64_t seq, uint8_t *out, uint64_t *carry) {
    uint64_t result, c;
    asm volatile(
        "cmp xzr, xzr\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "mov x3, %5\n"
        "mov x4, %6\n"
        "mov x5, %7\n"
        "mov x6, %8\n"
        "bl tls_record_encrypt\n"
        "cset %1, cs\n"
        "mov %0, x0\n"
        : "=r"(result), "=r"(c)
        : "r"(type), "r"(pt), "r"(pt_len), "r"(key), "r"(iv), "r"(seq),
          "r"(out)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24",
          "x30", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v16", "v17", "v18", "v19", "v20", "v21", "cc", "memory");
    *carry = c;
    return result;
}

// tls_record_decrypt(rec=x0, rec_len=x1, key=x2, iv=x3, seq=x4, out=x5)
// -> x0 = content length, x1 = inner content type, carry set on failure.
static uint64_t rec_decrypt(const uint8_t *rec, uint64_t rec_len,
                            const uint8_t *key, const uint8_t *iv,
                            uint64_t seq, uint8_t *out,
                            uint64_t *inner_type, uint64_t *carry) {
    uint64_t result, c, t;
    asm volatile(
        "cmp xzr, xzr\n"
        "mov x0, %3\n"
        "mov x1, %4\n"
        "mov x2, %5\n"
        "mov x3, %6\n"
        "mov x4, %7\n"
        "mov x5, %8\n"
        "bl tls_record_decrypt\n"
        "cset %1, cs\n"
        "mov %0, x0\n"
        "mov %2, x1\n"
        : "=r"(result), "=r"(c), "=r"(t)
        : "r"(rec), "r"(rec_len), "r"(key), "r"(iv), "r"(seq), "r"(out)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24",
          "x30", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v16", "v17", "v18", "v19", "v20", "v21", "cc", "memory");
    *carry = c;
    *inner_type = t;
    return result;
}

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t u24be(const uint8_t *p) {
    return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
}

static void set_alpn(const char *name, uint64_t len) {
    tls_alpn_len = len;
    for (uint64_t i = 0; i < len; i++)
        tls_alpn[i] = (uint8_t)name[i];
}

static void test_write_h2(void) {
    TEST_SUITE("tls_encrypted_extensions_write — ALPN \"h2\"");

    set_alpn("h2", 2);
    uint8_t out[64];
    uint64_t len = tls_encrypted_extensions_write(out);

    ASSERT_EQ("total length", 15, (int64_t)len);
    ASSERT_EQ("handshake type == encrypted_extensions",
              TLS_HS_ENCRYPTED_EXTENSIONS, out[0]);
    ASSERT_EQ("handshake length field", 11, (int64_t)u24be(out + 1));
    ASSERT_EQ("extensions block length", 9, u16be(out + 4));
    ASSERT_EQ("extension type == alpn", TLS_EXT_ALPN, u16be(out + 6));
    ASSERT_EQ("extension data length", 5, u16be(out + 8));
    ASSERT_EQ("protocol_name_list length", 3, u16be(out + 10));
    ASSERT_EQ("protocol name length", 2, out[12]);
    ASSERT_EQ("protocol name byte 0", 'h', out[13]);
    ASSERT_EQ("protocol name byte 1", '2', out[14]);
}

static void test_write_empty_alpn(void) {
    TEST_SUITE("tls_encrypted_extensions_write — degenerate empty ALPN");

    // Not a real negotiation outcome (the ClientHello parser always
    // records "h2" on success), but the writer is a pure function of
    // tls_state and should still produce a structurally valid message
    // for a zero-length name.
    set_alpn("", 0);
    uint8_t out[64];
    uint64_t len = tls_encrypted_extensions_write(out);

    ASSERT_EQ("total length", 13, (int64_t)len);
    ASSERT_EQ("handshake length field", 9, (int64_t)u24be(out + 1));
    ASSERT_EQ("extensions block length", 7, u16be(out + 4));
    ASSERT_EQ("extension data length", 3, u16be(out + 8));
    ASSERT_EQ("protocol_name_list length", 1, u16be(out + 10));
    ASSERT_EQ("protocol name length", 0, out[12]);
}

static void test_encrypt_decrypt_round_trip(void) {
    TEST_SUITE("EncryptedExtensions — seal/open round trip");

    set_alpn("h2", 2);
    uint8_t plaintext[64];
    uint64_t pt_len = tls_encrypted_extensions_write(plaintext);

    uint8_t record[128];
    uint64_t carry = 1;
    uint64_t rec_len = rec_encrypt(TLS_RECORD_HANDSHAKE, plaintext, pt_len,
                                   HS_KEY, HS_IV, 0, record, &carry);
    ASSERT_EQ("encrypt succeeds", 0, carry);
    ASSERT_EQ("record length", (int64_t)(5 + pt_len + 1 + 16), (int64_t)rec_len);
    ASSERT_EQ("outer type == application_data (opaque per RFC 8446 §5.2)",
              0x17, record[0]);

    uint8_t opened[64];
    uint64_t inner_type = 0;
    carry = 1;
    uint64_t content_len = rec_decrypt(record, rec_len, HS_KEY, HS_IV, 0,
                                       opened, &inner_type, &carry);
    ASSERT_EQ("decrypt succeeds", 0, carry);
    ASSERT_EQ("inner content type == handshake", TLS_RECORD_HANDSHAKE,
              (int64_t)inner_type);
    ASSERT_EQ("recovered content length", (int64_t)pt_len, (int64_t)content_len);
    ASSERT_EQ("recovered bytes match the original message", 0,
              memcmp(plaintext, opened, pt_len));

    // and the ALPN a client would parse back out of it is still "h2"
    ASSERT_EQ("recovered ALPN name length", 2, opened[12]);
    ASSERT_EQ("recovered ALPN byte 0", 'h', opened[13]);
    ASSERT_EQ("recovered ALPN byte 1", '2', opened[14]);
}

static void test_wrong_key_fails(void) {
    TEST_SUITE("EncryptedExtensions — tampered key is rejected");

    set_alpn("h2", 2);
    uint8_t plaintext[64];
    uint64_t pt_len = tls_encrypted_extensions_write(plaintext);

    uint8_t record[128];
    uint64_t carry = 1;
    rec_encrypt(TLS_RECORD_HANDSHAKE, plaintext, pt_len, HS_KEY, HS_IV, 0,
               record, &carry);
    ASSERT_EQ("encrypt succeeds", 0, carry);

    uint8_t bad_key[16];
    memcpy(bad_key, HS_KEY, 16);
    bad_key[0] ^= 0xff;

    uint8_t opened[64];
    uint64_t inner_type = 0;
    carry = 0;
    rec_decrypt(record, 5 + pt_len + 1 + 16, bad_key, HS_IV, 0, opened,
               &inner_type, &carry);
    ASSERT_EQ("decrypt with the wrong key fails", 1, (int64_t)carry);
}

int main(void) {
    test_write_h2();
    test_write_empty_alpn();
    test_encrypt_decrypt_round_trip();
    test_wrong_key_fails();
    test_summary();
    return 0;
}
