// Unit tests for tls_record_decrypt
#include "common.h"

// ── tests: decryption against RFC 8448 ──────────────────────────────

static void test_decrypt_rfc8448(void) {
    TEST_SUITE("record decrypt — RFC 8448 vectors");
    uint8_t out[OUT_BUF_MAX + 64];
    uint64_t type = 0, carry = 0;

    // the client's encrypted Finished (handshake read keys, seq 0)
    uint64_t n = rec_decrypt(RFC_CLIENT_FINISHED,
                             sizeof(RFC_CLIENT_FINISHED), RFC_CHS_KEY,
                             RFC_CHS_IV, 0, out, &type, &carry);
    ASSERT_EQ("Finished carry clear", 0, carry);
    ASSERT_EQ("Finished content len", 36, n);
    ASSERT_EQ("Finished inner type", TLS_RECORD_HANDSHAKE, type);
    ASSERT_EQ("Finished plaintext matches RFC 8448", 0,
              memcmp(RFC_CLIENT_FINISHED_PT, out, 36));
}

// ── tests: encrypt/decrypt roundtrips ───────────────────────────────

static void test_roundtrip(void) {
    TEST_SUITE("record encrypt/decrypt roundtrip");
    uint8_t out[OUT_BUF_MAX + 64];
    uint8_t pt[OUT_BUF_MAX + 64];
    uint8_t got[OUT_BUF_MAX + 64];
    uint64_t carry = 0, type = 0;
    // lengths straddling every interesting boundary: the AES block size,
    // the GCM length block, the plaintext limit, and a handful in between
    static const uint64_t lens[] = {0, 1, 2, 15, 16, 17, 31, 32, 47, 48,
                                    63, 64, 65, 127, 128, 255, 256, 1000,
                                    TLS_MAX_PLAINTEXT};
    static const uint64_t types[] = {TLS_RECORD_APPLICATION_DATA,
                                     TLS_RECORD_HANDSHAKE,
                                     TLS_RECORD_ALERT,
                                     TLS_RECORD_CHANGE_CIPHER_SPEC};

    for (unsigned ti = 0; ti < sizeof(types) / sizeof(types[0]); ti++) {
        for (unsigned li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
            uint64_t len = lens[li];
            // the record layer refuses empty handshake/alert content
            if (len == 0 && types[ti] != TLS_RECORD_APPLICATION_DATA)
                continue;
            fill_ascending(pt, len);
            uint64_t n = rec_encrypt(types[ti], pt, len, RFC_SAP_KEY,
                                     RFC_SAP_IV, 7, out, &carry);
            ASSERT_EQ("encrypt carry clear", 0, carry);
            ASSERT_EQ("encrypt record len", len + 22, n);
            ASSERT_EQ("outer type is application_data",
                      TLS_RECORD_APPLICATION_DATA, out[0]);
            ASSERT_EQ("outer version 0x0303", TLS_VERSION_1_2,
                      (out[1] << 8) | out[2]);
            ASSERT_EQ("outer length", len + 17, (out[3] << 8) | out[4]);

            uint64_t cn = rec_decrypt(out, n, RFC_SAP_KEY, RFC_SAP_IV, 7,
                                      got, &type, &carry);
            ASSERT_EQ("decrypt carry clear", 0, carry);
            ASSERT_EQ("decrypt content len", len, cn);
            ASSERT_EQ("decrypt inner type", types[ti], type);
            ASSERT_EQ("decrypt content matches", 0,
                      memcmp(pt, got, len));
        }
    }
}

// ── tests: decryption failure paths ─────────────────────────────────

static void test_decrypt_errors(void) {
    TEST_SUITE("record decrypt — failure paths");
    uint8_t rec[OUT_BUF_MAX + 64];
    uint8_t out[OUT_BUF_MAX + 64];
    uint8_t payload[50];
    uint64_t type = 0, carry = 0, n;
    fill_ascending(payload, sizeof(payload));

    n = rec_encrypt(TLS_RECORD_APPLICATION_DATA, payload, sizeof(payload),
                    RFC_CAP_KEY, RFC_CAP_IV, 0, rec, &carry);
    ASSERT_EQ("reference encrypt ok", 0, carry);

    // wrong key → MAC
    static const uint8_t other_key[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                          0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                          0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                          0x5a};
    ASSERT_EQ("wrong key → MAC", TLS_RECORD_ERR_MAC,
              rec_decrypt(rec, n, other_key, RFC_CAP_IV, 0, out, &type,
                          &carry));
    ASSERT_EQ("wrong key carry set", 1, carry);

    // wrong sequence number → MAC
    ASSERT_EQ("wrong seq → MAC", TLS_RECORD_ERR_MAC,
              rec_decrypt(rec, n, RFC_CAP_KEY, RFC_CAP_IV, 1, out, &type,
                          &carry));

    // tampered ciphertext byte → MAC
    uint8_t tampered[OUT_BUF_MAX + 64];
    memcpy(tampered, rec, n);
    tampered[6] ^= 0x01;
    ASSERT_EQ("tampered ct → MAC", TLS_RECORD_ERR_MAC,
              rec_decrypt(tampered, n, RFC_CAP_KEY, RFC_CAP_IV, 0, out,
                          &type, &carry));

    // tampered header (the AAD) → MAC
    memcpy(tampered, rec, n);
    tampered[0] ^= 0x01;
    ASSERT_EQ("tampered header → MAC", TLS_RECORD_ERR_MAC,
              rec_decrypt(tampered, n, RFC_CAP_KEY, RFC_CAP_IV, 0, out,
                          &type, &carry));

    // truncated header → SHORT
    ASSERT_EQ("len 4 → SHORT", TLS_RECORD_ERR_SHORT,
              rec_decrypt(rec, 4, RFC_CAP_KEY, RFC_CAP_IV, 0, out, &type,
                          &carry));

    // fragment shorter than tag + inner type → LENGTH
    uint8_t tiny[TLS_RECORD_HEADER_LEN + 16];
    memcpy(tiny, rec, sizeof(tiny));
    tiny[3] = 0x00;
    tiny[4] = 0x10;  // 16 < 17
    ASSERT_EQ("len 16 → LENGTH", TLS_RECORD_ERR_LENGTH,
              rec_decrypt(tiny, sizeof(tiny), RFC_CAP_KEY, RFC_CAP_IV, 0,
                          out, &type, &carry));

    // fragment longer than the AES-128-GCM bound → LENGTH
    memcpy(tiny, rec, sizeof(tiny));
    tiny[3] = 0x40;
    tiny[4] = 0x12;  // 16402 > TLS_MAX_AEAD
    ASSERT_EQ("len 16402 → LENGTH", TLS_RECORD_ERR_LENGTH,
              rec_decrypt(tiny, sizeof(tiny), RFC_CAP_KEY, RFC_CAP_IV, 0,
                          out, &type, &carry));

    // header length runs past the buffer → BOUNDS
    memcpy(tiny, rec, sizeof(tiny));
    tiny[3] = 0x00;
    tiny[4] = 0x50;  // 80 fragment bytes claimed, only 16 present
    ASSERT_EQ("fragment past end → BOUNDS", TLS_RECORD_ERR_BOUNDS,
              rec_decrypt(tiny, sizeof(tiny), RFC_CAP_KEY, RFC_CAP_IV, 0,
                          out, &type, &carry));

    // a failed open must leave the output untouched (§7.4)
    memset(out, 0xcc, sizeof(out));
    ASSERT_EQ("bad key again → MAC", TLS_RECORD_ERR_MAC,
              rec_decrypt(rec, n, other_key, RFC_CAP_IV, 0, out, &type,
                          &carry));
    ASSERT_EQ("output untouched on failure", 0xcc, out[0]);
}

// ── tests: inner plaintext validation & padding (§5.4) ──────────────

static void test_inner_plaintext(void) {
    TEST_SUITE("record decrypt — inner type & padding");
    uint8_t rec[OUT_BUF_MAX + 64];
    uint8_t out[OUT_BUF_MAX + 64];
    uint64_t type = 0, carry = 0, n;

    // an all-zero inner plaintext is malformed (RFC 8446 App. C.3): the
    // type scan finds no non-zero octet → INNER
    static const uint8_t zeros[16] = {0};
    n = build_raw_record(RFC_CAP_KEY, RFC_CAP_IV, 0, zeros, sizeof(zeros),
                         rec);
    ASSERT_EQ("all-zero plaintext → INNER", TLS_RECORD_ERR_INNER,
              rec_decrypt(rec, n, RFC_CAP_KEY, RFC_CAP_IV, 0, out, &type,
                          &carry));
    ASSERT_EQ("all-zero carry set", 1, carry);

    // an inner content type outside 20..23 → INNER
    static const uint8_t bad_type[1] = {0x05};
    n = build_raw_record(RFC_CAP_KEY, RFC_CAP_IV, 0, bad_type,
                         sizeof(bad_type), rec);
    ASSERT_EQ("inner type 5 → INNER", TLS_RECORD_ERR_INNER,
              rec_decrypt(rec, n, RFC_CAP_KEY, RFC_CAP_IV, 0, out, &type,
                          &carry));

    // padding: content || type || zeros — the trailing zeros are
    // stripped and the content/type reported (§5.4)
    static const uint8_t padded[] = {
        0x41, 0x42, 0x43,                     // content "ABC"
        TLS_RECORD_APPLICATION_DATA,          // inner type
        0x00, 0x00, 0x00, 0x00, 0x00,         // padding
    };
    n = build_raw_record(RFC_CAP_KEY, RFC_CAP_IV, 0, padded,
                         sizeof(padded), rec);
    uint64_t cn = rec_decrypt(rec, n, RFC_CAP_KEY, RFC_CAP_IV, 0, out,
                              &type, &carry);
    ASSERT_EQ("padded carry clear", 0, carry);
    ASSERT_EQ("padded content len", 3, cn);
    ASSERT_EQ("padded inner type", TLS_RECORD_APPLICATION_DATA, type);
    ASSERT_EQ("padded content", 0,
              memcmp(padded, out, 3));

    // padding-only plaintext would be all zeros → INNER (covered above);
    // a padded handshake content roundtrips through the real encrypt
    // only without padding, so the crafted record above is the padding
    // path — the type byte is always the last non-zero octet.
}

int main(void) {
    test_decrypt_rfc8448();
    test_roundtrip();
    test_decrypt_errors();
    test_inner_plaintext();
    test_summary();
    return 0;
}
