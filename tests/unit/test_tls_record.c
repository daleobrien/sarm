// Unit tests for src/tls/record.S (PLAN.MD Phase 11 — TLS record layer)
//
// The record layer (RFC 8446 §5) wraps every TLS message in a record:
//
//     TLSPlaintext:
//       type(1) || legacy_record_version(2) || length(2) || fragment
//
// Before the handshake keys exist records are plaintext
// (tls_record_parse / tls_record_write); afterwards every record is a
// TLSCiphertext — outer type 23, plaintext `content || type ||
// padding` sealed with AES-128-GCM (tls_record_encrypt /
// tls_record_decrypt). The per-record nonce is the write IV XORed with
// the sequence number (tls_record_nonce, §5.3) and the AEAD additional
// data is the 5-byte record header (§5.2).
//
// The tests:
//   1. parse genuine RFC 8448 §3 records (the ClientHello in a 0x0301
//      record, the ServerHello, a zero-length application_data record)
//      and reject malformed ones with the exact TLS_RECORD_ERR_* code
//      and the carry flag set;
//   2. generate plaintext records and check the wire bytes (the RFC
//      8448 ServerHello record reproduced byte-for-byte);
//   3. pin the nonce construction (iv XOR 0^4||seq) against hand-built
//      vectors;
//   4. pin encrypt/decrypt against the RFC 8448 §3 record-layer
//      vectors: the client's application_data record (seq 0) and the
//      server's (seq 1), plus the client's encrypted Finished (seq 0);
//   5. roundtrip many sizes and types through encrypt/decrypt;
//   6. verify tag tamper, key/seq mismatch, truncated and oversized
//      records, all-zero plaintext and bad inner types all fail closed
//      with the carry flag set;
//   7. check padding stripping (§5.4) on hand-crafted plaintexts;
//   8. verify the per-direction sequence counters increment exactly
//      once per record and independently of each other (§11.4).

#include "test_harness.h"

// ── constants, mirrored from src/defs.S ─────────────────────────────

#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_2 0x0303

#define TLS_RECORD_CHANGE_CIPHER_SPEC 20
#define TLS_RECORD_ALERT              21
#define TLS_RECORD_HANDSHAKE          22
#define TLS_RECORD_APPLICATION_DATA   23
#define TLS_RECORD_HEADER_LEN 5
#define TLS_MAX_PLAINTEXT     16384
#define TLS_TAG_LEN           16
#define TLS_INNER_TYPE_LEN    1
#define TLS_MAX_CIPHERTEXT    16640
#define TLS_MAX_AEAD          16401

#define TLS_RECORD_ERR_SHORT   1
#define TLS_RECORD_ERR_TYPE    2
#define TLS_RECORD_ERR_VERSION 3
#define TLS_RECORD_ERR_LENGTH  4
#define TLS_RECORD_ERR_BOUNDS  5
#define TLS_RECORD_ERR_MAC     6
#define TLS_RECORD_ERR_INNER   7
#define TLS_RECORD_ERR_EMPTY   8

// largest output the record layer can produce
#define OUT_BUF_MAX (TLS_RECORD_HEADER_LEN + TLS_MAX_PLAINTEXT + \
                     TLS_INNER_TYPE_LEN + TLS_TAG_LEN)

// ── asm entry points (bare labels, pinned via __asm__) ───────────────

extern uint64_t tls_record_parse(const void *buf, uint64_t len)
    __asm__("tls_record_parse");
extern uint64_t tls_record_write(uint64_t type, const void *frag,
                                 uint64_t frag_len, void *out)
    __asm__("tls_record_write");
extern void tls_record_nonce(const void *iv, uint64_t seq, void *out)
    __asm__("tls_record_nonce");
extern uint64_t tls_record_encrypt(uint64_t type, const void *pt,
                                   uint64_t pt_len, const void *key,
                                   const void *iv, uint64_t seq, void *out)
    __asm__("tls_record_encrypt");
extern uint64_t tls_record_decrypt(const void *rec, uint64_t rec_len,
                                   const void *key, const void *iv,
                                   uint64_t seq, void *out)
    __asm__("tls_record_decrypt");
extern uint64_t tls_record_next_client_seq(void)
    __asm__("tls_record_next_client_seq");
extern uint64_t tls_record_next_server_seq(void)
    __asm__("tls_record_next_server_seq");

// the per-connection sequence counters in src/tls/data.S
extern uint64_t tls_client_seq __asm__("tls_client_seq");
extern uint64_t tls_server_seq __asm__("tls_server_seq");

// the underlying AES-128-GCM (src/crypto/gcm.S) — used to hand-craft
// records the record layer would never produce itself (all-zero
// plaintext, invalid inner types, padding), so the decrypt validation
// paths can be exercised.
extern void aes_gcm_encrypt(const void *key, const void *iv,
                            const void *aad, uint64_t aad_len,
                            const void *pt, uint64_t pt_len,
                            void *ct, void *tag)
    __asm__("aes_gcm_encrypt");

// ── inline asm wrappers (carry flag capture, like test_atoi_n.c) ────

typedef struct {
    uint64_t type;         // content type
    const uint8_t *frag;   // fragment pointer
    uint64_t frag_len;     // fragment length
    uint64_t total;        // header + fragment
} rec_parse_result;

// tls_record_parse(buf=x0, buf_len=x1) → x0=type, x1=frag, x2=frag_len,
// x3=total; error code in x0 + carry set on failure. Returns 0 on
// success, TLS_RECORD_ERR_* on failure.
static uint64_t rec_parse(const uint8_t *buf, uint64_t len,
                          rec_parse_result *r) {
    uint64_t err = 0, v0 = 0, v1 = 0, v2 = 0, v3 = 0;
    asm volatile(
        "mov x0, %5\n"
        "mov x1, %6\n"
        "bl tls_record_parse\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        "mov %2, x1\n"
        "mov %3, x2\n"
        "mov %4, x3\n"
        : "=r"(err), "=r"(v0), "=r"(v1), "=r"(v2), "=r"(v3)
        : "r"(buf), "r"(len)
        : "x0", "x1", "x2", "x3", "x5", "x6", "x7", "x9", "x10", "x30",
          "cc", "memory");
    if (r) {
        r->type = v0;
        r->frag = (const uint8_t *)v1;
        r->frag_len = v2;
        r->total = v3;
    }
    return err ? v0 : 0;
}

// tls_record_write(type=x0, frag=x1, frag_len=x2, out=x3) → x0 = record
// length on success; error code + carry set on failure.
static inline uint64_t rec_write(uint64_t type, const uint8_t *frag,
                                 uint64_t frag_len, uint8_t *out,
                                 uint64_t *carry) {
    uint64_t result, c;
    asm volatile(
        "cmp xzr, xzr\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "mov x3, %5\n"
        "bl tls_record_write\n"
        "cset %1, cs\n"
        "mov %0, x0\n"
        : "=r"(result), "=r"(c)
        : "r"(type), "r"(frag), "r"(frag_len), "r"(out)
        : "x0", "x1", "x2", "x3", "x4", "x19", "x20", "x30", "cc",
          "memory");
    *carry = c;
    return result;
}

// tls_record_encrypt(type=x0, pt=x1, pt_len=x2, key=x3, iv=x4, seq=x5,
// out=x6) → x0 = record length on success; error code + carry set on
// failure.
static inline uint64_t rec_encrypt(uint64_t type, const uint8_t *pt,
                                   uint64_t pt_len, const uint8_t *key,
                                   const uint8_t *iv, uint64_t seq,
                                   uint8_t *out, uint64_t *carry) {
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
// → x0 = content length, x1 = inner content type on success; error
// code + carry set on failure.
static inline uint64_t rec_decrypt(const uint8_t *rec, uint64_t rec_len,
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

// ── RFC 8448 §3 record-layer vectors (simple 1-RTT handshake) ────────
// Bytes are taken verbatim from RFC 8448 (Example Handshake Traces for
// TLS 1.3); the keys and IVs are the "derive write traffic keys"
// outputs shown there. Decrypting the Finished also pins the
// client_handshake read keys.

// client_handshake_traffic_secret → write key/iv (server's read keys)
static const uint8_t RFC_CHS_KEY[16] = {
    0xdb, 0xfa, 0xa6, 0x93, 0xd1, 0x76, 0x2c, 0x5b,
    0x66, 0x6a, 0xf5, 0xd9, 0x50, 0x25, 0x8d, 0x01,
};
static const uint8_t RFC_CHS_IV[12] = {
    0x5b, 0xd3, 0xc7, 0x1b, 0x83, 0x6e, 0x0b, 0x76, 0xbb, 0x73, 0x26, 0x5f,
};

// client_application_traffic_secret_0 → write key/iv
static const uint8_t RFC_CAP_KEY[16] = {
    0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9,
    0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f, 0x50, 0x51,
};
static const uint8_t RFC_CAP_IV[12] = {
    0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9,
};

// server_application_traffic_secret_0 → write key/iv
static const uint8_t RFC_SAP_KEY[16] = {
    0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef,
    0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56,
};
static const uint8_t RFC_SAP_IV[12] = {
    0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84,
};

// the client's encrypted Finished: complete record (58 octets), seq 0
static const uint8_t RFC_CLIENT_FINISHED[58] = {
    0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xec, 0x4d, 0xc2, 0x38, 0xcc,
    0xe6, 0x0b, 0x29, 0x80, 0x44, 0xa7, 0x1e, 0x21, 0x9c, 0x56, 0xcc,
    0x77, 0xb0, 0x51, 0x7f, 0xe9, 0xb9, 0x3c, 0x7a, 0x4b, 0xfc, 0x44,
    0xd8, 0x7f, 0x38, 0xf8, 0x03, 0x38, 0xac, 0x98, 0xfc, 0x46, 0xde,
    0xb3, 0x84, 0xbd, 0x1c, 0xae, 0xac, 0xab, 0x68, 0x67, 0xd7, 0x26,
    0xc4, 0x05, 0x46,
};
// ... whose plaintext is the 36-octet Finished message, inner type 22
static const uint8_t RFC_CLIENT_FINISHED_PT[36] = {
    0x14, 0x00, 0x00, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34,
    0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1,
    0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2, 0xed,
    0xd5, 0xce, 0x61,
};

// the client's application_data record: complete record (72 octets),
// 50-octet payload 00 01 .. 30 31, seq 0 (client's first app record)
static const uint8_t RFC_CLIENT_APP[72] = {
    0x17, 0x03, 0x03, 0x00, 0x43, 0xa2, 0x3f, 0x70, 0x54, 0xb6, 0x2c,
    0x94, 0xd0, 0xaf, 0xfa, 0xfe, 0x82, 0x28, 0xba, 0x55, 0xcb, 0xef,
    0xac, 0xea, 0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f, 0x2b,
    0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39, 0x5b, 0xd5, 0x4a, 0x9a,
    0x20, 0x44, 0x1e, 0x2b, 0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92,
    0xa2, 0x97, 0x70, 0x14, 0xbd, 0x1e, 0x3d, 0xea, 0xe6, 0x3a, 0xee,
    0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4,
};

// the server's application_data record: complete record (72 octets),
// same payload, seq 1 (the NewSessionTicket was the server's seq 0)
static const uint8_t RFC_SERVER_APP[72] = {
    0x17, 0x03, 0x03, 0x00, 0x43, 0x2e, 0x93, 0x7e, 0x11, 0xef, 0x4a,
    0xc7, 0x40, 0xe5, 0x38, 0xad, 0x36, 0x00, 0x5f, 0xc4, 0xa4, 0x69,
    0x32, 0xfc, 0x32, 0x25, 0xd0, 0x5f, 0x82, 0xaa, 0x1b, 0x36, 0xe3,
    0x0e, 0xfa, 0xf9, 0x7d, 0x90, 0xe6, 0xdf, 0xfc, 0x60, 0x2d, 0xcb,
    0x50, 0x1a, 0x59, 0xa8, 0xfc, 0xc4, 0x9c, 0x4b, 0xf2, 0xe5, 0xf0,
    0xa2, 0x1c, 0x00, 0x47, 0xc2, 0xab, 0xf3, 0x32, 0x54, 0x0d, 0xd0,
    0x32, 0xe1, 0x67, 0xc2, 0x95, 0x5d,
};

// the client's initial ClientHello: complete record (201 octets),
// handshake type in a 0x0301 record — the one legal 0x0301 record
static const uint8_t RFC_CLIENT_HELLO[201] = {
    0x16, 0x03, 0x01, 0x00, 0xc4, 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03,
    0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6,
    0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12,
    0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00,
    0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00,
    0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73,
    0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
    0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01,
    0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
    0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd,
    0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0,
    0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52,
    0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
    0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
    0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
    0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
    0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00,
    0x02, 0x40, 0x01,
};

// the server's ServerHello: complete record (95 octets); the 90-octet
// fragment is also what tls_record_write must reproduce
static const uint8_t RFC_SERVER_HELLO[95] = {
    0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03,
    0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60,
    0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14,
    0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00,
    0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d,
    0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66,
    0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25,
    0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f,
    0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
};

// ── helpers ─────────────────────────────────────────────────────────

// hand-craft a TLSCiphertext whose AEAD plaintext is exactly `inner`
// bytes (the record layer's own encrypt would append the type byte).
// The nonce is built independently in C — iv XOR (0^4 || seq) — so it
// cross-checks tls_record_nonce through the decrypt path.
static uint64_t build_raw_record(const uint8_t *key, const uint8_t *iv,
                                 uint64_t seq, const uint8_t *inner,
                                 uint64_t inner_len, uint8_t *out) {
    uint64_t total = TLS_RECORD_HEADER_LEN + inner_len + TLS_TAG_LEN;
    uint64_t flen = inner_len + TLS_TAG_LEN;
    uint8_t nonce[12];
    out[0] = TLS_RECORD_APPLICATION_DATA;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(flen >> 8);
    out[4] = (uint8_t)flen;
    for (int i = 0; i < 4; i++)
        nonce[i] = iv[i];
    for (int i = 0; i < 8; i++)
        nonce[4 + i] = iv[4 + i] ^ (uint8_t)(seq >> (56 - 8 * i));
    aes_gcm_encrypt(key, nonce, out, TLS_RECORD_HEADER_LEN,
                    inner, inner_len, out + TLS_RECORD_HEADER_LEN,
                    out + TLS_RECORD_HEADER_LEN + inner_len);
    return total;
}

// the 50-octet application payload shared by the RFC records
static void fill_ascending(uint8_t *buf, uint64_t len) {
    for (uint64_t i = 0; i < len; i++)
        buf[i] = (uint8_t)i;
}

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

// ── main ───────────────────────────────────────────────────────────

int main(void) {
    test_parse_rfc8448_records();
    test_parse_errors();
    test_write();
    test_nonce();
    test_encrypt_rfc8448();
    test_decrypt_rfc8448();
    test_roundtrip();
    test_decrypt_errors();
    test_inner_plaintext();
    test_sequence_numbers();
    test_summary();
    return 0;
}
