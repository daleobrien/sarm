// Common definitions for TLS record layer tests (PLAN.MD Phase 11)
#pragma once

#include "../test_harness.h"

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
