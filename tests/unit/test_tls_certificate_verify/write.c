// Unit tests for tls_certificate_verify_write from
// src/tls/handshake/certificate_verify/write.S (RFC 8446 §4.4.3)
//
// tls_certificate_verify_write draws a fresh random nonce internally,
// so unlike sign_with_k.c this can't be pinned against a fixed
// (r,s) vector. Instead it's tested structurally: parse the wire
// format (handshake header, signature_algorithm, length-prefixed DER
// signature), decode the DER back into (r,s), and check the result
// verifies against the server's real public key -- a genuine
// randomness-through-to-verification round trip, the same discipline
// as test_tls_server_hello.c's ECDHE cross-check.

#include "test_harness.h"

extern uint64_t tls_certificate_verify_write(void *out, const uint8_t transcript_hash[32])
    __asm__("tls_certificate_verify_write");
extern int64_t p256_ecdsa_verify(const uint8_t hash[32], const uint8_t sig_r[32],
                                  const uint8_t sig_s[32], const uint8_t qx[32],
                                  const uint8_t qy[32])
    __asm__("p256_ecdsa_verify");
extern void tls_certificate_verify_content_hash(uint8_t out[32], const uint8_t transcript_hash[32])
    __asm__("tls_certificate_verify_content_hash");

#define TLS_HS_CERTIFICATE_VERIFY 15
#define SIG_ECDSA_SECP256R1_SHA256 0x0403

static const uint8_t SERVER_QX[32] = {0x74,0x52,0x7c,0x7a,0x9d,0x43,0x1e,0x13,0x7f,0x5b,0xbe,0x09,0x26,0x49,0xcc,0x7d,0x88,0x49,0x91,0xae,0x59,0x08,0x94,0x4a,0xbe,0x8b,0xf2,0x96,0xd1,0x08,0x65,0xe4};
static const uint8_t SERVER_QY[32] = {0xef,0x16,0x9a,0xb9,0x12,0x69,0x06,0x7c,0x65,0x92,0xfa,0xcd,0xf0,0x63,0x6f,0x93,0xe7,0xb3,0xdd,0x25,0x08,0xfe,0xa8,0xbf,0xea,0xfd,0xdd,0x94,0xb9,0x8e,0x03,0xa8};

static uint32_t u24be(const uint8_t *p) {
    return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
}
static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// Minimal DER INTEGER decoder for the two ECDSA-Sig-Value fields:
// strips the ASN.1 header and left-pads/truncates into a 32-byte
// big-endian buffer. Returns the number of DER bytes consumed, or 0
// on malformed input.
static int decode_der_int(const uint8_t *p, int len, uint8_t out[32]) {
    if (len < 2 || p[0] != 0x02) return 0;
    int ilen = p[1];
    if (ilen < 1 || 2 + ilen > len || ilen > 33) return 0;
    const uint8_t *v = p + 2;
    if (ilen > 32) { v++; ilen--; }  // drop the DER pad byte
    int pad = 32 - ilen;
    for (int i = 0; i < pad; i++) out[i] = 0;
    memcpy(out + pad, v, (unsigned long)ilen);
    return 2 + (p[1]);
}

// Parses the whole message, checks the fixed structure, decodes (r,s),
// and returns 1 iff everything (including the ECDSA verify) checks out.
static int check_message(const uint8_t *out, uint64_t len, const uint8_t transcript_hash[32]) {
    if (len < 8) return 0;
    if (out[0] != TLS_HS_CERTIFICATE_VERIFY) return 0;
    uint32_t body_len = u24be(out + 1);
    if (body_len + 4 != len) return 0;

    uint16_t alg = u16be(out + 4);
    if (alg != SIG_ECDSA_SECP256R1_SHA256) return 0;

    uint16_t sig_len = u16be(out + 6);
    if ((uint64_t)sig_len + 8 != len) return 0;

    const uint8_t *der = out + 8;
    if (der[0] != 0x30) return 0;
    int seq_len = der[1];
    if (seq_len + 2 != sig_len) return 0;

    uint8_t r[32], s[32];
    int used = decode_der_int(der + 2, seq_len, r);
    if (!used) return 0;
    int used2 = decode_der_int(der + 2 + used, seq_len - used, s);
    if (!used2) return 0;
    if (used + used2 != seq_len) return 0;

    uint8_t digest[32];
    tls_certificate_verify_content_hash(digest, transcript_hash);
    return (int)p256_ecdsa_verify(digest, r, s, SERVER_QX, SERVER_QY);
}

static void fill(uint8_t *buf, unsigned long n, uint8_t base) {
    for (unsigned long i = 0; i < n; i++)
        buf[i] = (uint8_t)(base + i);
}

static void test_write_verifies(void) {
    TEST_SUITE("tls_certificate_verify_write — output verifies against the server pubkey");
    uint8_t transcript_hash[32];
    fill(transcript_hash, 32, 0x11);

    uint8_t out[128];
    uint64_t len = tls_certificate_verify_write(out, transcript_hash);

    ASSERT_EQ("message parses and verifies", 1, check_message(out, len, transcript_hash));
}

static void test_write_randomizes(void) {
    TEST_SUITE("tls_certificate_verify_write — draws a fresh nonce each call");
    uint8_t transcript_hash[32];
    fill(transcript_hash, 32, 0x22);

    uint8_t out1[128], out2[128];
    uint64_t len1 = tls_certificate_verify_write(out1, transcript_hash);
    uint64_t len2 = tls_certificate_verify_write(out2, transcript_hash);

    int same = (len1 == len2) && (memcmp(out1, out2, len1) == 0);
    ASSERT_EQ("two calls over the same transcript differ", 0, same);
    ASSERT_EQ("first call still verifies", 1, check_message(out1, len1, transcript_hash));
    ASSERT_EQ("second call still verifies", 1, check_message(out2, len2, transcript_hash));
}

static void test_write_transcript_dependence(void) {
    TEST_SUITE("tls_certificate_verify_write — signature is bound to the transcript hash");
    uint8_t th_a[32], th_b[32];
    fill(th_a, 32, 0x33);
    fill(th_b, 32, 0x44);

    uint8_t out[128];
    uint64_t len = tls_certificate_verify_write(out, th_a);

    // The signature was produced over th_a's content hash; verifying it
    // against th_b's content hash must fail.
    ASSERT_EQ("verifies against the transcript it was signed over", 1,
              check_message(out, len, th_a));
    ASSERT_EQ("rejects a different transcript hash", 0,
              check_message(out, len, th_b));
}

int main(void) {
    test_write_verifies();
    test_write_randomizes();
    test_write_transcript_dependence();
    test_summary();
    return 0;
}
