// Unit tests for src/tls/handshake/key_schedule.S (PLAN.MD Phase 10,
// implemented alongside Phase 14 which needs the handshake keys).
//
// tls_derive_handshake_secrets(transcript_hash) runs the RFC 8446 §7.1
// key schedule from tls_shared_secret through the Master Secret. The
// RFC 8448 §3 "Simple 1-RTT Handshake" trace gives fixed values for
// every step (the same constants test_hkdf.c already cross-checks
// hkdf_expand_label against), so this is tested end-to-end against that
// trace rather than a synthetic vector:
//   - the ECDHE shared secret (the IKM RFC 8448 uses for the Handshake
//     Secret extract) goes into tls_shared_secret
//   - the ClientHello..ServerHello transcript hash RFC 8448 records is
//     passed straight to tls_derive_handshake_secrets
//   - the resulting tls_handshake_secret, server_hs_key/iv and
//     master_secret are compared against the RFC's published values
//   - the client_hs_key/iv (not directly published by RFC 8448, but
//     derivable from its published client_handshake_traffic_secret) are
//     cross-checked against hkdf_expand_label applied to that secret —
//     the same reciprocal-computation approach test_tls_server_hello.c
//     uses for the ECDHE round trip.

#include "test_harness.h"

extern void tls_derive_handshake_secrets(const uint8_t transcript_hash[32])
    __asm__("tls_derive_handshake_secrets");
extern void hkdf_expand_label(const uint8_t *secret,
                              const uint8_t *label, uint64_t label_len,
                              const uint8_t *context, uint64_t context_len,
                              uint8_t *out, uint64_t outlen)
    __asm__("hkdf_expand_label");

extern uint8_t tls_shared_secret[32] __asm__("tls_shared_secret");
extern uint8_t tls_handshake_secret[32] __asm__("tls_handshake_secret");
extern uint8_t tls_master_secret[32] __asm__("tls_master_secret");
extern uint8_t tls_client_hs_key[16] __asm__("tls_client_hs_key");
extern uint8_t tls_client_hs_iv[12] __asm__("tls_client_hs_iv");
extern uint8_t tls_server_hs_key[16] __asm__("tls_server_hs_key");
extern uint8_t tls_server_hs_iv[12] __asm__("tls_server_hs_iv");

// ── RFC 8448 §3 "Simple 1-RTT Handshake" vectors ────────────────────

// The ECDHE shared secret: X25519(client's ephemeral scalar, server's
// ephemeral public key) — the IKM the RFC extracts the Handshake Secret
// from.
static const uint8_t SHARED_SECRET[32] = {
    0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d,
    0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d,
};
// SHA-256 transcript hash of ClientHello..ServerHello.
static const uint8_t CH_HS_HASH[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7, 0x42, 0x8c, 0x58, 0xed,
    0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f, 0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8,
};
static const uint8_t HANDSHAKE_SECRET[32] = {
    0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01,
    0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac,
};
static const uint8_t C_HS_TRAFFIC[32] = {
    0xb3, 0xed, 0xdb, 0x12, 0x6e, 0x06, 0x7f, 0x35, 0xa7, 0x80, 0xb3, 0xab, 0xf4, 0x5e, 0x2d, 0x8f,
    0x3b, 0x1a, 0x95, 0x07, 0x38, 0xf5, 0x2e, 0x96, 0x00, 0x74, 0x6a, 0x0e, 0x27, 0xa5, 0x5a, 0x21,
};
static const uint8_t S_HS_TRAFFIC[32] = {
    0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4,
    0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38,
};
static const uint8_t HS_KEY[16] = {
    0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc,
};
static const uint8_t HS_IV[12] = {
    0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30,
};
static const uint8_t MASTER_SECRET[32] = {
    0x18, 0xdf, 0x06, 0x84, 0x3d, 0x13, 0xa0, 0x8b, 0xf2, 0xa4, 0x49, 0x84, 0x4c, 0x5f, 0x8a, 0x47,
    0x80, 0x01, 0xbc, 0x4d, 0x4c, 0x62, 0x79, 0x84, 0xd5, 0xa4, 0x1d, 0xa8, 0xd0, 0x40, 0x29, 0x19,
};

static int buf_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

static void test_rfc8448_handshake_keys(void) {
    TEST_SUITE("tls_derive_handshake_secrets — RFC 8448 §3 trace");

    memcpy(tls_shared_secret, SHARED_SECRET, 32);
    tls_derive_handshake_secrets(CH_HS_HASH);

    ASSERT_TRUE("handshake_secret matches RFC 8448",
                buf_eq(HANDSHAKE_SECRET, tls_handshake_secret, 32));
    ASSERT_TRUE("server_hs_key matches RFC 8448",
                buf_eq(HS_KEY, tls_server_hs_key, 16));
    ASSERT_TRUE("server_hs_iv matches RFC 8448",
                buf_eq(HS_IV, tls_server_hs_iv, 12));
    ASSERT_TRUE("master_secret matches RFC 8448",
                buf_eq(MASTER_SECRET, tls_master_secret, 32));

    // RFC 8448 doesn't publish the client key/iv directly — cross-check
    // them by expanding its published client_handshake_traffic_secret
    // the same way the key schedule itself does.
    uint8_t want_key[16], want_iv[12];
    hkdf_expand_label(C_HS_TRAFFIC, (const uint8_t *)"key", 3, NULL, 0,
                      want_key, 16);
    hkdf_expand_label(C_HS_TRAFFIC, (const uint8_t *)"iv", 2, NULL, 0,
                      want_iv, 12);
    ASSERT_TRUE("client_hs_key == expand(RFC c_hs_traffic, \"key\")",
                buf_eq(want_key, tls_client_hs_key, 16));
    ASSERT_TRUE("client_hs_iv == expand(RFC c_hs_traffic, \"iv\")",
                buf_eq(want_iv, tls_client_hs_iv, 12));
}

static void test_deterministic(void) {
    TEST_SUITE("tls_derive_handshake_secrets — deterministic");

    memcpy(tls_shared_secret, SHARED_SECRET, 32);
    tls_derive_handshake_secrets(CH_HS_HASH);
    uint8_t hs1[32], sk1[16], si1[12];
    memcpy(hs1, tls_handshake_secret, 32);
    memcpy(sk1, tls_server_hs_key, 16);
    memcpy(si1, tls_server_hs_iv, 12);

    // zero everything, then rerun with the same inputs
    memset(tls_handshake_secret, 0, 32);
    memset(tls_server_hs_key, 0, 16);
    memset(tls_server_hs_iv, 0, 12);
    tls_derive_handshake_secrets(CH_HS_HASH);

    ASSERT_TRUE("handshake_secret reproducible", buf_eq(hs1, tls_handshake_secret, 32));
    ASSERT_TRUE("server_hs_key reproducible", buf_eq(sk1, tls_server_hs_key, 16));
    ASSERT_TRUE("server_hs_iv reproducible", buf_eq(si1, tls_server_hs_iv, 12));
}

static void test_different_transcript_differs(void) {
    TEST_SUITE("tls_derive_handshake_secrets — transcript-dependence");

    memcpy(tls_shared_secret, SHARED_SECRET, 32);
    tls_derive_handshake_secrets(CH_HS_HASH);
    uint8_t sk1[16];
    memcpy(sk1, tls_server_hs_key, 16);

    uint8_t other_hash[32];
    memcpy(other_hash, CH_HS_HASH, 32);
    other_hash[0] ^= 0xff;             // any different transcript
    tls_derive_handshake_secrets(other_hash);

    // handshake_secret depends only on the shared secret, not the
    // transcript, so it must be unchanged...
    ASSERT_TRUE("handshake_secret unaffected by transcript",
                buf_eq(HANDSHAKE_SECRET, tls_handshake_secret, 32));
    // ...but the traffic secrets (and therefore the keys) are
    // Derive-Secret(handshake_secret, label, transcript_hash), so a
    // different transcript must change them.
    ASSERT_EQ("server_hs_key changes with the transcript hash", 0,
              buf_eq(sk1, tls_server_hs_key, 16));
}

int main(void) {
    test_rfc8448_handshake_keys();
    test_deterministic();
    test_different_transcript_differs();
    test_summary();
    return 0;
}
