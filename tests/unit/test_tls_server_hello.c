// Unit tests for src/tls/handshake/server_hello.S
//
// Two entry points:
//   - tls_server_hello_write(out) -> length: a pure wire-format writer
//     driven entirely off fields already sitting in tls_state
//     (server_random, the session ID echo, server_key_share). Tested
//     here by pre-filling those fields directly and checking the wire
//     bytes byte-for-byte, the same way test_tls_client_hello.c drives
//     the parser with hand-built ClientHellos.
//   - tls_build_server_hello(out) -> length, carry-signalled: generates
//     the ephemeral X25519 key pair and ECDHE shared secret (the RNG-
//     dependent half), then calls the writer. Tested by setting up a
//     "client" key pair with a known scalar and checking the resulting
//     shared secret matches an independently computed X25519(client
//     scalar, server's public key) — a real end-to-end ECDHE check
//     that doesn't require a fixed KAT vector.

#include "test_harness.h"

extern uint64_t tls_server_hello_write(void *out)
    __asm__("tls_server_hello_write");
extern uint64_t tls_build_server_hello(void *out)
    __asm__("tls_build_server_hello");
extern void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point)
    __asm__("x25519");

extern uint8_t tls_server_random[32] __asm__("tls_server_random");
extern uint8_t tls_client_key_share[32] __asm__("tls_client_key_share");
extern uint8_t tls_server_key_share[32] __asm__("tls_server_key_share");
extern uint8_t tls_shared_secret[32] __asm__("tls_shared_secret");
extern uint64_t tls_session_id_len __asm__("tls_session_id_len");
extern uint8_t tls_session_id[32] __asm__("tls_session_id");

// RFC 7748 §5: X25519 base point, u = 9, little-endian.
static const uint8_t BASE9[32] = {9, 0};

static uint64_t build_sh(uint8_t *out, uint64_t *alert) {
    uint64_t fail = 0, a = 0;
    asm volatile(
        "mov x0, %2\n"
        "bl tls_build_server_hello\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(a)
        : "r"(out)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x30", "cc", "memory");
    if (alert)
        *alert = a;
    return fail;
}

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t u24be(const uint8_t *p) {
    return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
}

static void fill(uint8_t *buf, size_t n, uint8_t base) {
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(base + i);
}

// checks the fixed structure common to every ServerHello this server
// emits: type, legacy_version, cipher, compression and both
// extensions. `sid_len` is the session ID length used to compute
// offsets. Returns the offset of the key_share public key (32 bytes).
static size_t assert_fixed_structure(const uint8_t *out, uint64_t len,
                                      uint64_t sid_len) {
    uint64_t body_len = 86 + sid_len;
    ASSERT_EQ("total length == 4 + body_len", (int64_t)(4 + body_len),
              (int64_t)len);
    ASSERT_EQ("handshake type == server_hello", 2, out[0]);
    ASSERT_EQ("handshake length field", (int64_t)body_len,
              (int64_t)u24be(out + 1));
    ASSERT_EQ("legacy_version == 0x0303", 0x0303, u16be(out + 4));
    ASSERT_EQ("session id length byte", (int64_t)sid_len, out[38]);

    size_t p = 39 + sid_len;
    ASSERT_EQ("cipher_suite == TLS_AES_128_GCM_SHA256", 0x1301,
              u16be(out + p));
    ASSERT_EQ("legacy_compression_method == 0", 0, out[p + 2]);
    ASSERT_EQ("extensions length == 46", 46, u16be(out + p + 3));

    size_t e = p + 5;
    ASSERT_EQ("ext[0] type == supported_versions", 43, u16be(out + e));
    ASSERT_EQ("ext[0] length == 2", 2, u16be(out + e + 2));
    ASSERT_EQ("ext[0] selected_version == TLS 1.3", 0x0304,
              u16be(out + e + 4));
    e += 6;
    ASSERT_EQ("ext[1] type == key_share", 51, u16be(out + e));
    ASSERT_EQ("ext[1] length == 36", 36, u16be(out + e + 2));
    ASSERT_EQ("ext[1] group == X25519", 0x001d, u16be(out + e + 4));
    ASSERT_EQ("ext[1] key_exchange_length == 32", 32, u16be(out + e + 6));
    return e + 8;
}

static void test_write_empty_session_id(void) {
    TEST_SUITE("tls_server_hello_write — empty session ID");

    tls_session_id_len = 0;
    fill(tls_server_random, 32, 0x11);
    fill(tls_server_key_share, 32, 0x22);

    uint8_t out[256];
    uint64_t len = tls_server_hello_write(out);
    size_t ks = assert_fixed_structure(out, len, 0);
    ASSERT_EQ("random(32) copied verbatim", 0,
              memcmp(out + 6, tls_server_random, 32));
    ASSERT_EQ("key_share public key copied verbatim", 0,
              memcmp(out + ks, tls_server_key_share, 32));
}

static void test_write_full_session_id(void) {
    TEST_SUITE("tls_server_hello_write — full 32-byte session ID");

    tls_session_id_len = 32;
    fill(tls_session_id, 32, 0x55);
    fill(tls_server_random, 32, 0x66);
    fill(tls_server_key_share, 32, 0x77);

    uint8_t out[256];
    uint64_t len = tls_server_hello_write(out);
    size_t ks = assert_fixed_structure(out, len, 32);
    ASSERT_EQ("session id echoed verbatim", 0,
              memcmp(out + 39, tls_session_id, 32));
    ASSERT_EQ("key_share public key copied verbatim", 0,
              memcmp(out + ks, tls_server_key_share, 32));
}

static void test_build_ecdh_roundtrip(void) {
    TEST_SUITE("tls_build_server_hello — ECDHE round trip");

    // a fixed "client" ephemeral scalar and its public key
    uint8_t client_scalar[32];
    fill(client_scalar, 32, 0x9c);
    uint8_t client_pub[32];
    x25519(client_pub, client_scalar, BASE9);
    memcpy(tls_client_key_share, client_pub, 32);

    tls_session_id_len = 16;
    fill(tls_session_id, 16, 0x33);
    memset(tls_server_random, 0, 32);
    memset(tls_server_key_share, 0, 32);
    memset(tls_shared_secret, 0, 32);

    uint8_t out[256];
    uint64_t alert = 0xdeadbeef;
    ASSERT_EQ("build succeeds", 0, build_sh(out, &alert));

    uint64_t len = (uint64_t)(out[1] << 16 | out[2] << 8 | out[3]) + 4;
    assert_fixed_structure(out, len, 16);

    int random_zero = 1, keyshare_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (tls_server_random[i] != 0)
            random_zero = 0;
        if (tls_server_key_share[i] != 0)
            keyshare_zero = 0;
    }
    ASSERT_EQ("server_random was generated (not all zero)", 0, random_zero);
    ASSERT_EQ("server_key_share was generated (not all zero)", 0,
              keyshare_zero);

    uint8_t expected_shared[32];
    x25519(expected_shared, client_scalar, tls_server_key_share);
    ASSERT_EQ("shared_secret == X25519(client_scalar, server_pub)", 0,
              memcmp(expected_shared, tls_shared_secret, 32));
}

static void test_build_randomizes_each_call(void) {
    TEST_SUITE("tls_build_server_hello — fresh randomness each call");

    tls_session_id_len = 0;
    uint8_t out[256];

    ASSERT_EQ("first build succeeds", 0, build_sh(out, NULL));
    uint8_t random1[32], keyshare1[32];
    memcpy(random1, tls_server_random, 32);
    memcpy(keyshare1, tls_server_key_share, 32);

    ASSERT_EQ("second build succeeds", 0, build_sh(out, NULL));
    ASSERT_EQ("server_random differs across calls", 0,
              memcmp(random1, tls_server_random, 32) == 0);
    ASSERT_EQ("server_key_share differs across calls", 0,
              memcmp(keyshare1, tls_server_key_share, 32) == 0);
}

int main(void) {
    test_write_empty_session_id();
    test_write_full_session_id();
    test_build_ecdh_roundtrip();
    test_build_randomizes_each_call();
    test_summary();
    return 0;
}
