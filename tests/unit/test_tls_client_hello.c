// Unit tests for tls_parse_client_hello (PLAN.MD Phase 12)
//
// Two sources of ClientHello bytes:
//   - RFC_CLIENT_HELLO: the real RFC 8448 §3 wire trace. It offers
//     everything Phase 12 requires *except* ALPN, so it doubles as a
//     natural "no_application_protocol" test case while also pinning
//     the client_random/key_share extraction against known-good bytes.
//   - build_client_hello(): a small builder for synthetic ClientHellos,
//     used to exercise each individual requirement (§12.1-§12.5) and
//     the structural bounds checks in isolation.

#include "test_harness.h"

// ── wire constants mirrored from defs.S ─────────────────────────────

#define TLS_ALERT_HANDSHAKE_FAILURE       40
#define TLS_ALERT_ILLEGAL_PARAMETER       47
#define TLS_ALERT_DECODE_ERROR            50
#define TLS_ALERT_PROTOCOL_VERSION        70
#define TLS_ALERT_UNRECOGNIZED_NAME       112
#define TLS_ALERT_NO_APPLICATION_PROTOCOL 120

// ── asm entry point ──────────────────────────────────────────────────

extern uint64_t tls_parse_client_hello(const void *body, uint64_t len)
    __asm__("tls_parse_client_hello");

// the tls_state fields this parser fills in (src/tls/data.S)
extern uint8_t tls_client_random[32] __asm__("tls_client_random");
extern uint8_t tls_client_key_share[32] __asm__("tls_client_key_share");
extern uint64_t tls_alpn_len __asm__("tls_alpn_len");
extern uint8_t tls_alpn[16] __asm__("tls_alpn");

// tls_parse_client_hello(body=x0, len=x1) → x0=0 on success; alert code
// + carry set on failure (matches the rec_parse idiom in
// test_tls_record/common.h).
static uint64_t ch_parse(const uint8_t *body, uint64_t len, uint64_t *alert) {
    uint64_t fail = 0, a = 0;
    asm volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl tls_parse_client_hello\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(a)
        : "r"(body), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x30", "cc", "memory");
    if (alert)
        *alert = a;
    return fail;
}

// clear the fields the parser writes, so a test can tell "written by
// this call" apart from "leftover from a previous test"
static void reset_output_fields(void) {
    memset(tls_client_random, 0xAA, sizeof(tls_client_random));
    memset(tls_client_key_share, 0xAA, sizeof(tls_client_key_share));
    tls_alpn_len = 0xdeadbeef;
    memset(tls_alpn, 0xAA, sizeof(tls_alpn));
}

// ── RFC 8448 §3 ClientHello (real wire trace, 201-octet record) ─────
// Record header (5) + handshake header (4) + 192-byte ClientHello body.
// Offers TLS 1.3, TLS_AES_128_GCM_SHA256, X25519 (group + key_share)
// and SNI "server" — but no ALPN.
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
#define RFC_CH_BODY (RFC_CLIENT_HELLO + 9)   // past record + handshake headers
#define RFC_CH_BODY_LEN 192

static const uint8_t RFC_CH_RANDOM[32] = {
    0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6,
    0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12,
    0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7,
};
static const uint8_t RFC_CH_KEY_SHARE[32] = {
    0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e,
    0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c,
    0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c,
};

// ── synthetic ClientHello builder ────────────────────────────────────

typedef struct {
    int with_version;    // supported_versions offering TLS 1.3
    int with_cipher;     // cipher_suites offering TLS_AES_128_GCM_SHA256
    int with_group;      // supported_groups offering X25519
    int with_keyshare;   // key_share carrying an X25519 entry
    int with_alpn;       // ALPN offering "h2"
    int with_sni;        // server_name extension present
    const char *sni_host;
    uint64_t sni_host_len;
} ch_opts;

static const ch_opts CH_ACCEPT = {1, 1, 1, 1, 1, 1, "localhost", 9};

static uint8_t *put_u8(uint8_t *p, uint8_t v) {
    *p = v;
    return p + 1;
}
static uint8_t *put_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
    return p + 2;
}
static uint8_t *put_bytes(uint8_t *p, const void *src, uint64_t n) {
    memcpy(p, src, (unsigned long)n);
    return p + n;
}

// builds a syntactically well-formed ClientHello body into `out`
// (caller-provided, >= 512 bytes) and returns its length.
static uint64_t build_client_hello(uint8_t *out, const ch_opts *o) {
    uint8_t *p = out;
    p = put_u16(p, 0x0303);              // legacy_version
    for (int i = 0; i < 32; i++)         // client_random (arbitrary)
        p = put_u8(p, (uint8_t)(i + 1));
    p = put_u8(p, 0);                    // legacy_session_id, empty

    uint8_t *cs_len_pos = p;
    p += 2;
    uint8_t *cs_start = p;
    p = put_u16(p, o->with_cipher ? 0x1301 : 0x1302);  // 1 cipher suite
    put_u16(cs_len_pos, (uint16_t)(p - cs_start));

    p = put_u8(p, 1);                    // compression_methods length
    p = put_u8(p, 0);                    // null compression

    uint8_t ext[256];
    uint8_t *e = ext;
    if (o->with_version) {
        e = put_u16(e, 43);              // supported_versions
        e = put_u16(e, 3);
        e = put_u8(e, 2);
        e = put_u16(e, 0x0304);
    }
    if (o->with_group) {
        e = put_u16(e, 10);              // supported_groups
        e = put_u16(e, 4);
        e = put_u16(e, 2);
        e = put_u16(e, 0x001d);
    }
    if (o->with_keyshare) {
        e = put_u16(e, 51);              // key_share
        e = put_u16(e, 2 + 2 + 2 + 32);
        e = put_u16(e, 2 + 2 + 32);
        e = put_u16(e, 0x001d);
        e = put_u16(e, 32);
        for (int i = 0; i < 32; i++)
            e = put_u8(e, (uint8_t)(0x40 + i));
    }
    if (o->with_alpn) {
        e = put_u16(e, 16);              // ALPN
        e = put_u16(e, 2 + 1 + 2);
        e = put_u16(e, 1 + 2);
        e = put_u8(e, 2);
        e = put_u8(e, 'h');
        e = put_u8(e, '2');
    }
    if (o->with_sni) {
        uint64_t hl = o->sni_host_len;
        e = put_u16(e, 0);               // server_name
        e = put_u16(e, (uint16_t)(2 + 3 + hl));
        e = put_u16(e, (uint16_t)(3 + hl));
        e = put_u8(e, 0);                // host_name
        e = put_u16(e, (uint16_t)hl);
        e = put_bytes(e, o->sni_host, hl);
    }
    uint64_t ext_len = (uint64_t)(e - ext);
    p = put_u16(p, (uint16_t)ext_len);
    p = put_bytes(p, ext, ext_len);

    return (uint64_t)(p - out);
}

// ── tests: acceptance (§12.1-§12.5, the happy path) ─────────────────

static void test_accept(void) {
    TEST_SUITE("ClientHello parse — accept");
    uint8_t buf[512];
    uint64_t len = build_client_hello(buf, &CH_ACCEPT);
    uint64_t alert = 0;

    reset_output_fields();
    ASSERT_EQ("fully-compliant ClientHello accepted", 0,
              ch_parse(buf, len, &alert));

    ASSERT_EQ("client_random[0]", 1, tls_client_random[0]);
    ASSERT_EQ("client_random[31]", 32, tls_client_random[31]);
    ASSERT_EQ("client_key_share[0]", 0x40, tls_client_key_share[0]);
    ASSERT_EQ("client_key_share[31]", 0x40 + 31, tls_client_key_share[31]);
    ASSERT_EQ("negotiated ALPN length", 2, tls_alpn_len);
    ASSERT_STR_EQ("negotiated ALPN == \"h2\"", "h2", tls_alpn, 2);

    // SNI absent entirely — still accepted (no virtual hosts to pick)
    ch_opts no_sni = CH_ACCEPT;
    no_sni.with_sni = 0;
    len = build_client_hello(buf, &no_sni);
    ASSERT_EQ("ClientHello without SNI accepted", 0,
              ch_parse(buf, len, &alert));
}

static void test_accept_rfc8448_shape(void) {
    TEST_SUITE("ClientHello parse — RFC 8448 vector shape");
    // RFC_CLIENT_HELLO lacks ALPN, so the overall parse fails, but
    // client_random/key_share are extracted before that check runs —
    // pin both against the RFC's known values.
    uint64_t alert = 0;
    reset_output_fields();
    ASSERT_EQ("RFC ClientHello rejected (no ALPN)", 1,
              ch_parse(RFC_CH_BODY, RFC_CH_BODY_LEN, &alert));
    ASSERT_EQ("RFC ClientHello rejected (no ALPN) — alert",
              TLS_ALERT_NO_APPLICATION_PROTOCOL, alert);
    ASSERT_EQ("RFC client_random extracted", 0,
              memcmp(tls_client_random, RFC_CH_RANDOM, 32));
    ASSERT_EQ("RFC client_key_share extracted", 0,
              memcmp(tls_client_key_share, RFC_CH_KEY_SHARE, 32));
}

// ── tests: requirements (§12.1-§12.4) ────────────────────────────────

static void test_requirements(void) {
    TEST_SUITE("ClientHello parse — requirement alerts");
    uint8_t buf[512];
    uint64_t alert;

    ch_opts no_version = CH_ACCEPT;
    no_version.with_version = 0;
    uint64_t len = build_client_hello(buf, &no_version);
    ASSERT_EQ("no supported_versions → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("no supported_versions → protocol_version",
              TLS_ALERT_PROTOCOL_VERSION, alert);

    ch_opts no_cipher = CH_ACCEPT;
    no_cipher.with_cipher = 0;
    len = build_client_hello(buf, &no_cipher);
    ASSERT_EQ("no matching cipher → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("no matching cipher → handshake_failure",
              TLS_ALERT_HANDSHAKE_FAILURE, alert);

    ch_opts no_group = CH_ACCEPT;
    no_group.with_group = 0;
    len = build_client_hello(buf, &no_group);
    ASSERT_EQ("no X25519 group → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("no X25519 group → handshake_failure",
              TLS_ALERT_HANDSHAKE_FAILURE, alert);

    ch_opts no_keyshare = CH_ACCEPT;
    no_keyshare.with_keyshare = 0;
    len = build_client_hello(buf, &no_keyshare);
    ASSERT_EQ("no X25519 key_share → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("no X25519 key_share → handshake_failure",
              TLS_ALERT_HANDSHAKE_FAILURE, alert);

    ch_opts no_alpn = CH_ACCEPT;
    no_alpn.with_alpn = 0;
    len = build_client_hello(buf, &no_alpn);
    ASSERT_EQ("no ALPN \"h2\" → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("no ALPN \"h2\" → no_application_protocol",
              TLS_ALERT_NO_APPLICATION_PROTOCOL, alert);

    ch_opts wrong_host = CH_ACCEPT;
    wrong_host.sni_host = "evil.example";
    wrong_host.sni_host_len = 12;
    len = build_client_hello(buf, &wrong_host);
    ASSERT_EQ("SNI mismatch → fail", 1, ch_parse(buf, len, &alert));
    ASSERT_EQ("SNI mismatch → unrecognized_name",
              TLS_ALERT_UNRECOGNIZED_NAME, alert);
}

// ── tests: structural bounds checking (decode_error) ─────────────────

static void test_decode_errors(void) {
    TEST_SUITE("ClientHello parse — malformed structure");
    uint8_t buf[512];
    uint64_t alert;
    uint64_t len = build_client_hello(buf, &CH_ACCEPT);

    // fewer than 35 bytes (version+random+session_id length prefix)
    for (uint64_t n = 0; n < 35; n++) {
        ASSERT_EQ("too short → decode_error", 1, ch_parse(buf, n, &alert));
        ASSERT_EQ("too short → decode_error (alert)",
                  TLS_ALERT_DECODE_ERROR, alert);
    }

    // session_id length claims more than fits
    uint8_t bad[64];
    memcpy(bad, buf, 40);
    bad[34] = 200;  // session_id length byte, way past the buffer
    ASSERT_EQ("session_id overflow → decode_error", 1,
              ch_parse(bad, 40, &alert));
    ASSERT_EQ("session_id overflow → decode_error (alert)",
              TLS_ALERT_DECODE_ERROR, alert);

    // legacy_session_id<0..32> — 33 is already illegal regardless of
    // buffer size
    memcpy(bad, buf, 64);
    bad[34] = 33;
    ASSERT_EQ("session_id length 33 → decode_error", 1,
              ch_parse(bad, 64, &alert));
    ASSERT_EQ("session_id length 33 → decode_error (alert)",
              TLS_ALERT_DECODE_ERROR, alert);

    // extensions length that doesn't exactly fill the remaining buffer
    uint8_t trunc[512];
    memcpy(trunc, buf, len);
    ASSERT_EQ("one byte short of the extensions block → decode_error", 1,
              ch_parse(trunc, len - 1, &alert));
    ASSERT_EQ("...decode_error (alert)", TLS_ALERT_DECODE_ERROR, alert);

    // legacy_compression_methods must be exactly one byte, value 0
    // (§4.1.2) — anything else is illegal_parameter, not decode_error.
    ch_opts base = CH_ACCEPT;
    uint64_t l2 = build_client_hello(buf, &base);
    // compression_methods starts right after: 2(ver)+32(rand)+1(sid=0)
    // +2(cs_len)+2(one cipher)=39
    ASSERT_EQ("sanity: compression length byte is 1", 1, buf[39]);
    ASSERT_EQ("sanity: compression method byte is 0", 0, buf[40]);

    uint8_t nonnull[512];
    memcpy(nonnull, buf, l2);
    nonnull[40] = 1;  // non-null compression method
    ASSERT_EQ("non-null compression → fail", 1,
              ch_parse(nonnull, l2, &alert));
    ASSERT_EQ("non-null compression → illegal_parameter",
              TLS_ALERT_ILLEGAL_PARAMETER, alert);

    uint8_t extra[512];
    memcpy(extra, buf, 41);
    extra[39] = 2;       // claims two compression methods
    extra[41] = 1;       // second byte, shifting everything after by 1
    memcpy(extra + 42, buf + 41, l2 - 41);
    ASSERT_EQ("compression length != 1 → fail", 1,
              ch_parse(extra, l2 + 1, &alert));
    ASSERT_EQ("compression length != 1 → illegal_parameter",
              TLS_ALERT_ILLEGAL_PARAMETER, alert);
}

int main(void) {
    test_accept();
    test_accept_rfc8448_shape();
    test_requirements();
    test_decode_errors();
    test_summary();
    return 0;
}
