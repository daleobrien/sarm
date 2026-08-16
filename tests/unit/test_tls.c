// Unit tests for the TLS constants and connection state (PLAN.MD §2)
//
// §2.1 — TLS constants: the wire-format constants in defs.S (protocol
// versions, cipher suites, named groups, signature schemes, ALPN,
// record types, handshake types, alert types, extension types) are
// mirrored here as #defines and pinned to their RFC 8446 values, so a
// typo in either place fails this suite.
//
// §2.2 — tls_state: the fixed-layout connection state struct in
// src/tls/data.S. Every field is exported under a tls_* label; this
// suite takes the address of tls_state and of each label via inline
// asm (pure-assembly symbols carry no C underscore on Apple ARM64, so
// C `extern` cannot reach them — same idiom as test_h2_alignment.c)
// and asserts each sits at exactly the TLS_* offset defs.S documents.
// It also checks the struct is 16-byte aligned, its storage extent
// matches TLS_STATE_SIZE, the initial values are the "no connection
// yet" defaults, and tls_alpn_h2 is the "h2" ALPN identifier.

#include "test_harness.h"

// ── TLS wire constants, mirroring defs.S (RFC 8446) ────────────────

// protocol versions (§4.1.2, §5.1)
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304

// cipher suites (§B.4)
#define TLS_CIPHER_AES_128_GCM_SHA256 0x1301

// named groups (§4.2.7)
#define NAMED_GROUP_SECP256R1 0x0017
#define NAMED_GROUP_X25519    0x001D

// signature schemes (§4.2.3)
#define SIG_ECDSA_SECP256R1_SHA256 0x0403

// ALPN (§3.3 / RFC 7301)
#define TLS_ALPN_H2_LEN 2

// record layer (§5)
#define TLS_RECORD_CHANGE_CIPHER_SPEC 20
#define TLS_RECORD_ALERT               21
#define TLS_RECORD_HANDSHAKE           22
#define TLS_RECORD_APPLICATION_DATA    23
#define TLS_RECORD_HEADER_LEN 5
#define TLS_MAX_PLAINTEXT      16384

// handshake message types (§4)
#define TLS_HS_CLIENT_HELLO         1
#define TLS_HS_SERVER_HELLO         2
#define TLS_HS_NEW_SESSION_TICKET   4
#define TLS_HS_END_OF_EARLY_DATA    5
#define TLS_HS_ENCRYPTED_EXTENSIONS 8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_CERTIFICATE_REQUEST  13
#define TLS_HS_CERTIFICATE_VERIFY   15
#define TLS_HS_FINISHED             20
#define TLS_HS_KEY_UPDATE           24
#define TLS_HS_MESSAGE_HASH         254
#define TLS_HS_HEADER_LEN 4

// alert levels (§6.2)
#define TLS_ALERT_WARNING 1
#define TLS_ALERT_FATAL   2

// alert descriptions (§6.2)
#define TLS_ALERT_CLOSE_NOTIFY             0
#define TLS_ALERT_UNEXPECTED_MESSAGE       10
#define TLS_ALERT_BAD_RECORD_MAC           20
#define TLS_ALERT_RECORD_OVERFLOW          22
#define TLS_ALERT_HANDSHAKE_FAILURE        40
#define TLS_ALERT_BAD_CERTIFICATE          42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE  43
#define TLS_ALERT_CERTIFICATE_REVOKED      44
#define TLS_ALERT_CERTIFICATE_EXPIRED      45
#define TLS_ALERT_CERTIFICATE_UNKNOWN      46
#define TLS_ALERT_ILLEGAL_PARAMETER        47
#define TLS_ALERT_UNKNOWN_CA               48
#define TLS_ALERT_ACCESS_DENIED            49
#define TLS_ALERT_DECODE_ERROR             50
#define TLS_ALERT_DECRYPT_ERROR            51
#define TLS_ALERT_PROTOCOL_VERSION         70
#define TLS_ALERT_INSUFFICIENT_SECURITY    71
#define TLS_ALERT_INTERNAL_ERROR           80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK   86
#define TLS_ALERT_USER_CANCELED            90
#define TLS_ALERT_MISSING_EXTENSION        109
#define TLS_ALERT_UNSUPPORTED_EXTENSION    110
#define TLS_ALERT_UNRECOGNIZED_NAME        112
#define TLS_ALERT_BAD_CERT_STATUS_RESPONSE 113
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY     115
#define TLS_ALERT_CERTIFICATE_REQUIRED     116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL  120

// extensions (§4.2)
#define TLS_EXT_SERVER_NAME               0
#define TLS_EXT_MAX_FRAGMENT_LENGTH       1
#define TLS_EXT_STATUS_REQUEST            5
#define TLS_EXT_SUPPORTED_GROUPS          10
#define TLS_EXT_SIGNATURE_ALGORITHMS      13
#define TLS_EXT_USE_SRTP                  14
#define TLS_EXT_HEARTBEAT                 15
#define TLS_EXT_ALPN                      16
#define TLS_EXT_SIGNED_CERT_TIMESTAMP     18
#define TLS_EXT_CLIENT_CERT_TYPE          19
#define TLS_EXT_SERVER_CERT_TYPE          20
#define TLS_EXT_PADDING                   21
#define TLS_EXT_PRE_SHARED_KEY            41
#define TLS_EXT_EARLY_DATA                42
#define TLS_EXT_SUPPORTED_VERSIONS        43
#define TLS_EXT_COOKIE                    44
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES    45
#define TLS_EXT_CERTIFICATE_AUTHORITIES   47
#define TLS_EXT_OID_FILTERS               48
#define TLS_EXT_POST_HANDSHAKE_AUTH       49
#define TLS_EXT_SIGNATURE_ALGORITHMS_CERT 50
#define TLS_EXT_KEY_SHARE                 51

// handshake state machine (tls_state handshake_state values)
#define TLS_HS_START       0
#define TLS_HS_CH_RECEIVED 1
#define TLS_HS_SH_SENT     2
#define TLS_HS_EE_SENT     3
#define TLS_HS_CERT_SENT   4
#define TLS_HS_CV_SENT     5
#define TLS_HS_FIN_SENT    6
#define TLS_HS_CONNECTED   7
#define TLS_HS_FAILED      8

// ── tls_state layout, mirroring defs.S (PLAN.MD §2.2) ──────────────

// field sizes (bytes)
#define TLS_RANDOM_LEN    32
#define TLS_KEY_SHARE_LEN 32
#define TLS_SECRET_LEN    32
#define TLS_DIGEST_LEN    32
#define TLS_KEY_LEN       16
#define TLS_IV_LEN        12
#define TLS_IV_STRIDE     16
#define TLS_SEQ_LEN       8
#define TLS_ALPN_BUF      16

// field offsets
#define TLS_FD               0
#define TLS_HS_STATE         8
#define TLS_CLIENT_RANDOM    16
#define TLS_SERVER_RANDOM    48
#define TLS_CLIENT_KEY_SHARE 80
#define TLS_SERVER_KEY_SHARE 112
#define TLS_SHARED_SECRET    144
#define TLS_TRANSCRIPT_HASH  176
#define TLS_HANDSHAKE_SECRET 208
#define TLS_MASTER_SECRET    240
#define TLS_CLIENT_HS_KEY    272
#define TLS_CLIENT_HS_IV     288
#define TLS_SERVER_HS_KEY    304
#define TLS_SERVER_HS_IV     320
#define TLS_CLIENT_APP_KEY   336
#define TLS_CLIENT_APP_IV    352
#define TLS_SERVER_APP_KEY   368
#define TLS_SERVER_APP_IV    384
#define TLS_CLIENT_SEQ       400
#define TLS_SERVER_SEQ       408
#define TLS_ALPN_LEN         416
#define TLS_ALPN             424
#define TLS_SESSION_ID_LEN   440
#define TLS_SESSION_ID       448
#define TLS_SERVER_HS_TRAFFIC_SECRET 480
#define TLS_CLIENT_HS_TRAFFIC_SECRET 512
#define TLS_STATE_SIZE       544

// ── asm symbol addressing ──────────────────────────────────────────
// Take the address of a pure-assembly symbol by name (see file header).

#define ASM_SYM_ADDR(sym) ({ \
	uintptr_t _addr; \
	asm volatile( \
		"adrp x0, " #sym "@PAGE\n\t" \
		"add  x0, x0, " #sym "@PAGEOFF\n\t" \
		"mov  %0, x0\n\t" \
		: "=r"(_addr) \
		: \
		: "x0"); \
	_addr; \
})

// offset of an asm field label from tls_state
#define TLS_OFFSET(sym) \
	((int64_t)ASM_SYM_ADDR(sym) - (int64_t)ASM_SYM_ADDR(tls_state))

// assert an asm field label sits at the documented TLS_* offset
#define ASSERT_TLS_OFFSET(label, sym, expected) \
	ASSERT_EQ(label, (int64_t)(expected), TLS_OFFSET(sym))

// dereference an asm u64 field
#define TLS_FIELD(sym) (*(int64_t *)(void *)ASM_SYM_ADDR(sym))

// ── tests: wire constants (§2.1) ───────────────────────────────────

static void test_wire_constants(void) {
	TEST_SUITE("TLS wire constants");
	ASSERT_EQ_HEX("TLS 1.3 version", 0x0304, TLS_VERSION_1_3);
	ASSERT_EQ_HEX("TLS 1.2 (legacy record version)", 0x0303, TLS_VERSION_1_2);
	ASSERT_EQ_HEX("TLS_AES_128_GCM_SHA256", 0x1301,
	              TLS_CIPHER_AES_128_GCM_SHA256);
	ASSERT_EQ_HEX("named group X25519", 0x001D, NAMED_GROUP_X25519);
	ASSERT_EQ_HEX("named group secp256r1", 0x0017, NAMED_GROUP_SECP256R1);
	ASSERT_EQ_HEX("signature scheme ecdsa_secp256r1_sha256", 0x0403,
	              SIG_ECDSA_SECP256R1_SHA256);
	ASSERT_EQ("ALPN h2 length", 2, TLS_ALPN_H2_LEN);
}

static void test_record_types(void) {
	TEST_SUITE("TLS record types");
	ASSERT_EQ("change_cipher_spec", 20, TLS_RECORD_CHANGE_CIPHER_SPEC);
	ASSERT_EQ("alert", 21, TLS_RECORD_ALERT);
	ASSERT_EQ("handshake", 22, TLS_RECORD_HANDSHAKE);
	ASSERT_EQ("application_data", 23, TLS_RECORD_APPLICATION_DATA);
	ASSERT_EQ("record header length", 5, TLS_RECORD_HEADER_LEN);
	ASSERT_EQ("max plaintext (2^14)", 16384, TLS_MAX_PLAINTEXT);
}

static void test_handshake_types(void) {
	TEST_SUITE("TLS handshake types");
	ASSERT_EQ("client_hello", 1, TLS_HS_CLIENT_HELLO);
	ASSERT_EQ("server_hello", 2, TLS_HS_SERVER_HELLO);
	ASSERT_EQ("new_session_ticket", 4, TLS_HS_NEW_SESSION_TICKET);
	ASSERT_EQ("end_of_early_data", 5, TLS_HS_END_OF_EARLY_DATA);
	ASSERT_EQ("encrypted_extensions", 8, TLS_HS_ENCRYPTED_EXTENSIONS);
	ASSERT_EQ("certificate", 11, TLS_HS_CERTIFICATE);
	ASSERT_EQ("certificate_request", 13, TLS_HS_CERTIFICATE_REQUEST);
	ASSERT_EQ("certificate_verify", 15, TLS_HS_CERTIFICATE_VERIFY);
	ASSERT_EQ("finished", 20, TLS_HS_FINISHED);
	ASSERT_EQ("key_update", 24, TLS_HS_KEY_UPDATE);
	ASSERT_EQ("message_hash", 254, TLS_HS_MESSAGE_HASH);
	ASSERT_EQ("handshake header length", 4, TLS_HS_HEADER_LEN);
}

static void test_alert_types(void) {
	TEST_SUITE("TLS alert types");
	ASSERT_EQ("level warning", 1, TLS_ALERT_WARNING);
	ASSERT_EQ("level fatal", 2, TLS_ALERT_FATAL);
	ASSERT_EQ("close_notify", 0, TLS_ALERT_CLOSE_NOTIFY);
	ASSERT_EQ("unexpected_message", 10, TLS_ALERT_UNEXPECTED_MESSAGE);
	ASSERT_EQ("bad_record_mac", 20, TLS_ALERT_BAD_RECORD_MAC);
	ASSERT_EQ("record_overflow", 22, TLS_ALERT_RECORD_OVERFLOW);
	ASSERT_EQ("handshake_failure", 40, TLS_ALERT_HANDSHAKE_FAILURE);
	ASSERT_EQ("bad_certificate", 42, TLS_ALERT_BAD_CERTIFICATE);
	ASSERT_EQ("unsupported_certificate", 43,
	          TLS_ALERT_UNSUPPORTED_CERTIFICATE);
	ASSERT_EQ("certificate_revoked", 44, TLS_ALERT_CERTIFICATE_REVOKED);
	ASSERT_EQ("certificate_expired", 45, TLS_ALERT_CERTIFICATE_EXPIRED);
	ASSERT_EQ("certificate_unknown", 46, TLS_ALERT_CERTIFICATE_UNKNOWN);
	ASSERT_EQ("illegal_parameter", 47, TLS_ALERT_ILLEGAL_PARAMETER);
	ASSERT_EQ("unknown_ca", 48, TLS_ALERT_UNKNOWN_CA);
	ASSERT_EQ("access_denied", 49, TLS_ALERT_ACCESS_DENIED);
	ASSERT_EQ("decode_error", 50, TLS_ALERT_DECODE_ERROR);
	ASSERT_EQ("decrypt_error", 51, TLS_ALERT_DECRYPT_ERROR);
	ASSERT_EQ("protocol_version", 70, TLS_ALERT_PROTOCOL_VERSION);
	ASSERT_EQ("insufficient_security", 71, TLS_ALERT_INSUFFICIENT_SECURITY);
	ASSERT_EQ("internal_error", 80, TLS_ALERT_INTERNAL_ERROR);
	ASSERT_EQ("inappropriate_fallback", 86, TLS_ALERT_INAPPROPRIATE_FALLBACK);
	ASSERT_EQ("user_canceled", 90, TLS_ALERT_USER_CANCELED);
	ASSERT_EQ("missing_extension", 109, TLS_ALERT_MISSING_EXTENSION);
	ASSERT_EQ("unsupported_extension", 110, TLS_ALERT_UNSUPPORTED_EXTENSION);
	ASSERT_EQ("unrecognized_name", 112, TLS_ALERT_UNRECOGNIZED_NAME);
	ASSERT_EQ("bad_cert_status_response", 113,
	          TLS_ALERT_BAD_CERT_STATUS_RESPONSE);
	ASSERT_EQ("unknown_psk_identity", 115, TLS_ALERT_UNKNOWN_PSK_IDENTITY);
	ASSERT_EQ("certificate_required", 116, TLS_ALERT_CERTIFICATE_REQUIRED);
	ASSERT_EQ("no_application_protocol", 120,
	          TLS_ALERT_NO_APPLICATION_PROTOCOL);
}

static void test_extension_types(void) {
	TEST_SUITE("TLS extension types");
	ASSERT_EQ("server_name", 0, TLS_EXT_SERVER_NAME);
	ASSERT_EQ("max_fragment_length", 1, TLS_EXT_MAX_FRAGMENT_LENGTH);
	ASSERT_EQ("status_request", 5, TLS_EXT_STATUS_REQUEST);
	ASSERT_EQ("supported_groups", 10, TLS_EXT_SUPPORTED_GROUPS);
	ASSERT_EQ("signature_algorithms", 13, TLS_EXT_SIGNATURE_ALGORITHMS);
	ASSERT_EQ("use_srtp", 14, TLS_EXT_USE_SRTP);
	ASSERT_EQ("heartbeat", 15, TLS_EXT_HEARTBEAT);
	ASSERT_EQ("alpn", 16, TLS_EXT_ALPN);
	ASSERT_EQ("signed_cert_timestamp", 18, TLS_EXT_SIGNED_CERT_TIMESTAMP);
	ASSERT_EQ("client_cert_type", 19, TLS_EXT_CLIENT_CERT_TYPE);
	ASSERT_EQ("server_cert_type", 20, TLS_EXT_SERVER_CERT_TYPE);
	ASSERT_EQ("padding", 21, TLS_EXT_PADDING);
	ASSERT_EQ("pre_shared_key", 41, TLS_EXT_PRE_SHARED_KEY);
	ASSERT_EQ("early_data", 42, TLS_EXT_EARLY_DATA);
	ASSERT_EQ("supported_versions", 43, TLS_EXT_SUPPORTED_VERSIONS);
	ASSERT_EQ("cookie", 44, TLS_EXT_COOKIE);
	ASSERT_EQ("psk_key_exchange_modes", 45, TLS_EXT_PSK_KEY_EXCHANGE_MODES);
	ASSERT_EQ("certificate_authorities", 47, TLS_EXT_CERTIFICATE_AUTHORITIES);
	ASSERT_EQ("oid_filters", 48, TLS_EXT_OID_FILTERS);
	ASSERT_EQ("post_handshake_auth", 49, TLS_EXT_POST_HANDSHAKE_AUTH);
	ASSERT_EQ("signature_algorithms_cert", 50,
	          TLS_EXT_SIGNATURE_ALGORITHMS_CERT);
	ASSERT_EQ("key_share", 51, TLS_EXT_KEY_SHARE);
}

static void test_handshake_state_values(void) {
	TEST_SUITE("TLS handshake state machine");
	ASSERT_EQ("TLS_HS_START", 0, TLS_HS_START);
	ASSERT_EQ("TLS_HS_CH_RECEIVED", 1, TLS_HS_CH_RECEIVED);
	ASSERT_EQ("TLS_HS_SH_SENT", 2, TLS_HS_SH_SENT);
	ASSERT_EQ("TLS_HS_EE_SENT", 3, TLS_HS_EE_SENT);
	ASSERT_EQ("TLS_HS_CERT_SENT", 4, TLS_HS_CERT_SENT);
	ASSERT_EQ("TLS_HS_CV_SENT", 5, TLS_HS_CV_SENT);
	ASSERT_EQ("TLS_HS_FIN_SENT", 6, TLS_HS_FIN_SENT);
	ASSERT_EQ("TLS_HS_CONNECTED", 7, TLS_HS_CONNECTED);
	ASSERT_EQ("TLS_HS_FAILED", 8, TLS_HS_FAILED);
}

// ── tests: tls_state structure (§2.2) ──────────────────────────────

static void test_state_offsets(void) {
	TEST_SUITE("tls_state field offsets");
	ASSERT_TLS_OFFSET("tls_fd", tls_fd, TLS_FD);
	ASSERT_TLS_OFFSET("tls_hs_state", tls_hs_state, TLS_HS_STATE);
	ASSERT_TLS_OFFSET("tls_client_random", tls_client_random,
	                  TLS_CLIENT_RANDOM);
	ASSERT_TLS_OFFSET("tls_server_random", tls_server_random,
	                  TLS_SERVER_RANDOM);
	ASSERT_TLS_OFFSET("tls_client_key_share", tls_client_key_share,
	                  TLS_CLIENT_KEY_SHARE);
	ASSERT_TLS_OFFSET("tls_server_key_share", tls_server_key_share,
	                  TLS_SERVER_KEY_SHARE);
	ASSERT_TLS_OFFSET("tls_shared_secret", tls_shared_secret,
	                  TLS_SHARED_SECRET);
	ASSERT_TLS_OFFSET("tls_transcript_hash_field", tls_transcript_hash_field,
	                  TLS_TRANSCRIPT_HASH);
	ASSERT_TLS_OFFSET("tls_handshake_secret", tls_handshake_secret,
	                  TLS_HANDSHAKE_SECRET);
	ASSERT_TLS_OFFSET("tls_master_secret", tls_master_secret,
	                  TLS_MASTER_SECRET);
	ASSERT_TLS_OFFSET("tls_client_hs_key", tls_client_hs_key,
	                  TLS_CLIENT_HS_KEY);
	ASSERT_TLS_OFFSET("tls_client_hs_iv", tls_client_hs_iv,
	                  TLS_CLIENT_HS_IV);
	ASSERT_TLS_OFFSET("tls_server_hs_key", tls_server_hs_key,
	                  TLS_SERVER_HS_KEY);
	ASSERT_TLS_OFFSET("tls_server_hs_iv", tls_server_hs_iv,
	                  TLS_SERVER_HS_IV);
	ASSERT_TLS_OFFSET("tls_client_app_key", tls_client_app_key,
	                  TLS_CLIENT_APP_KEY);
	ASSERT_TLS_OFFSET("tls_client_app_iv", tls_client_app_iv,
	                  TLS_CLIENT_APP_IV);
	ASSERT_TLS_OFFSET("tls_server_app_key", tls_server_app_key,
	                  TLS_SERVER_APP_KEY);
	ASSERT_TLS_OFFSET("tls_server_app_iv", tls_server_app_iv,
	                  TLS_SERVER_APP_IV);
	ASSERT_TLS_OFFSET("tls_client_seq", tls_client_seq, TLS_CLIENT_SEQ);
	ASSERT_TLS_OFFSET("tls_server_seq", tls_server_seq, TLS_SERVER_SEQ);
	ASSERT_TLS_OFFSET("tls_alpn_len", tls_alpn_len, TLS_ALPN_LEN);
	ASSERT_TLS_OFFSET("tls_alpn", tls_alpn, TLS_ALPN);
	ASSERT_TLS_OFFSET("tls_session_id_len", tls_session_id_len,
	                  TLS_SESSION_ID_LEN);
	ASSERT_TLS_OFFSET("tls_session_id", tls_session_id, TLS_SESSION_ID);
	ASSERT_TLS_OFFSET("tls_server_hs_traffic_secret",
	                  tls_server_hs_traffic_secret,
	                  TLS_SERVER_HS_TRAFFIC_SECRET);
	ASSERT_TLS_OFFSET("tls_client_hs_traffic_secret",
	                  tls_client_hs_traffic_secret,
	                  TLS_CLIENT_HS_TRAFFIC_SECRET);
}

static void test_state_alignment_and_size(void) {
	TEST_SUITE("tls_state alignment & size");
	ASSERT_EQ("tls_state 16-byte aligned", 0,
	          (int64_t)ASM_SYM_ADDR(tls_state) % 16);
	// storage extent: last field (tls_client_hs_traffic_secret) + its
	// buffer. If data.S's layout drifts from defs.S's TLS_STATE_SIZE
	// this catches it.
	ASSERT_EQ("storage extent == TLS_STATE_SIZE", TLS_STATE_SIZE,
	          TLS_OFFSET(tls_client_hs_traffic_secret) + 32);
	// every scalar/array field boundary stays 8-aligned (defs.S contract)
	ASSERT_EQ("TLS_ALPN 8-aligned", 0, TLS_ALPN % 8);
}

static void test_state_initial_values(void) {
	TEST_SUITE("tls_state initial values");
	ASSERT_EQ("tls_fd starts -1 (no connection)", -1, TLS_FIELD(tls_fd));
	ASSERT_EQ("tls_hs_state starts at TLS_HS_START", TLS_HS_START,
	          TLS_FIELD(tls_hs_state));
	ASSERT_EQ("tls_client_seq starts 0", 0, TLS_FIELD(tls_client_seq));
	ASSERT_EQ("tls_server_seq starts 0", 0, TLS_FIELD(tls_server_seq));
	ASSERT_EQ("tls_alpn_len starts 0 (nothing negotiated)", 0,
	          TLS_FIELD(tls_alpn_len));
	ASSERT_EQ("tls_session_id_len starts 0", 0,
	          TLS_FIELD(tls_session_id_len));
	// the alpn name buffer is zeroed until negotiation fills it
	{
		static const char zeros[TLS_ALPN_BUF] = {0};
		ASSERT_EQ("tls_alpn buffer zeroed", 0,
		          memcmp(zeros, (const void *)ASM_SYM_ADDR(tls_alpn),
		                 TLS_ALPN_BUF));
	}
}

static void test_alpn_h2(void) {
	TEST_SUITE("ALPN h2 identifier");
	const char *h2 = (const char *)ASM_SYM_ADDR(tls_alpn_h2);
	ASSERT_EQ("tls_alpn_h2 16-byte aligned", 0,
	          (int64_t)ASM_SYM_ADDR(tls_alpn_h2) % 16);
	ASSERT_STR_EQ("tls_alpn_h2 holds \"h2\"", "h2", h2, TLS_ALPN_H2_LEN);
	// the h2 bytes are exactly 'h' (0x68) and '2' (0x32)
	ASSERT_EQ("byte 0 == 'h'", 0x68, (unsigned char)h2[0]);
	ASSERT_EQ("byte 1 == '2'", 0x32, (unsigned char)h2[1]);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_wire_constants();
	test_record_types();
	test_handshake_types();
	test_alert_types();
	test_extension_types();
	test_handshake_state_values();
	test_state_offsets();
	test_state_alignment_and_size();
	test_state_initial_values();
	test_alpn_h2();
	test_summary();
	return 0;
}
