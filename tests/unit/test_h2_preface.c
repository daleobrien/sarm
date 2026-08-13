// Unit tests for src/http2.S — Stage 5 (connection preface) and the
// Stage 14 protocol-detection probe (h2_probe).
// h2_verify_preface reads exactly 24 bytes and compares them with the
// HTTP/2 preface (RFC 9113 §3.4), flipping connection_mode;
// h2_send_settings emits the server's opening SETTINGS frame (§3.5),
// captured over a real socketpair and verified byte-for-byte.
// h2_probe (Stage 14) reads the first bytes of a connection and
// decides HTTP/1 vs HTTP/2 without consuming or altering the bytes.

#include "test_h2_common.h"

static void test_connection_mode_default(void) {
	TEST_SUITE("connection_mode — 5.1 default is HTTP/1");

	// HTTP/1 is the default; nothing in the server changes that unless
	// the HTTP/2 preface is verified, so existing HTTP/1 connections are
	// untouched.
	ASSERT_EQ("connection_mode defaults to CONNECTION_HTTP1",
	          CONNECTION_HTTP1, connection_mode_value());
}

static void test_h2_preface_verify(void) {
	TEST_SUITE("h2_verify_preface — 3.4 correct preface");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN + 8];
	int64_t carry;

	// correct preface, single write
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN);
	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("correct preface → CONNECTION_HTTP2", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("connection_mode flipped to HTTP/2", CONNECTION_HTTP2,
	          connection_mode_value());

	// correct preface arriving as partial reads (10 + 14)
	set_connection_mode(CONNECTION_HTTP1);
	write(sv[0], H2_PREFACE, 10);
	write(sv[0], H2_PREFACE + 10, 14);
	ASSERT_EQ("preface across two writes still verifies", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	close(sv[0]);
	close(sv[1]);
}

static void test_h2_preface_partial_reads(void) {
	TEST_SUITE("h2_verify_preface — read exactly 24 bytes across partial reads");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	write(sv[0], H2_PREFACE, 10);
	int pid = fork();
	if (pid == 0) {
		// child: deliver the rest once the parent is blocked in read()
		usleep(50000); // 50ms
		write(sv[0], H2_PREFACE + 10, 14);
		_exit(0);
	}

	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("10 + 14 byte deliveries verify", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	int status;
	waitpid(pid, &status, 0);
	close(sv[0]);
	close(sv[1]);
}

static void test_h2_preface_rejected(void) {
	TEST_SUITE("h2_verify_preface — 3.4 incorrect preface rejected");

	int sv[2];
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	// 24 bytes that are not the preface
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	for (int i = 0; i < H2_PREFACE_LEN; i++)
		buf[i] = (uint8_t)('A' + i);
	write(sv[0], buf, H2_PREFACE_LEN);
	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("garbage → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set (connection rejected)", 1, carry);
	ASSERT_EQ("mode stays HTTP/1", CONNECTION_HTTP1, connection_mode_value());
	close(sv[0]);
	close(sv[1]);

	// a near-miss: identical except the final byte — every word compare
	// must hold for the preface to verify
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN - 1);
	uint8_t bad = 0x41; // 'A' instead of '\n'
	write(sv[0], &bad, 1);
	ASSERT_EQ("last byte wrong → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set", 1, carry);
	close(sv[0]);
	close(sv[1]);

	// EOF before the preface completes
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	close(sv[0]); // peer closes without sending anything
	ASSERT_EQ("EOF → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set", 1, carry);
	close(sv[1]);

	// a read() failure (fd already closed → EBADF) rejects too
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	close(sv[1]); // now sv[1] is not an open fd
	set_connection_mode(CONNECTION_HTTP1);
	int64_t rc = h2_verify_preface_wrapper(sv[1], buf, &carry);
	ASSERT_EQ("read error → errno EBADF", 9, rc);
	ASSERT_EQ("carry set (connection rejected)", 1, carry);
	ASSERT_EQ("mode stays HTTP/1", CONNECTION_HTTP1, connection_mode_value());
	close(sv[0]);
}

static void test_h2_send_settings(void) {
	TEST_SUITE("h2_send_settings — 3.5 opening SETTINGS frame");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	// full flow: client preface → verified → server sends SETTINGS
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN);
	ASSERT_EQ("preface verified", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("settings sent — 21 bytes written", 21,
	          h2_send_settings_wrapper(sv[1], &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// capture the frame from the client side and check every header field
	uint8_t frame[21];
	long n = read(sv[0], frame, 21);
	ASSERT_EQ("21-byte frame captured", 21, n);

	uint32_t length = ((uint32_t)frame[0] << 16) |
	                  ((uint32_t)frame[1] << 8) | frame[2];
	ASSERT_EQ("payload length = 12 (two SETTINGS entries)", 12, length);
	ASSERT_EQ("type = SETTINGS", H2_FRAME_SETTINGS, frame[3]);
	ASSERT_EQ("flags = 0", 0, frame[4]);
	uint32_t stream = ((uint32_t)frame[5] << 24) |
	                  ((uint32_t)frame[6] << 16) |
	                  ((uint32_t)frame[7] << 8) | frame[8];
	ASSERT_EQ("stream id = 0", 0, stream);

	// entry 1: SETTINGS_HEADER_TABLE_SIZE = 0 (dynamic table off)
	uint32_t id = ((uint32_t)frame[9] << 8) | frame[10];
	ASSERT_EQ("entry id = SETTINGS_HEADER_TABLE_SIZE",
	          H2_SETTINGS_HEADER_TABLE_SIZE, id);
	uint32_t value = ((uint32_t)frame[11] << 24) | ((uint32_t)frame[12] << 16) |
	                 ((uint32_t)frame[13] << 8) | frame[14];
	ASSERT_EQ("entry value = 0 (dynamic table disabled)", 0, value);

	// entry 2: SETTINGS_MAX_CONCURRENT_STREAMS = 32 (Stage 12)
	id = ((uint32_t)frame[15] << 8) | frame[16];
	ASSERT_EQ("entry id = SETTINGS_MAX_CONCURRENT_STREAMS",
	          H2_SETTINGS_MAX_CONCURRENT_STREAMS, id);
	value = ((uint32_t)frame[17] << 24) | ((uint32_t)frame[18] << 16) |
	        ((uint32_t)frame[19] << 8) | frame[20];
	ASSERT_EQ("entry value = 32 (MAX_CONCURRENT_STREAMS)",
	          MAX_CONCURRENT_STREAMS, value);

	// the captured frame matches the asm constant byte-for-byte
	ASSERT_STR_EQ("frame matches h2_settings_frame constant",
	              h2_settings_frame_addr(), frame, 21);

	close(sv[0]);
	close(sv[1]);
}

static void test_h2_preface_constant(void) {
	TEST_SUITE("h2_preface constant — byte-for-byte (3.4)");

	const uint8_t *p = h2_preface_addr();
	ASSERT_STR_EQ("matches the spec string", H2_PREFACE, p, H2_PREFACE_LEN);
}

static void test_h2_probe(void) {
	TEST_SUITE("h2_probe — HTTP/2 preface detection (Phase 16 Option B)");

	ASSERT_EQ("full preface", 1, h2_probe_wrapper(H2_PREFACE, H2_PREFACE_LEN));
	ASSERT_EQ("partial preface (10 bytes)", 1, h2_probe_wrapper(H2_PREFACE, 10));
	ASSERT_EQ("preface + extra bytes", 1,
	          h2_probe_wrapper(H2_PREFACE, H2_PREFACE_LEN + 1));
	static const char get[] = "GET / HTTP/1.1\r\n";
	ASSERT_EQ("HTTP/1 GET rejected", 0,
	          h2_probe_wrapper((const uint8_t *)get, LITLEN(get)));
	ASSERT_EQ("empty buffer rejected", 0, h2_probe_wrapper(H2_PREFACE, 0));
}

static void test_h2_probe_prefixes(void) {
	TEST_SUITE("14.1 h2_probe — every preface prefix detected, deviations rejected");

	int ok = 1;
	for (int k = 1; k <= H2_PREFACE_LEN; k++)
		ok &= (h2_probe_wrapper(H2_PREFACE, k) == 1);
	ASSERT_EQ("every 1..24-byte preface prefix detected", 1, ok);

	ok = 1;
	uint8_t bad[H2_PREFACE_LEN];
	for (int i = 0; i < H2_PREFACE_LEN; i++) {
		memcpy(bad, H2_PREFACE, H2_PREFACE_LEN);
		bad[i] ^= 0xff;             // flip one byte at position i
		ok &= (h2_probe_wrapper(bad, H2_PREFACE_LEN) == 0);
	}
	ASSERT_EQ("single-byte deviation at every position rejected", 1, ok);

	// a wrong minor version is not the HTTP/2 preface
	static const char h21[] = "PRI * HTTP/2.1\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ("HTTP/2.1 preface rejected", 0,
	          h2_probe_wrapper((const uint8_t *)h21, LITLEN(h21)));

	// common HTTP/1 requests are never mistaken for the preface
	static const char *reqs[] = {
		"GET / HTTP/1.1\r\n",
		"HEAD / HTTP/1.1\r\n",
		"POST / HTTP/1.1\r\n",
		"OPTIONS / HTTP/1.1\r\n",
		"PUT / HTTP/1.1\r\n",
		"DELETE / HTTP/1.1\r\n",
	};
	ok = 1;
	for (int i = 0; i < 6; i++)
		ok &= (h2_probe_wrapper((const uint8_t *)reqs[i], LITLEN(reqs[i])) == 0);
	ASSERT_EQ("common HTTP/1 requests rejected", 1, ok);
}

static void test_h2_probe_preserves(void) {
	TEST_SUITE("14.2 h2_probe — buffer preserved byte-for-byte (HTTP/1 sees all bytes)");

	uint8_t buf[64];
	memcpy(buf, H2_PREFACE, H2_PREFACE_LEN);
	ASSERT_EQ("HTTP/2 preface detected", 1,
	          h2_probe_wrapper(buf, H2_PREFACE_LEN));
	ASSERT_TRUE("preface buffer unchanged by the probe",
	            memcmp(buf, H2_PREFACE, H2_PREFACE_LEN) == 0);

	static const char get[] = "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
	memcpy(buf, get, LITLEN(get));
	ASSERT_EQ("HTTP/1 request rejected by the probe", 0,
	          h2_probe_wrapper(buf, LITLEN(get)));
	ASSERT_TRUE("HTTP/1 buffer unchanged by the probe",
	            memcmp(buf, get, (unsigned long)LITLEN(get)) == 0);

	// the same buffer, byte-for-byte, is what the HTTP/1 parser sees
	ASSERT_EQ("probed buffer still parses as HTTP/1", 0,
	          parse_request_wrapper((const char *)buf, LITLEN(get)));
}

int main(void) {
	test_connection_mode_default();
	test_h2_preface_verify();
	test_h2_preface_partial_reads();
	test_h2_preface_rejected();
	test_h2_send_settings();
	test_h2_preface_constant();
	test_h2_probe();
	test_h2_probe_prefixes();
	test_h2_probe_preserves();
	test_summary();
	return 0;
}
