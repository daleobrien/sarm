// Unit tests for src/h2/ — Stage 9: the first working HTTP/2 GET.
// h2_process_request runs the common request through the existing
// resource handler; h2_write_headers / h2_write_body emit the HEADERS
// and DATA frames; h2_connection_loop drives the full preface + frame
// receive loop, including the Stage 14 partial-preface hand-off where
// 10 probe-buffered preface bytes reach the loop before the rest.

#include "test_h2_common.h"

static void test_h2_write_headers(void) {
	TEST_SUITE("9.2 h2_write_headers — HEADERS frame (200, content-type, content-length)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;        // RES_NONE — no content-encoding
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello</h1>";
	response_t resp = {
		.status = 200,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 1, 0);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x88 | 0x0f 0x10 0x18 ct | 0x0f 0x0d 0x02 "14" → 33 bytes
	// (content-type = static 31, content-length = static 28 — both need
	// the two-octet 4-bit-prefix name index)
	// frame: 9-byte header (len 33, HEADERS, END_HEADERS, stream 1) + block
	uint8_t expect[] = {
		0x00, 0x00, 0x21, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x88,
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '4',
	};
	ASSERT_EQ("42 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

static void test_h2_write_headers_gzip(void) {
	TEST_SUITE("9.2 h2_write_headers — content-encoding: gzip for gzipped assets");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 1;        // RES_EMBEDDED
	embedded_gzip = 1;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello</h1>";
	response_t resp = {
		.status = 200,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 1, 0);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x88 | ct | content-length | 0x0f 0x0b 0x04 "gzip" → 40 bytes
	uint8_t expect[] = {
		0x00, 0x00, 0x28, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x88,
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '4',
		0x0f, 0x0b, 0x04, 'g', 'z', 'i', 'p',
	};
	ASSERT_EQ("49 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the gzip HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

static void test_h2_write_headers_404(void) {
	TEST_SUITE("9.2 h2_write_headers — 404 (literal :status, END_STREAM)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	response_t resp = {
		.status = 404,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = 0,
		.body = 0,
		.body_length = 0,
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 3, H2_FLAG_END_STREAM);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[128];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x08 0x03 "404" | 0x0f 0x0d 0x01 "0" → 9 bytes
	// (content-length = static 28, the two-octet 4-bit-prefix name index)
	uint8_t expect[] = {
		0x00, 0x00, 0x09, 0x01, 0x05, 0x00, 0x00, 0x00, 0x03,
		0x08, 0x03, '4', '0', '4',
		0x0f, 0x0d, 0x01, '0',
	};
	ASSERT_EQ("18 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected 404 HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

static void test_h2_write_body(void) {
	TEST_SUITE("9.3 h2_write_body — single DATA frame + END_STREAM");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	static const char body[] = "hello world";
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[128];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	uint8_t expect[] = {
		0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // DATA len=11 END_STREAM
		'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd',
	};
	ASSERT_EQ("20 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected DATA frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

static void test_h2_write_body_chunked(void) {
	TEST_SUITE("9.3 h2_write_body — multi-frame DATA (max frame size)");

	static uint8_t big[H2_DEFAULT_MAX_FRAME_SIZE + 100];
	memset(big, 'a', sizeof(big));

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = (int64_t)sizeof(big),
		.body = (const char *)big,
		.body_length = (int64_t)sizeof(big),
		.range_start = -1,
		.range_end = -1,
	};

	int pid = fork();
	if (pid == 0) {
		// ── reader/verifier side ──
		close(sv[1]);
		uint8_t got[H2_DEFAULT_MAX_FRAME_SIZE + 128];
		long n = 0;
		while (n < (long)sizeof(got)) {
			long r = read(sv[0], got + n, (unsigned long)(sizeof(got) - n));
			if (r <= 0) break;
			n += r;
		}
		close(sv[0]);

		long total = (long)(2 * H2_WIRE_HEADER_LEN + sizeof(big));
		if (n != total) _exit(1);

		// frame 1 — the full max frame (16384 = 0x4000), no END_STREAM
		if ((((uint32_t)got[0] << 16) | ((uint32_t)got[1] << 8) | got[2]) != 0x4000)
			_exit(2);
		if (got[3] != H2_FRAME_DATA || got[4] != 0) _exit(3);
		if ((((uint32_t)got[5] << 24) | ((uint32_t)got[6] << 16) |
		     ((uint32_t)got[7] << 8) | got[8]) != 1) _exit(4);
		if (got[9] != 'a' || got[9 + H2_DEFAULT_MAX_FRAME_SIZE - 1] != 'a') _exit(5);

		// frame 2 — the 100-byte remainder, END_STREAM
		long off = H2_WIRE_HEADER_LEN + H2_DEFAULT_MAX_FRAME_SIZE;
		if ((((uint32_t)got[off + 0] << 16) | ((uint32_t)got[off + 1] << 8) |
		     got[off + 2]) != 100) _exit(6);
		if (got[off + 3] != H2_FRAME_DATA ||
		    got[off + 4] != H2_FLAG_END_STREAM) _exit(7);
		if ((((uint32_t)got[off + 5] << 24) | ((uint32_t)got[off + 6] << 16) |
		     ((uint32_t)got[off + 7] << 8) | got[off + 8]) != 1) _exit(8);
		if (got[off + 9] != 'a') _exit(9);
		_exit(0);
	}

	// ── writer side ──
	close(sv[0]);
	int64_t carry = h2_write_body_wrapper(sv[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(sv[1]);
	int status = 0;
	waitpid(pid, &status, 0);

	ASSERT_EQ("reader verified two DATA frames + END_STREAM", 0,
	          (status >> 8) & 0xff);
}

static void test_h2_process_request(void) {
	TEST_SUITE("9.1 h2_process_request — common request → existing resource handler");

	reset_streams();
	reset_fields();
	reset_conn(h2_conn_addr());

	// a request stream: IDLE → OPEN → HALF_CLOSED_REMOTE (HEADERS + END_STREAM)
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_NOT_NULL("stream created", s);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry);
	ASSERT_EQ("headers event ok", 0, carry);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry);
	ASSERT_EQ("end_stream event ok", 0, carry);
	ASSERT_EQ("stream is HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s->state);

	// build the request: GET /index.html
	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	set_fields(f, 2);
	ASSERT_EQ("request built", 0, h2_build_request_wrapper(1, 2, &carry));

	// serve it through a pipe and capture the response frames
	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	ASSERT_EQ("process succeeds", 0, h2_process_request_wrapper(1, fds[1], &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream moved to CLOSED", H2_STREAM_CLOSED, s->state);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// HEADERS (9) + block (33) = 42, DATA (9 + 17) = 26 → 68 total
	ASSERT_EQ("68 response bytes", 68, n);

	// HEADERS frame: len=0x21 (33), END_HEADERS, stream 1
	ASSERT_EQ("headers length", 0x21,
	          ((uint32_t)got[0] << 16) | ((uint32_t)got[1] << 8) | got[2]);
	ASSERT_EQ("headers type", H2_FRAME_HEADERS, got[3]);
	ASSERT_EQ("headers flags", H2_FLAG_END_HEADERS, got[4]);
	ASSERT_EQ("headers stream", 1,
	          ((uint32_t)got[5] << 24) | ((uint32_t)got[6] << 16) |
	          ((uint32_t)got[7] << 8) | got[8]);
	// HPACK block: :status 200 indexed, content-type (static 31),
	// content-length (static 28) — both two-octet 4-bit-prefix indices
	ASSERT_EQ(":status 200 indexed", 0x88, got[9]);
	ASSERT_EQ("content-type name idx", 0x0f, got[10]);
	ASSERT_EQ("content-type name idx cont", 0x10, got[11]);
	ASSERT_EQ("content-type len", 24, got[12]);
	ASSERT_STR_EQ("content-type value", "text/html; charset=utf-8",
	              got + 13, 24);
	ASSERT_EQ("content-length name idx", 0x0f, got[37]);
	ASSERT_EQ("content-length name idx cont", 0x0d, got[38]);
	ASSERT_EQ("content-length len", 2, got[39]);
	ASSERT_STR_EQ("content-length value", "17", got + 40, 2);

	// DATA frame: len=17, END_STREAM, stream 1, the stub's body
	ASSERT_EQ("data length", 17,
	          ((uint32_t)got[42] << 16) | ((uint32_t)got[43] << 8) | got[44]);
	ASSERT_EQ("data type", H2_FRAME_DATA, got[45]);
	ASSERT_EQ("data flags", H2_FLAG_END_STREAM, got[46]);
	ASSERT_EQ("data stream", 1,
	          ((uint32_t)got[47] << 24) | ((uint32_t)got[48] << 16) |
	          ((uint32_t)got[49] << 8) | got[50]);
	ASSERT_STR_EQ("body", "<h1>hello h2</h1>", got + 51, 17);
}

static void test_h2_connection_loop(void) {
	TEST_SUITE("9.4 h2_connection_loop — preface + SETTINGS + HEADERS + DATA");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side ──
		close(sv[0]);
		uint8_t out[128], in[256];
		long out_len = 0;

		// the 24-byte connection preface
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		// client SETTINGS — empty payload, stream 0
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// HEADERS — the exact block curl 8.7.1 sent for GET / (captured
		// on the wire): indexed :method GET / :scheme http, a Huffman-
		// coded :authority, indexed :path /, an incremental-indexed
		// Huffman user-agent, and a plain accept — the full set of
		// representations a real client uses
		static const uint8_t block[] = {
			0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70,
			0xdc, 0x78, 0x20, 0x07, 0x84, 0x7a, 0x88, 0x25, 0xb6, 0x50,
			0xc3, 0xcb, 0xba, 0xb8, 0x7f, 0x53, 0x03, 0x2a, 0x2f, 0x2a,
		};
		put_wire_header(out + out_len, (uint32_t)sizeof(block), H2_FRAME_HEADERS,
		                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		out_len += H2_WIRE_HEADER_LEN;
		memcpy(out + out_len, block, sizeof(block));
		out_len += (long)sizeof(block);

		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(1);
			w += r;
		}
		// read the full response: SETTINGS (21) + HEADERS (42) + DATA (26)
		long n = 0;
		while (n < 89) {
			long r = read(sv[1], in + n, (unsigned long)(89 - n));
			if (r <= 0) break;
			n += r;
		}
		if (n != 89) _exit(2);
		// server SETTINGS: len=12, type=4, stream=0
		if (in[0] != 0 || in[1] != 0 || in[2] != 12 ||
		    in[3] != H2_FRAME_SETTINGS || in[4] != 0 ||
		    in[5] != 0 || in[6] != 0 || in[7] != 0 || in[8] != 0)
			_exit(3);
		// entry 1: SETTINGS_HEADER_TABLE_SIZE = 4096 (protocol default)
		if (in[9] != 0 || in[10] != H2_SETTINGS_HEADER_TABLE_SIZE ||
		    in[11] != 0 || in[12] != 0 || in[13] != 0x10 || in[14] != 0)
			_exit(4);
		// entry 2: SETTINGS_MAX_CONCURRENT_STREAMS = 32
		if (in[15] != 0 || in[16] != H2_SETTINGS_MAX_CONCURRENT_STREAMS ||
		    in[17] != 0 || in[18] != 0 || in[19] != 0 || in[20] != 0x20)
			_exit(9);
		// HEADERS: len=0x21 (33), type=1, flags=END_HEADERS, stream=1
		if (in[21] != 0 || in[22] != 0 || in[23] != 0x21 ||
		    in[24] != H2_FRAME_HEADERS || in[25] != H2_FLAG_END_HEADERS ||
		    in[26] != 0 || in[27] != 0 || in[28] != 0 || in[29] != 1)
			_exit(5);
		// HPACK block: 0x88 | 0x0f 0x10 0x18 ct | 0x0f 0x0d 0x02 "17"
		if (in[30] != 0x88 || in[31] != 0x0f || in[32] != 0x10 ||
		    in[33] != 0x18 ||
		    memcmp(in + 34, "text/html; charset=utf-8", 24) != 0 ||
		    in[58] != 0x0f || in[59] != 0x0d || in[60] != 0x02 ||
		    in[61] != '1' || in[62] != '7')
			_exit(6);
		// DATA: len=17, type=0, flags=END_STREAM, stream=1, body
		if (in[63] != 0 || in[64] != 0 || in[65] != 17 ||
		    in[66] != H2_FRAME_DATA || in[67] != H2_FLAG_END_STREAM ||
		    in[68] != 0 || in[69] != 0 || in[70] != 0 || in[71] != 1)
			_exit(7);
		if (memcmp(in + 72, "<h1>hello h2</h1>", 17) != 0)
			_exit(8);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: run the loop with no pre-buffered bytes ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);

	// the child's exit code doubles as the verification result
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client verified preface + SETTINGS + HEADERS + DATA", 0, exit_code);
}

static void test_h2_connection_loop_partial_preface(void) {
	TEST_SUITE("14.2 h2_connection_loop — 10 pre-buffered preface bytes + socket");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side: the preface arrives in two fragments ──
		close(sv[0]);
		uint8_t out[128], in[128];
		long out_len = 0;

		// fragment 1: the first 10 bytes — what the main loop's first
		// read() buffered before the probe fired
		if (write(sv[1], H2_PREFACE, 10) != 10) _exit(1);
		usleep(20000); // 20ms — the server is blocked reading the rest

		// fragment 2: the remaining preface + client SETTINGS + HEADERS
		memcpy(out + out_len, H2_PREFACE + 10, H2_PREFACE_LEN - 10);
		out_len += H2_PREFACE_LEN - 10;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		out_len += put_request_headers(out + out_len, "/", 1,
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(2);
			w += r;
		}

		// the same 89-byte response as the unfragmented loop:
		// SETTINGS (21) + HEADERS (42) + DATA (26, "<h1>hello h2</h1>")
		long n = 0;
		while (n < 89) {
			long r = read(sv[1], in + n, (unsigned long)(89 - n));
			if (r <= 0) break;
			n += r;
		}
		if (n != 89) _exit(3);
		if (in[0] != 0 || in[1] != 0 || in[2] != 12 ||
		    in[3] != H2_FRAME_SETTINGS || in[4] != 0) _exit(4);
		if (in[24] != H2_FRAME_HEADERS || in[29] != 1) _exit(5);
		if (in[66] != H2_FRAME_DATA || in[71] != 1) _exit(6);
		if (memcmp(in + 72, "<h1>hello h2</h1>", 17) != 0) _exit(7);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: consume the first 10 bytes like the main loop's ──
	// first read(), then hand the buffer + count to the connection loop
	close(sv[1]);
	uint8_t in[512];
	long n0 = 0;
	while (n0 < 10) {
		long r = read(sv[0], in + n0, (unsigned long)(10 - n0));
		if (r <= 0) break;
		n0 += r;
	}
	if (n0 != 10) {
		printf("  ✗ server's first read() did not get the 10 preface bytes\n");
		exit(2);
	}
	h2_connection_loop_wrapper(sv[0], in, 10);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);

	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("partial preface (10 buffered + 14 from socket) served", 0, exit_code);
}

int main(void) {
	test_h2_write_headers();
	test_h2_write_headers_gzip();
	test_h2_write_headers_404();
	test_h2_write_body();
	test_h2_write_body_chunked();
	test_h2_process_request();
	test_h2_connection_loop();
	test_h2_connection_loop_partial_preface();
	test_summary();
	return 0;
}
