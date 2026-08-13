// Unit tests for src/http2.S — Stage 11: DATA flow control
// (RFC 9113 §5.2, §6.9). The connection window (h2_conn) and stream
// window (h2_streams entry) start at 65535, every DATA send drains
// both, h2_handle_window_update replenishes them (rejecting bad
// lengths, zero increments, idle streams and over-2^31 windows), and
// h2_write_body pauses for WINDOW_UPDATE when credit runs out — so a
// file larger than the window (70000-byte www/big.bin stub) delivers
// end-to-end.

#include "test_h2_common.h"

static void test_h2_flow_conn_window(void) {
	TEST_SUITE("11.1 connection window — DATA send drains it");

	reset_conn(h2_conn_addr());
	reset_streams();

	static const char body[] = "flow control body";
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

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	int64_t carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(fds[1]);
	uint8_t drain[128];
	while (read(fds[0], drain, sizeof(drain)) > 0) ;
	close(fds[0]);

	ASSERT_EQ("connection window drained by the body",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), h2_conn_addr()->window);
}

static void test_h2_flow_stream_window(void) {
	TEST_SUITE("11.2 stream window — DATA send drains both windows");

	reset_conn(h2_conn_addr());
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_EQ("stream created", 0, carry);
	ASSERT_EQ("stream window starts at 65535", H2_DEF_INITIAL_WINDOW_SIZE,
	          s->window);

	static const char body[] = "flow control body";
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

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(fds[1]);
	uint8_t drain[128];
	while (read(fds[0], drain, sizeof(drain)) > 0) ;
	close(fds[0]);

	ASSERT_EQ("connection window drained",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), h2_conn_addr()->window);
	ASSERT_EQ("stream window drained",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), s->window);
}

static void test_h2_flow_window_update(void) {
	TEST_SUITE("11.3 h2_handle_window_update — §6.9 credit replenishment");

	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, &conn, &carry);
	ASSERT_EQ("stream created", 0, carry);

	uint8_t payload[4];
	h2_frame_header_t hdr;
	hdr.type = H2_FRAME_WINDOW_UPDATE;
	hdr.flags = 0;

	// stream 0 → the connection window
	hdr.length = 4;
	hdr.stream_id = 0;
	payload[0] = 0x00; payload[1] = 0x00; payload[2] = 0x03; payload[3] = 0xe8; // +1000
	ASSERT_EQ("conn window update ok", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("connection window +1000", H2_DEF_INITIAL_WINDOW_SIZE + 1000,
	          conn.window);

	// stream 1 → the stream window
	hdr.stream_id = 1;
	payload[2] = 0x01; payload[3] = 0xf4; // +500
	ASSERT_EQ("stream window update ok", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream window +500", H2_DEF_INITIAL_WINDOW_SIZE + 500, s->window);

	// an increment of 0 → PROTOCOL_ERROR
	hdr.stream_id = 0;
	payload[2] = 0x00; payload[3] = 0x00;
	ASSERT_EQ("zero increment → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// a length other than 4 → FRAME_SIZE_ERROR
	hdr.length = 2;
	ASSERT_EQ("bad length → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// an update that would push a window past 2^31-1 → FLOW_CONTROL_ERROR.
	// conn.window is 66535; 0x7fffffff more overshoots the ceiling.
	hdr.length = 4;
	hdr.stream_id = 0;
	payload[0] = 0x7f; payload[1] = 0xff; payload[2] = 0xff; payload[3] = 0xff;
	ASSERT_EQ("window overflow → FLOW_CONTROL_ERROR", H2_ERR_FLOW_CONTROL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// an idle stream (never created) → PROTOCOL_ERROR
	hdr.stream_id = 5;
	payload[0] = 0x00; payload[1] = 0x00; payload[2] = 0x00; payload[3] = 0x64;
	ASSERT_EQ("idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// RST_STREAM closes stream 1 (after moving it to OPEN — a reset on an
	// idle stream is itself a PROTOCOL_ERROR, §5.1); a WINDOW_UPDATE on it
	// is then ignored, not an error, and the window is untouched
	h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry);
	ASSERT_EQ("stream opened", H2_STREAM_OPEN, s->state);
	hdr.type = H2_FRAME_RST_STREAM;
	hdr.length = 4;
	hdr.stream_id = 1;
	uint8_t rst[4] = { 0, 0, 0, H2_ERR_CANCEL };
	ASSERT_EQ("RST_STREAM ok", 0, h2_dispatch_wrapper(&hdr, rst, &conn, &carry));
	ASSERT_EQ("stream closed", H2_STREAM_CLOSED, s->state);

	hdr.type = H2_FRAME_WINDOW_UPDATE;
	hdr.stream_id = 1;
	uint8_t wu[4] = { 0, 0, 0x00, 0x64 };
	ASSERT_EQ("closed stream update ignored", 0,
	          h2_dispatch_wrapper(&hdr, wu, &conn, &carry));
	ASSERT_EQ("stream window unchanged", H2_DEF_INITIAL_WINDOW_SIZE + 500,
	          s->window);
}

static void test_h2_flow_resume(void) {
	TEST_SUITE("11.3 transmission resumes after WINDOW_UPDATE");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side: grant credit, then read the body ──
		close(sv[0]);
		uint8_t out[64];
		long out_len = 0;
		// stream 1 WINDOW_UPDATE +2000
		put_wire_header(out + out_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 1);
		out_len += H2_WIRE_HEADER_LEN;
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x07; out[out_len++] = 0xd0;
		// connection WINDOW_UPDATE +2000
		put_wire_header(out + out_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x07; out[out_len++] = 0xd0;
		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(1);
			w += r;
		}
		// the resumed body — one DATA frame, END_STREAM, stream 1
		uint8_t in[64];
		long n = 0;
		while (n < H2_WIRE_HEADER_LEN) {
			long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
			if (r <= 0) _exit(2);
			n += r;
		}
		long len = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
		if (len != 20) _exit(3);
		if (in[3] != H2_FRAME_DATA) _exit(4);
		if ((in[4] & H2_FLAG_END_STREAM) == 0) _exit(5);
		if ((((uint32_t)in[5] << 24) | ((uint32_t)in[6] << 16) |
		     ((uint32_t)in[7] << 8) | in[8]) != 1) _exit(6);
		n = 0;
		while (n < len) {
			long r = read(sv[1], in + n, (unsigned long)(len - n));
			if (r <= 0) _exit(7);
			n += r;
		}
		if (memcmp(in, "flow control resumes", 20) != 0) _exit(8);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: both windows at 0, then write the body ──
	close(sv[1]);
	reset_conn(h2_conn_addr());
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_EQ("stream created", 0, carry);
	h2_conn_addr()->window = 0;
	s->window = 0;

	static const char body[] = "flow control resumes";
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

	carry = h2_write_body_wrapper(sv[0], &resp, 1);
	ASSERT_EQ("writer resumed and completed", 0, carry);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client received the resumed body", 0, exit_code);
	// 2000 granted − 20 sent on each window
	ASSERT_EQ("connection window after send", 2000 - LITLEN(body),
	          h2_conn_addr()->window);
	ASSERT_EQ("stream window after send", 2000 - LITLEN(body), s->window);
}

static void test_h2_flow_large_file(void) {
	TEST_SUITE("11.4 large file (> initial window) — complete, no deadlock");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side ──
		close(sv[0]);
		uint8_t out[256], in[70000 + 32];
		long out_len = 0;
		// preface + client SETTINGS + HEADERS (GET /big.bin)
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// HPACK block: :method GET (0x82) + literal :path /big.bin
		static const uint8_t block[] = {
			0x82, 0x04, 0x08, '/', 'b', 'i', 'g', '.', 'b', 'i', 'n',
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

		// the server's opening SETTINGS (21 bytes) — read, then skip
		long n = 0;
		while (n < 21) {
			long r = read(sv[1], in + n, (unsigned long)(21 - n));
			if (r <= 0) _exit(2);
			n += r;
		}
		// the HEADERS frame header, then skip its HPACK payload
		n = 0;
		while (n < H2_WIRE_HEADER_LEN) {
			long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
			if (r <= 0) _exit(3);
			n += r;
		}
		if (in[3] != H2_FRAME_HEADERS) _exit(4);
		long hlen = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
		n = 0;
		while (n < hlen) {
			long r = read(sv[1], in, (unsigned long)hlen);
			if (r <= 0) _exit(5);
			n += r;
		}

		// DATA loop: top the windows up before they run dry, then read
		long stream_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long conn_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long total = 0, len = 0;
		int done = 0, nframes = 0;
		while (!done) {
			while (stream_credit < H2_DEFAULT_MAX_FRAME_SIZE ||
			       conn_credit < H2_DEFAULT_MAX_FRAME_SIZE) {
				// replenish both windows by the initial amount
				uint8_t wu[26];
				long wu_len = 0;
				put_wire_header(wu + wu_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 1);
				wu_len += H2_WIRE_HEADER_LEN;
				wu[wu_len++] = 0x00; wu[wu_len++] = 0x00;
				wu[wu_len++] = 0xff; wu[wu_len++] = 0xff;
				put_wire_header(wu + wu_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
				wu_len += H2_WIRE_HEADER_LEN;
				wu[wu_len++] = 0x00; wu[wu_len++] = 0x00;
				wu[wu_len++] = 0xff; wu[wu_len++] = 0xff;
				long w2 = 0;
				while (w2 < wu_len) {
					long r = write(sv[1], wu + w2, (unsigned long)(wu_len - w2));
					if (r <= 0) _exit(6);
					w2 += r;
				}
				stream_credit += H2_DEF_INITIAL_WINDOW_SIZE;
				conn_credit += H2_DEF_INITIAL_WINDOW_SIZE;
			}
			n = 0;
			while (n < H2_WIRE_HEADER_LEN) {
				long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
				if (r <= 0) _exit(7);
				n += r;
			}
			len = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
			if (in[3] != H2_FRAME_DATA) _exit(8);
			// save the flags byte — the payload read below overwrites in[0..]
			int end_stream = in[4] & H2_FLAG_END_STREAM;
			nframes++;
			stream_credit -= len;
			conn_credit -= len;
			n = 0;
			while (n < len) {
				long r = read(sv[1], in + n, (unsigned long)(len - n));
				if (r <= 0) _exit(9);
				n += r;
			}
			total += len;
			if (end_stream) done = 1;
		}
		if (total != 70000) _exit(10);
		// spot-check the body content ('a' everywhere)
		if (in[0] != 'a' || in[len - 1] != 'a') _exit(11);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: the full connection loop over the socketpair ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client received all 70000 bytes (no deadlock)", 0, exit_code);
}

int main(void) {
	test_h2_flow_conn_window();
	test_h2_flow_stream_window();
	test_h2_flow_window_update();
	test_h2_flow_resume();
	test_h2_flow_large_file();
	test_summary();
	return 0;
}
