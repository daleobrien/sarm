// Unit tests for src/h2/ — Stage 12: connection multiplexing.
// Two (or more) streams on one TCP connection, each served as its
// request completes; the opening SETTINGS frame advertises
// MAX_CONCURRENT_STREAMS = 32, the 33rd concurrent stream is refused
// with GOAWAY(ENHANCE_YOUR_CALM) (§5.1.2), and finished (CLOSED) stream
// entries are recycled so a long-lived connection outlives its 32-entry
// table.

#include "test_h2_common.h"

static void test_h2_multiplex_two_streams(void) {
	TEST_SUITE("12.1 two streams on one connection — both responses returned");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[256];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		out_len += put_request_headers(out + out_len, "/", 1,
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		out_len += put_request_headers(out + out_len, "/assets/style.css",
		                               LITLEN("/assets/style.css"),
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 3);
		send_all(sv[1], out, out_len);

		uint8_t in[256];
		uint8_t type, flags;
		uint32_t sid;
		// the server's opening SETTINGS first
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// §6.5.3 — then the ACK for the SETTINGS we sent in the preface
		if (expect_settings_ack(sv[1], in, sizeof(in)) != 0) _exit(11);
		// response 1 — stream 1, /: HEADERS then DATA "<h1>hello h2</h1>"
		long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len < 0 || type != H2_FRAME_HEADERS || sid != 1 ||
		    (flags & H2_FLAG_END_HEADERS) == 0) _exit(3);
		len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 17 || type != H2_FRAME_DATA || sid != 1 ||
		    (flags & H2_FLAG_END_STREAM) == 0) _exit(4);
		if (memcmp(in, "<h1>hello h2</h1>", 17) != 0) _exit(5);
		// response 2 — stream 3, /assets/style.css
		len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len < 0 || type != H2_FRAME_HEADERS || sid != 3 ||
		    (flags & H2_FLAG_END_HEADERS) == 0) _exit(6);
		len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 15 || type != H2_FRAME_DATA || sid != 3 ||
		    (flags & H2_FLAG_END_STREAM) == 0) _exit(7);
		if (memcmp(in, "body{color:red}", 15) != 0) _exit(8);
		close(sv[1]);
		_exit(0);
	}

	// ── server side ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client received both responses on one connection", 0, exit_code);
}

static void test_h2_multiplex_interleave(void) {
	TEST_SUITE("12.2 interleaved requests — HEADERS 1, 3, 5 before the first response");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[512];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// all three HEADERS frames, one burst, before any response is read
		out_len += put_request_headers(out + out_len, "/", 1,
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		out_len += put_request_headers(out + out_len, "/assets/style.css",
		                               LITLEN("/assets/style.css"),
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 3);
		out_len += put_request_headers(out + out_len, "/assets/app.js",
		                               LITLEN("/assets/app.js"),
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 5);
		send_all(sv[1], out, out_len);

		uint8_t in[256];
		uint8_t type, flags;
		uint32_t sid;
		// the server's opening SETTINGS
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// §6.5.3 — then the ACK for the SETTINGS we sent in the preface
		if (expect_settings_ack(sv[1], in, sizeof(in)) != 0) _exit(11);
		// three responses, each HEADERS + DATA, in stream order
		static const uint32_t ids[3] = { 1, 3, 5 };
		static const long lens[3] = { 17, 15, 14 };
		static const char *bodies[3] = {
			"<h1>hello h2</h1>", "body{color:red}", "console.log(1)",
		};
		for (int i = 0; i < 3; i++) {
			long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
			if (len < 0 || type != H2_FRAME_HEADERS || sid != ids[i] ||
			    (flags & H2_FLAG_END_HEADERS) == 0) _exit(3);
			len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
			if (len != lens[i] || type != H2_FRAME_DATA || sid != ids[i] ||
			    (flags & H2_FLAG_END_STREAM) == 0) _exit(4);
			if (memcmp(in, bodies[i], (unsigned long)lens[i]) != 0) _exit(5);
		}
		close(sv[1]);
		_exit(0);
	}

	// ── server side ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("all three interleaved streams completed", 0, exit_code);
}

static void test_h2_stream_recycle(void) {
	TEST_SUITE("12 stream table — CLOSED entries recycled for new streams");

	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	int64_t carry;

	// fill the table with 32 entries — all live (IDLE), not recyclable
	for (int64_t id = 1; id <= 63; id += 2)
		h2_stream_create_wrapper(id, &conn, &carry);
	ASSERT_EQ("full table refuses the 33rd", H2_ERR_REFUSED_STREAM,
	          (int64_t)h2_stream_create_wrapper(65, &conn, &carry));

	// close them all — the state h2_process_request leaves behind — and
	// the slots become recyclable
	for (int64_t id = 1; id <= 63; id += 2) {
		h2_stream_t *s = h2_stream_find_wrapper(id);
		if (s != NULL)
			s->state = H2_STREAM_CLOSED;
	}
	h2_stream_t *s = h2_stream_create_wrapper(65, &conn, &carry);
	ASSERT_EQ("recycled create succeeds", 0, carry);
	ASSERT_NOT_NULL("stream 65 created in a recycled slot", s);
	ASSERT_EQ("state reset to IDLE", H2_STREAM_IDLE, s->state);
	ASSERT_EQ("conn last stream id = 65", 65, conn.last_stream_id);
	ASSERT_EQ("find 65 works", (int64_t)s, (int64_t)h2_stream_find_wrapper(65));
	// the recycled slot displaced one of the closed streams — whichever
	// slot the scan picked, exactly 31 of the original 32 remain
	int64_t remaining = 0;
	for (int64_t old = 1; old <= 63; old += 2) {
		if (h2_stream_find_wrapper(old) != NULL)
			remaining++;
	}
	ASSERT_EQ("one closed stream displaced by the recycle", 31, remaining);
}

static void test_h2_max_streams_dispatch(void) {
	TEST_SUITE("12.3 MAX_CONCURRENT_STREAMS — 33rd concurrent stream refused");

	uint8_t wire[9];
	uint8_t payload[4];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// open 32 streams (ids 1..63) without END_STREAM — they stay OPEN
	reset_streams();
	reset_conn(&conn);
	for (int64_t id = 1; id <= 63; id += 2) {
		put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, (uint32_t)id);
		h2_parse_wrapper(wire, &hdr);
		h2_dispatch_wrapper(&hdr, payload, &conn, &carry);
	}
	h2_stream_t *last = h2_stream_find_wrapper(63);
	ASSERT_NOT_NULL("32nd stream (63) created", last);
	ASSERT_EQ("32nd stream still OPEN", H2_STREAM_OPEN, last->state);

	// the 33rd (stream 65) crosses the limit — refused, not created
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 65);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("33rd concurrent stream → ENHANCE_YOUR_CALM",
	          H2_ERR_ENHANCE_YOUR_CALM,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("stream 65 not created", 0, (int64_t)h2_stream_find_wrapper(65));

	// the limit is about concurrency, not stream ids: with only 16 open,
	// stream 33 (the 17th) is accepted
	reset_streams();
	reset_conn(&conn);
	for (int64_t id = 1; id <= 31; id += 2) {
		put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, (uint32_t)id);
		h2_parse_wrapper(wire, &hdr);
		h2_dispatch_wrapper(&hdr, payload, &conn, &carry);
	}
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 33);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("stream 33 accepted (17 concurrent ≤ 32)", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream 33 OPEN", H2_STREAM_OPEN,
	          h2_stream_find_wrapper(33)->state);
}

static void test_h2_max_streams_loop(void) {
	TEST_SUITE("12.3 MAX_CONCURRENT_STREAMS — 33rd refused (GOAWAY ENHANCE_YOUR_CALM)");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[512];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// 32 concurrent streams — no END_STREAM, so they stay open
		for (int64_t id = 1; id <= 63; id += 2)
			out_len += put_request_headers(out + out_len, "/", 1,
			                               H2_FLAG_END_HEADERS, (uint32_t)id);
		// the 33rd — crosses the limit
		out_len += put_request_headers(out + out_len, "/", 1,
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 65);
		send_all(sv[1], out, out_len);

		uint8_t in[64];
		uint8_t type, flags;
		uint32_t sid;
		// the server's opening SETTINGS
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// §6.5.3 — then the ACK for the SETTINGS we sent in the preface
		if (expect_settings_ack(sv[1], in, sizeof(in)) != 0) _exit(11);
		// GOAWAY — ENHANCE_YOUR_CALM, last accepted stream 63
		long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 8 || type != H2_FRAME_GOAWAY || sid != 0) _exit(3);
		uint32_t last = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
		                ((uint32_t)in[2] << 8) | in[3];
		uint32_t code = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
		                ((uint32_t)in[6] << 8) | in[7];
		if (last != 63) _exit(4);
		if (code != H2_ERR_ENHANCE_YOUR_CALM) _exit(5);
		close(sv[1]);
		_exit(0);
	}

	// ── server side ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("33rd concurrent stream refused with GOAWAY", 0, exit_code);
}

static void test_h2_many_sequential(void) {
	TEST_SUITE("12 multiplexing — 33 sequential requests on one connection");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[512];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		for (int64_t id = 1; id <= 65; id += 2)
			out_len += put_request_headers(out + out_len, "/", 1,
			                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS,
			                               (uint32_t)id);
		send_all(sv[1], out, out_len);

		uint8_t in[256];
		uint8_t type, flags;
		uint32_t sid;
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// §6.5.3 — then the ACK for the SETTINGS we sent in the preface
		if (expect_settings_ack(sv[1], in, sizeof(in)) != 0) _exit(11);
		int64_t id = 1;
		for (int i = 0; i < 33; i++) {
			long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
			if (len < 0 || type != H2_FRAME_HEADERS || sid != (uint32_t)id)
				_exit(3);
			len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
			if (len != 17 || type != H2_FRAME_DATA || sid != (uint32_t)id ||
			    (flags & H2_FLAG_END_STREAM) == 0) _exit(4);
			if (memcmp(in, "<h1>hello h2</h1>", 17) != 0) _exit(5);
			id += 2;
		}
		close(sv[1]);
		_exit(0);
	}

	// ── server side ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("all 33 sequential requests completed", 0, exit_code);
}

int main(void) {
	test_h2_multiplex_two_streams();
	test_h2_multiplex_interleave();
	test_h2_stream_recycle();
	test_h2_max_streams_dispatch();
	test_h2_max_streams_loop();
	test_h2_many_sequential();
	test_summary();
	return 0;
}
