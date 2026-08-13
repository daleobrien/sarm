// Unit tests for src/h2/ — Stage 13: connection management.
// PING (RFC 9113 §6.7): an 8-octet PING without ACK is answered with a
// PING ACK carrying the identical payload, wrong lengths and non-zero
// stream ids are rejected, and an ACK is never answered. GOAWAY (§6.8):
// the server records a client GOAWAY, answers with its own
// GOAWAY(NO_ERROR), and refuses any brand-new stream with
// REFUSED_STREAM — while already-accepted streams run to completion,
// so a connection shut down mid-response drains gracefully.

#include "test_h2_common.h"

static void test_h2_ping_dispatch(void) {
	TEST_SUITE("13.1 PING — 8-octet ACK echoes the payload");

	uint8_t wire[9];
	uint8_t ping_payload[8] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}
	reset_conn(&conn);
	conn.fd = sv[0]; // the ACK writer's fd

	// a plain PING → a PING ACK with the identical payload
	put_wire_header(wire, 8, H2_FRAME_PING, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("PING accepted", 0,
	          h2_dispatch_wrapper(&hdr, ping_payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	uint8_t in[32];
	uint8_t type, flags;
	uint32_t sid;
	long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
	ASSERT_EQ("ACK length 8", 8, len);
	ASSERT_EQ("ACK type PING", H2_FRAME_PING, type);
	ASSERT_TRUE("ACK flag set", (flags & H2_FLAG_ACK) != 0);
	ASSERT_EQ("ACK on stream 0", 0, (int64_t)sid);
	ASSERT_EQ("payload echoed verbatim", 0, memcmp(in, ping_payload, 8));

	// a PING with the ACK flag → no frame comes back (§6.7)
	put_wire_header(wire, 8, H2_FRAME_PING, H2_FLAG_ACK, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("ACK-flagged PING accepted", 0,
	          h2_dispatch_wrapper(&hdr, ping_payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	long r = read(sv[1], in, sizeof(in));
	ASSERT_EQ("no frame answered an ACK-flagged PING", -1, r);

	// length != 8 → FRAME_SIZE_ERROR
	put_wire_header(wire, 7, H2_FRAME_PING, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("7-byte PING → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, ping_payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// stream id != 0 → PROTOCOL_ERROR
	put_wire_header(wire, 8, H2_FRAME_PING, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("PING on stream 3 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, ping_payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	close(sv[0]);
	close(sv[1]);
}

static void test_h2_goaway_dispatch(void) {
	TEST_SUITE("13.2 GOAWAY — recorded, answered, new streams refused");

	uint8_t wire[9];
	uint8_t goaway_payload[8] = { 0, 0, 0, 5, 0, 0, 0, 0 }; // last 5, NO_ERROR
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}
	reset_conn(&conn);
	reset_streams();
	conn.fd = sv[0]; // the GOAWAY reply writer's fd

	// stream 1 is accepted before the GOAWAY — trailers on it stay legal
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("stream 1 accepted before GOAWAY", 0,
	          h2_dispatch_wrapper(&hdr, H2_REQ_BLOCK, &conn, &carry));

	// the client's GOAWAY — accepted, recorded, and answered
	put_wire_header(wire, 8, H2_FRAME_GOAWAY, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GOAWAY accepted", 0,
	          h2_dispatch_wrapper(&hdr, goaway_payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("goaway_received set", 1, conn.goaway_received);
	ASSERT_EQ("peer last stream id recorded", 5, conn.goaway_last_stream_id);
	uint8_t in[32];
	uint8_t type, flags;
	uint32_t sid;
	long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
	ASSERT_EQ("GOAWAY reply length 8", 8, len);
	ASSERT_EQ("GOAWAY reply type", H2_FRAME_GOAWAY, type);
	ASSERT_EQ("GOAWAY reply on stream 0", 0, (int64_t)sid);
	uint32_t last = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
	                ((uint32_t)in[2] << 8) | in[3];
	uint32_t code = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
	                ((uint32_t)in[6] << 8) | in[7];
	ASSERT_EQ("reply last stream = our high-water mark", 1, (int64_t)last);
	ASSERT_EQ("reply error NO_ERROR", H2_ERR_NO_ERROR, (int64_t)code);

	// a brand-new stream after GOAWAY → REFUSED_STREAM, not created
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("new stream after GOAWAY → REFUSED_STREAM", H2_ERR_REFUSED_STREAM,
	          h2_dispatch_wrapper(&hdr, H2_REQ_BLOCK, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("stream 3 not created", 0, (int64_t)h2_stream_find_wrapper(3));

	// HEADERS on the existing stream (trailers) is still accepted
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("trailers on stream 1 accepted", 0,
	          h2_dispatch_wrapper(&hdr, H2_REQ_BLOCK, &conn, &carry));

	// stream id != 0 → PROTOCOL_ERROR
	put_wire_header(wire, 8, H2_FRAME_GOAWAY, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GOAWAY on stream 3 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, goaway_payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// length < 8 → FRAME_SIZE_ERROR
	put_wire_header(wire, 7, H2_FRAME_GOAWAY, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("7-byte GOAWAY → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, goaway_payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	close(sv[0]);
	close(sv[1]);
}

static void test_h2_ping_loop(void) {
	TEST_SUITE("13.1 PING — answered with PING ACK, payload echoed");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[64], in[64];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// PING with a distinctive payload
		put_wire_header(out + out_len, 8, H2_FRAME_PING, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		memcpy(out + out_len, "pingpong", 8);
		out_len += 8;
		send_all(sv[1], out, out_len);

		uint8_t type, flags;
		uint32_t sid;
		// the server's opening SETTINGS first
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// then the PING ACK — 8 payload bytes, echoed verbatim
		long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 8 || type != H2_FRAME_PING || sid != 0) _exit(3);
		if ((flags & H2_FLAG_ACK) == 0) _exit(4);
		if (memcmp(in, "pingpong", 8) != 0) _exit(5);
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
	ASSERT_EQ("client received a PING ACK echoing the payload", 0, exit_code);
}

static void test_h2_goaway_loop(void) {
	TEST_SUITE("13.2 GOAWAY — server replies and refuses new streams");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[256], in[64];
		long out_len = 0;
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// GOAWAY(NO_ERROR), last stream 0 — the client is going away
		put_wire_header(out + out_len, 8, H2_FRAME_GOAWAY, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x00; out[out_len++] = 0x00; // last stream id 0
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x00; out[out_len++] = 0x00; // NO_ERROR
		// a brand-new stream after GOAWAY — must be refused
		out_len += put_request_headers(out + out_len, "/", 1,
		                               H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		send_all(sv[1], out, out_len);

		uint8_t type, flags;
		uint32_t sid;
		// the server's opening SETTINGS
		if (read_frame(sv[1], in, sizeof(in), &type, &flags, &sid) != 12)
			_exit(1);
		if (type != H2_FRAME_SETTINGS || sid != 0) _exit(2);
		// the server's GOAWAY — NO_ERROR, its own last stream 0
		long len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 8 || type != H2_FRAME_GOAWAY || sid != 0) _exit(3);
		uint32_t last = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
		                ((uint32_t)in[2] << 8) | in[3];
		uint32_t code = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
		                ((uint32_t)in[6] << 8) | in[7];
		if (last != 0) _exit(4);
		if (code != H2_ERR_NO_ERROR) _exit(5);
		// the new stream is refused — RST_STREAM(REFUSED_STREAM)
		len = read_frame(sv[1], in, sizeof(in), &type, &flags, &sid);
		if (len != 4 || type != H2_FRAME_RST_STREAM || sid != 1) _exit(6);
		uint32_t rc = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
		              ((uint32_t)in[2] << 8) | in[3];
		if (rc != H2_ERR_REFUSED_STREAM) _exit(7);
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
	ASSERT_EQ("server answered GOAWAY and refused the new stream", 0, exit_code);
}

static void test_h2_goaway_graceful(void) {
	TEST_SUITE("13.3 graceful shutdown — in-flight stream finishes after GOAWAY");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		close(sv[0]);
		uint8_t out[256], in[70000 + 64];
		long out_len = 0;
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
		send_all(sv[1], out, out_len);

		// the server's opening SETTINGS (21 bytes) — read, then skip
		long n = 0;
		while (n < 21) {
			long r = read(sv[1], in + n, (unsigned long)(21 - n));
			if (r <= 0) _exit(1);
			n += r;
		}
		// the response HEADERS header, then skip its HPACK payload
		n = 0;
		while (n < H2_WIRE_HEADER_LEN) {
			long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
			if (r <= 0) _exit(2);
			n += r;
		}
		if (in[3] != H2_FRAME_HEADERS) _exit(3);
		long hlen = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
		n = 0;
		while (n < hlen) {
			long r = read(sv[1], in, (unsigned long)hlen);
			if (r <= 0) _exit(4);
			n += r;
		}

		// DATA loop: send GOAWAY once the credit first runs low, keep
		// topping the windows up, and tolerate the server's GOAWAY reply
		// interleaved between DATA frames
		long stream_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long conn_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long total = 0, len = 0;
		int done = 0, goaway_sent = 0, goaway_seen = 0;
		while (!done) {
			if (stream_credit < H2_DEFAULT_MAX_FRAME_SIZE ||
			    conn_credit < H2_DEFAULT_MAX_FRAME_SIZE) {
				if (!goaway_sent) {
					// GOAWAY while the server is mid-response — it is
					// blocked on credit and must dispatch this frame
					// without killing the in-flight stream (§6.8)
					put_wire_header(out, 8, H2_FRAME_GOAWAY, 0, 0);
					out[9] = 0x00; out[10] = 0x00;
					out[11] = 0x00; out[12] = 0x01; // last stream 1
					out[13] = 0x00; out[14] = 0x00;
					out[15] = 0x00; out[16] = 0x00; // NO_ERROR
					send_all(sv[1], out, 17);
					goaway_sent = 1;
				}
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
				send_all(sv[1], wu, wu_len);
				stream_credit += H2_DEF_INITIAL_WINDOW_SIZE;
				conn_credit += H2_DEF_INITIAL_WINDOW_SIZE;
			}
			n = 0;
			while (n < H2_WIRE_HEADER_LEN) {
				long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
				if (r <= 0) _exit(5);
				n += r;
			}
			len = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
			if (in[3] == H2_FRAME_GOAWAY) {
				// the server's GOAWAY reply — interleaved mid-response
				if (len != 8 || in[4] != 0) _exit(6);
				uint32_t sid_w = ((uint32_t)in[5] << 24) | ((uint32_t)in[6] << 16) |
				                 ((uint32_t)in[7] << 8) | in[8];
				if (sid_w != 0) _exit(7);
				n = 0;
				while (n < 8) {
					long r = read(sv[1], in + n, (unsigned long)(8 - n));
					if (r <= 0) _exit(8);
					n += r;
				}
				uint32_t last = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
				                ((uint32_t)in[2] << 8) | in[3];
				uint32_t code = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) |
				                ((uint32_t)in[6] << 8) | in[7];
				if (last != 1) _exit(9);      // stream 1 was accepted
				if (code != H2_ERR_NO_ERROR) _exit(10);
				goaway_seen = 1;
				continue;
			}
			if (in[3] != H2_FRAME_DATA) _exit(11);
			int end_stream = in[4] & H2_FLAG_END_STREAM;
			uint32_t sid = ((uint32_t)in[5] << 24) | ((uint32_t)in[6] << 16) |
			               ((uint32_t)in[7] << 8) | in[8];
			if (sid != 1) _exit(12);
			stream_credit -= len;
			conn_credit -= len;
			n = 0;
			while (n < len) {
				long r = read(sv[1], in + n, (unsigned long)(len - n));
				if (r <= 0) _exit(13);
				n += r;
			}
			total += len;
			if (end_stream) done = 1;
		}
		if (total != 70000) _exit(14);
		if (!goaway_seen) _exit(15);
		// spot-check the body content ('a' everywhere)
		if (in[0] != 'a' || in[len - 1] != 'a') _exit(16);
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
	ASSERT_EQ("in-flight stream finished after GOAWAY (70000 bytes)", 0, exit_code);
}

int main(void) {
	test_h2_ping_dispatch();
	test_h2_goaway_dispatch();
	test_h2_ping_loop();
	test_h2_goaway_loop();
	test_h2_goaway_graceful();
	test_summary();
	return 0;
}
