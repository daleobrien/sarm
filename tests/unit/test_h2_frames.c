// Unit tests for src/http2.S — Stage 4: the frame engine.
// h2_parse_frame_header (RFC 9113 §4.1), h2_validate_frame (§4.2),
// h2_dispatch_frame (§4.3), h2_handle_settings (§4.4) and SETTINGS
// ACK (§4.5). SETTINGS tests go through h2_dispatch_frame so the full
// header → handler path is exercised.

#include "test_h2_common.h"

static void test_h2_conn_defaults(void) {
	TEST_SUITE("h2_conn — RFC 9113 §6.5.2 defaults");

	h2_conn_t *conn = h2_conn_addr();
	ASSERT_EQ("max_rx_frame_size", H2_DEF_MAX_FRAME_SIZE, conn->max_rx_frame_size);
	ASSERT_EQ("header_table_size", H2_DEF_HEADER_TABLE_SIZE,
	          conn->settings_header_table_size);
	ASSERT_EQ("enable_push", H2_DEF_ENABLE_PUSH, conn->settings_enable_push);
	ASSERT_EQ("max_concurrent_streams", H2_DEF_MAX_CONCURRENT_STREAMS,
	          conn->settings_max_concurrent_streams);
	ASSERT_EQ("initial_window_size", H2_DEF_INITIAL_WINDOW_SIZE,
	          conn->settings_initial_window_size);
	ASSERT_EQ("max_frame_size", H2_DEF_MAX_FRAME_SIZE, conn->settings_max_frame_size);
	ASSERT_EQ("max_header_list_size", H2_DEF_MAX_HEADER_LIST_SIZE,
	          conn->settings_max_header_list_size);
	ASSERT_EQ("ack_received", 0, conn->ack_received);
	ASSERT_EQ("last_stream_id", 0, conn->last_stream_id);
	ASSERT_EQ("last_frame_type", 0, conn->last_frame_type);
	ASSERT_EQ("window", H2_DEF_INITIAL_WINDOW_SIZE, conn->window);
	ASSERT_EQ("fd", -1, conn->fd);
	ASSERT_EQ("goaway_received", 0, conn->goaway_received);
	ASSERT_EQ("goaway_last_stream_id", 0, conn->goaway_last_stream_id);
}

static void test_h2_parse_frame_header(void) {
	TEST_SUITE("h2_parse_frame_header — 4.1");

	uint8_t wire[9];
	h2_frame_header_t hdr;

	// a known SETTINGS frame: length=18, type=4, flags=0, stream 0
	put_wire_header(wire, 18, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("SETTINGS length decoded", 18, hdr.length);
	ASSERT_EQ("SETTINGS type decoded", H2_FRAME_SETTINGS, hdr.type);
	ASSERT_EQ("SETTINGS flags decoded", 0, hdr.flags);
	ASSERT_EQ("SETTINGS stream id decoded", 0, hdr.stream_id);

	// full 24-bit length, nonzero flags, R bit set in the stream id
	put_wire_header(wire, 0x123456, H2_FRAME_HEADERS, 0x5, 0x80000005u);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("full 24-bit length", 0x123456, hdr.length);
	ASSERT_EQ("type decoded", H2_FRAME_HEADERS, hdr.type);
	ASSERT_EQ("flags decoded", 0x5, hdr.flags);
	ASSERT_EQ("R bit masked — stream id 5", 5, hdr.stream_id);

	// extremes: zero length, max stream id, all flags
	put_wire_header(wire, 0, H2_FRAME_PING, 0xff, 0x7fffffffu);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("zero length", 0, hdr.length);
	ASSERT_EQ("all flags preserved", 0xff, hdr.flags);
	ASSERT_EQ("max stream id preserved", 0x7fffffff, hdr.stream_id);
}

static void test_h2_validate_frame(void) {
	TEST_SUITE("h2_validate_frame — 4.2");

	h2_conn_t conn;
	reset_conn(&conn);
	h2_frame_header_t hdr;
	hdr.type = H2_FRAME_DATA; // type is irrelevant to size validation
	hdr.flags = 0;
	hdr.stream_id = 0;
	int64_t carry;

	hdr.length = 0;
	ASSERT_EQ("length 0 accepted", 0, h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	hdr.length = H2_DEF_MAX_FRAME_SIZE;
	ASSERT_EQ("length == default max accepted", 0,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	hdr.length = H2_DEF_MAX_FRAME_SIZE + 1;
	ASSERT_EQ("length > max → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// beyond the 24-bit wire limit
	hdr.length = 0x01000000u;
	ASSERT_EQ("length > 2^24-1 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	// the limit is per-connection — raise it and the frame becomes legal
	conn.max_rx_frame_size = 20000;
	hdr.length = 20000;
	ASSERT_EQ("conn limit raised → accepted", 0,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
}

static void test_h2_dispatch_frame(void) {
	TEST_SUITE("h2_dispatch_frame — 4.3");

	// Since Stage 6, stream-scoped frames (HEADERS, DATA, RST_STREAM)
	// are real: HEADERS on stream 1 opens the stream, DATA rides on it,
	// RST_STREAM closes it. Connection-scoped frames (SETTINGS, PING,
	// GOAWAY) keep stream id 0; the remaining stream-scoped types are
	// still stubs and accept any id. RST_STREAM needs its 4-byte
	// payload to pass the §6.4 length check. Since Stage 8 the HEADERS
	// payload is HPACK and must be a valid request block — the 2-byte
	// :method GET + :path / block from H2_REQ_BLOCK. Since Stage 11
	// WINDOW_UPDATE is real (§6.9): it needs its 4-byte increment, and
	// on stream 1 — closed by the RST_STREAM above — the update is
	// ignored, not an error (§5.1 closed). Since Stage 13 PING and
	// GOAWAY are real: both need their 8-byte payloads, and each sends
	// a frame (PING ACK / GOAWAY reply) to the connection's fd — a
	// socketpair here, so the writes land in a socket buffer instead of
	// a dead descriptor.
	static const uint8_t types[] = {
		H2_FRAME_HEADERS, H2_FRAME_DATA, H2_FRAME_PRIORITY, H2_FRAME_RST_STREAM,
		H2_FRAME_SETTINGS, H2_FRAME_PUSH_PROMISE, H2_FRAME_PING, H2_FRAME_GOAWAY,
		H2_FRAME_WINDOW_UPDATE, H2_FRAME_CONTINUATION,
	};
	static const uint8_t streams[] = { 1, 1, 1, 1, 0, 1, 0, 0, 1, 1 };
	static const uint32_t lens[]   = { 2, 0, 0, 4, 0, 0, 8, 8, 4, 0 };
	uint8_t payload[8];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // HEADERS' HPACK block
	// WINDOW_UPDATE's 4-byte increment — nonzero so the §6.9 check passes
	payload[2] = 0x00; payload[3] = 0x00; payload[4] = 0x00; payload[5] = 0x10;
	// PING's / GOAWAY's 8-byte payloads — the four bytes the GOAWAY
	// handler reads as the peer's last stream id stay zero
	payload[6] = 0; payload[7] = 0;
	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	h2_frame_header_t hdr;
	hdr.flags = 0;
	int64_t carry;
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}
	conn.fd = sv[0]; // PING ACK / GOAWAY reply land here

	for (int i = 0; i < 10; i++) {
		hdr.type = types[i];
		hdr.length = lens[i];
		hdr.stream_id = streams[i];
		ASSERT_EQ("handler returns success", 0,
		          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
		ASSERT_EQ("carry clear", 0, carry);
		ASSERT_EQ("frame reached its handler", types[i], conn.last_frame_type);
	}

	// unknown frame types are ignored, not errors (RFC 9113 §5.5)
	hdr.type = 0x0a;
	ASSERT_EQ("type 0x0a ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	hdr.type = 0xff;
	ASSERT_EQ("type 0xff ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("last dispatched unchanged", H2_FRAME_CONTINUATION,
	          conn.last_frame_type);
	close(sv[0]);
	close(sv[1]);
}

static void test_h2_settings_store(void) {
	TEST_SUITE("h2_handle_settings — 4.4 store");

	uint8_t wire[9];
	uint8_t payload[18];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// client SETTINGS frame — three entries
	put_wire_header(wire, 18, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload + 0,  H2_SETTINGS_HEADER_TABLE_SIZE, 8192);
	put_setting(payload + 6,  H2_SETTINGS_ENABLE_PUSH, 0);
	put_setting(payload + 12, H2_SETTINGS_MAX_CONCURRENT_STREAMS, 100);

	reset_conn(&conn);
	ASSERT_EQ("first SETTINGS stored cleanly", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	ASSERT_EQ("header_table_size = 8192", 8192, conn.settings_header_table_size);
	ASSERT_EQ("enable_push = 0", 0, conn.settings_enable_push);
	ASSERT_EQ("max_concurrent_streams = 100", 100,
	          conn.settings_max_concurrent_streams);
	// untouched settings keep their RFC defaults
	ASSERT_EQ("initial_window_size default", H2_DEF_INITIAL_WINDOW_SIZE,
	          conn.settings_initial_window_size);
	ASSERT_EQ("max_frame_size default", H2_DEF_MAX_FRAME_SIZE,
	          conn.settings_max_frame_size);
	ASSERT_EQ("max_header_list_size default", H2_DEF_MAX_HEADER_LIST_SIZE,
	          conn.settings_max_header_list_size);

	// second SETTINGS frame — the remaining three settings
	put_setting(payload + 0,  H2_SETTINGS_INITIAL_WINDOW_SIZE, 123456);
	put_setting(payload + 6,  H2_SETTINGS_MAX_FRAME_SIZE, 65536);
	put_setting(payload + 12, H2_SETTINGS_MAX_HEADER_LIST_SIZE, 100000);

	ASSERT_EQ("second SETTINGS stored cleanly", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	ASSERT_EQ("initial_window_size = 123456", 123456,
	          conn.settings_initial_window_size);
	ASSERT_EQ("max_frame_size = 65536", 65536, conn.settings_max_frame_size);
	ASSERT_EQ("max_header_list_size = 100000", 100000,
	          conn.settings_max_header_list_size);
	// earlier values persist
	ASSERT_EQ("header_table_size persists", 8192, conn.settings_header_table_size);
	ASSERT_EQ("enable_push persists", 0, conn.settings_enable_push);
}

static void test_h2_settings_validation(void) {
	TEST_SUITE("h2_handle_settings — validation");

	uint8_t wire[9];
	uint8_t payload[12];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// unknown identifiers are ignored (§6.5.2)
	put_wire_header(wire, 12, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload + 0, 0x0a, 0xdeadbeefu); // unknown id
	put_setting(payload + 6, H2_SETTINGS_ENABLE_PUSH, 0);
	reset_conn(&conn);
	ASSERT_EQ("unknown id ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("known setting still stored", 0, conn.settings_enable_push);

	// SETTINGS_MAX_FRAME_SIZE out of range → PROTOCOL_ERROR
	put_setting(payload + 0, H2_SETTINGS_MAX_FRAME_SIZE, 100); // < 2^14
	reset_conn(&conn);
	ASSERT_EQ("max_frame_size too small → PROTOCOL_ERROR",
	          H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	put_setting(payload + 0, H2_SETTINGS_MAX_FRAME_SIZE, 0x01000000u); // > 2^24-1
	reset_conn(&conn);
	ASSERT_EQ("max_frame_size too large → PROTOCOL_ERROR",
	          H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 → FLOW_CONTROL_ERROR
	put_setting(payload + 0, H2_SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000u);
	reset_conn(&conn);
	ASSERT_EQ("initial_window_size too large → FLOW_CONTROL_ERROR",
	          H2_ERR_FLOW_CONTROL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// payload length not a multiple of 6 → FRAME_SIZE_ERROR
	put_wire_header(wire, 7, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	payload[0] = 0x00; payload[1] = 0x01; payload[2] = 0;
	payload[3] = 0;    payload[4] = 0x20; payload[5] = 0x00;
	payload[6] = 0xff; // 7th byte — length % 6 != 0
	reset_conn(&conn);
	ASSERT_EQ("length not % 6 → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// SETTINGS on a stream (id != 0) → PROTOCOL_ERROR
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, 0, 5);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("SETTINGS on stream 5 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));

	// an empty non-ACK SETTINGS frame is valid
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("empty SETTINGS accepted", 0,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received stays 0", 0, conn.ack_received);
}

static void test_h2_settings_ack(void) {
	TEST_SUITE("h2_handle_settings — ACK (4.5)");

	uint8_t wire[9];
	uint8_t payload[6];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// SETTINGS + ACK with an empty payload → acknowledged
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("ACK accepted", 0, h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received set", 1, conn.ack_received);
	ASSERT_EQ("carry clear", 0, carry);

	// SETTINGS + ACK with a payload → FRAME_SIZE_ERROR
	put_wire_header(wire, 6, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload, H2_SETTINGS_ENABLE_PUSH, 0);
	reset_conn(&conn);
	ASSERT_EQ("ACK with payload → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("ack_received not set", 0, conn.ack_received);

	// SETTINGS + ACK on a stream → PROTOCOL_ERROR (stream check wins)
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 3);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("ACK on stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received not set", 0, conn.ack_received);

	// a plain SETTINGS frame must not set ack_received
	put_wire_header(wire, 6, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("non-ACK SETTINGS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("ack_received stays 0", 0, conn.ack_received);
}

static void test_h2_malformed_rejected(void) {
	TEST_SUITE("h2 — malformed frames rejected");

	uint8_t wire[9];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// oversized payload — caught at validation, before any dispatch
	put_wire_header(wire, H2_DEF_MAX_FRAME_SIZE + 1, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("oversized frame → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// 2^24 cannot be encoded on the wire, but a hand-built struct can —
	// still rejected
	hdr.length = 0x01000000u;
	ASSERT_EQ("length above 2^24-1 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	// a malformed SETTINGS payload passes validation (size is fine) but
	// is rejected by the handler — no crash, connection error returned
	put_wire_header(wire, 7, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("SETTINGS length % 6 != 0 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, wire, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
}

int main(void) {
	test_h2_conn_defaults();
	test_h2_parse_frame_header();
	test_h2_validate_frame();
	test_h2_dispatch_frame();
	test_h2_settings_store();
	test_h2_settings_validation();
	test_h2_settings_ack();
	test_h2_malformed_rejected();
	test_summary();
	return 0;
}
