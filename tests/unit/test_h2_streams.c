// Unit tests for src/http2.S — Stage 6: stream management.
// The fixed stream table (h2_streams / h2_stream_find / h2_stream_create),
// stream id validation (h2_validate_stream_id), the receive-side state
// machine (h2_stream_event) and RST_STREAM handling. HEADERS/DATA
// handlers drive the machine through h2_dispatch_frame.

#include "test_h2_common.h"

static void test_h2_stream_table(void) {
	TEST_SUITE("h2_stream table — 6.1 create and find");

	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	int64_t carry;

	// an empty table finds nothing
	ASSERT_EQ("find stream 1 — not found", 0,
	          (int64_t)h2_stream_find_wrapper(1));

	// creating stream 1 fills a fresh entry with the RFC defaults
	h2_stream_t *s1 = h2_stream_create_wrapper(1, &conn, &carry);
	ASSERT_EQ("create 1 succeeds", 0, carry);
	ASSERT_NOT_NULL("create 1 returns an entry", s1);
	ASSERT_EQ("stream_id = 1", 1, s1->stream_id);
	ASSERT_EQ("initial state IDLE", H2_STREAM_IDLE, s1->state);
	ASSERT_EQ("initial flags 0", 0, s1->flags);
	ASSERT_EQ("initial window 65535", H2_DEF_INITIAL_WINDOW_SIZE, s1->window);
	ASSERT_EQ("conn tracks last stream id", 1, conn.last_stream_id);

	// ... and can be found again
	ASSERT_EQ("find 1 returns the same entry", (int64_t)s1,
	          (int64_t)h2_stream_find_wrapper(1));

	// a second stream uses a different entry; the first is untouched
	h2_stream_t *s3 = h2_stream_create_wrapper(3, &conn, &carry);
	ASSERT_EQ("create 3 succeeds", 0, carry);
	ASSERT_NOT_NULL("create 3 returns an entry", s3);
	ASSERT_EQ("entries differ", 1, s1 != s3);
	ASSERT_EQ("find 3 returns its entry", (int64_t)s3,
	          (int64_t)h2_stream_find_wrapper(3));
	ASSERT_EQ("stream 1 still present", (int64_t)s1,
	          (int64_t)h2_stream_find_wrapper(1));
	ASSERT_EQ("conn tracks last stream id", 3, conn.last_stream_id);

	// creating an existing id is find-or-create: same entry, no change
	ASSERT_EQ("create 1 again returns existing entry", (int64_t)s1,
	          (int64_t)h2_stream_create_wrapper(1, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream 1 state unchanged", H2_STREAM_IDLE, s1->state);

	// the table is fixed at H2_MAX_STREAMS — filling it rejects the next
	reset_streams();
	reset_conn(&conn);
	for (int64_t id = 1; id < 2 * H2_MAX_STREAMS; id += 2)
		h2_stream_create_wrapper(id, &conn, &carry);
	// 32 odd ids (1..63) fill the table; the 33rd is rejected
	h2_stream_t *full = h2_stream_create_wrapper(65, &conn, &carry);
	ASSERT_EQ("table full → carry set", 1, carry);
	ASSERT_EQ("table full → REFUSED_STREAM", H2_ERR_REFUSED_STREAM,
	          (int64_t)full);
}

static void test_h2_validate_stream_id(void) {
	TEST_SUITE("h2_validate_stream_id — 6.2");

	uint8_t wire[9];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);

	// zero is reserved for connection-level frames (§5.1.1)
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("id 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// client streams are odd — an even id belongs to a server stream
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 4);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id 4 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	// a fresh odd id is fine
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("id 1 accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// ids must increase for new streams (§5.1.1)
	reset_streams();
	reset_conn(&conn);
	conn.last_stream_id = 9; // the connection has already seen up to 9
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 7); // new stream, lower id
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("new id ≤ last → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 11); // new stream, higher id
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("new id > last accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	// an existing stream may keep its id — no increase check for it
	reset_streams();
	reset_conn(&conn);
	h2_stream_create_wrapper(5, &conn, &carry); // last becomes 5
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 5);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("existing id accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
}

static void test_h2_headers_stream_creation(void) {
	TEST_SUITE("h2_handle_headers — 6.2 stream creation");

	uint8_t wire[9];
	uint8_t payload[4];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);

	// a HEADERS frame on stream 0 is a PROTOCOL_ERROR
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("no stream created", 0, (int64_t)h2_stream_find_wrapper(1));

	// an even stream id is a PROTOCOL_ERROR
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 2 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("no stream created", 0, (int64_t)h2_stream_find_wrapper(2));

	// a valid HEADERS opens the stream and bumps the high-water mark
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 1 accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_NOT_NULL("stream 1 created", s);
	ASSERT_EQ("state OPEN", H2_STREAM_OPEN, s->state);
	ASSERT_EQ("conn last stream id = 1", 1, conn.last_stream_id);

	// the next stream must use a larger id
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 3 accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("conn last stream id = 3", 3, conn.last_stream_id);

	// a HEADERS for an existing stream is fine (trailers, §5.1 open)
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS on existing stream accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream 1 still OPEN", H2_STREAM_OPEN,
	          h2_stream_find_wrapper(1)->state);
}

static void test_h2_stream_transitions(void) {
	TEST_SUITE("h2_stream_event — 6.3 state machine");

	h2_conn_t conn;
	h2_stream_t *s;
	int64_t carry;

	// ── IDLE ──
	s = stream_in_state(&conn, 1, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+HEADERS → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("IDLE+HEADERS → OPEN", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 3, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+DATA → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	s = stream_in_state(&conn, 5, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+END_STREAM → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	s = stream_in_state(&conn, 7, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+RST → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	// ── OPEN ──
	s = stream_in_state(&conn, 9, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+HEADERS → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("OPEN+HEADERS stays OPEN (trailers)", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 11, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+DATA → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("OPEN+DATA stays OPEN", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 13, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+END_STREAM → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("OPEN+END_STREAM → HALF_CLOSED_REMOTE",
	          H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	s = stream_in_state(&conn, 15, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("OPEN+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── HALF_CLOSED_REMOTE ──
	s = stream_in_state(&conn, 17, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+HEADERS → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	s = stream_in_state(&conn, 19, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));

	s = stream_in_state(&conn, 21, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+END_STREAM → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));

	s = stream_in_state(&conn, 23, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("HCR+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── HALF_CLOSED_LOCAL ──
	s = stream_in_state(&conn, 25, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+HEADERS → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));

	s = stream_in_state(&conn, 27, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));

	s = stream_in_state(&conn, 29, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+END_STREAM → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("HCL+END_STREAM → CLOSED", H2_STREAM_CLOSED, s->state);

	s = stream_in_state(&conn, 31, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("HCL+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── CLOSED ──
	s = stream_in_state(&conn, 33, H2_STREAM_CLOSED);
	ASSERT_EQ("CLOSED+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_CLOSED, s->state);

	// a reset racing our own END_STREAM is tolerated (§5.1 closed)
	s = stream_in_state(&conn, 35, H2_STREAM_CLOSED);
	ASSERT_EQ("CLOSED+RST → 0 (tolerated)", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("state stays CLOSED", H2_STREAM_CLOSED, s->state);

	// defensive: an out-of-range event is an invalid transition
	s = stream_in_state(&conn, 37, H2_STREAM_OPEN);
	ASSERT_EQ("event out of range → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, 4, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_OPEN, s->state);
}

static void test_h2_end_stream_flags(void) {
	TEST_SUITE("h2 HEADERS/DATA — 6.3 END_STREAM flag");

	uint8_t wire[9];
	uint8_t payload[4];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// HEADERS without END_STREAM → OPEN
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state OPEN", H2_STREAM_OPEN, h2_stream_find_wrapper(1)->state);

	// HEADERS with END_STREAM → HALF_CLOSED_REMOTE
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	// DATA without END_STREAM → stays OPEN
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	put_wire_header(wire, 5, H2_FRAME_DATA, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state still OPEN", H2_STREAM_OPEN, h2_stream_find_wrapper(1)->state);

	// DATA with END_STREAM → HALF_CLOSED_REMOTE
	put_wire_header(wire, 5, H2_FRAME_DATA, H2_FLAG_END_STREAM, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          h2_stream_find_wrapper(1)->state);

	// DATA on an unknown stream → idle violation (PROTOCOL_ERROR)
	put_wire_header(wire, 5, H2_FRAME_DATA, 0, 9);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA on idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
}

static void test_h2_rst_stream(void) {
	TEST_SUITE("h2_handle_rst_stream — 6.4");

	uint8_t wire[9];
	uint8_t payload[4] = {0, 0, 0, H2_ERR_CANCEL}; // 4-byte error code
	uint8_t block[4];
	memcpy(block, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// the happy path: HEADERS opens a stream, RST_STREAM closes it
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, block, &conn, &carry));
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_EQ("stream OPEN", H2_STREAM_OPEN, s->state);

	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream CLOSED", H2_STREAM_CLOSED, h2_stream_find_wrapper(1)->state);

	// a wrong payload length is a FRAME_SIZE_ERROR
	put_wire_header(wire, 3, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("length 3 → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// stream 0 is a connection-level id — RST_STREAM there is an error
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("stream 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// an even id (server-initiated) is an error from the client
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// RST_STREAM on an idle (never opened) stream (§6.4)
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 9);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// RST_STREAM on a half-closed (remote) stream also closes it
	// (stream 1 is closed now; use a fresh stream 3)
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, block, &conn, &carry));
	h2_stream_t *s3 = h2_stream_find_wrapper(3);
	ASSERT_EQ("stream 3 HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s3->state);

	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream 3 CLOSED", H2_STREAM_CLOSED, h2_stream_find_wrapper(3)->state);

	// RST_STREAM on an already-closed stream is tolerated (§5.1 closed)
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST on CLOSED stream tolerated", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream 1 still CLOSED", H2_STREAM_CLOSED,
	          h2_stream_find_wrapper(1)->state);
}

int main(void) {
	test_h2_stream_table();
	test_h2_validate_stream_id();
	test_h2_headers_stream_creation();
	test_h2_stream_transitions();
	test_h2_end_stream_flags();
	test_h2_rst_stream();
	test_summary();
	return 0;
}
