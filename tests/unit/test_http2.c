// Unit tests for src/http2.S — Stage 4: the HTTP/2 frame engine.
// Tests: h2_parse_frame_header (4.1), h2_validate_frame (4.2),
// h2_dispatch_frame (4.3), h2_handle_settings (4.4) and SETTINGS ACK
// (4.5). SETTINGS tests go through h2_dispatch_frame so the full
// header → handler path is exercised.
//
// NOTE: avoids libc string.h/stdlib.h per test_harness.h guidance.

#include "test_harness.h"

// ── HTTP/2 constants, mirroring defs.S ─────────────────────────────
#define H2_FRAME_DATA          0
#define H2_FRAME_HEADERS       1
#define H2_FRAME_PRIORITY      2
#define H2_FRAME_RST_STREAM    3
#define H2_FRAME_SETTINGS      4
#define H2_FRAME_PUSH_PROMISE  5
#define H2_FRAME_PING          6
#define H2_FRAME_GOAWAY        7
#define H2_FRAME_WINDOW_UPDATE 8
#define H2_FRAME_CONTINUATION  9

#define H2_SETTINGS_HEADER_TABLE_SIZE       1
#define H2_SETTINGS_ENABLE_PUSH             2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS  3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE     4
#define H2_SETTINGS_MAX_FRAME_SIZE          5
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE    6

#define H2_FLAG_ACK 0x1

#define H2_ERR_PROTOCOL_ERROR     1
#define H2_ERR_FLOW_CONTROL_ERROR 3
#define H2_ERR_FRAME_SIZE_ERROR   6

// RFC 9113 §6.5.2 default values
#define H2_DEF_HEADER_TABLE_SIZE       4096
#define H2_DEF_ENABLE_PUSH             1
#define H2_DEF_MAX_CONCURRENT_STREAMS  0xffffffff
#define H2_DEF_INITIAL_WINDOW_SIZE     65535
#define H2_DEF_MAX_FRAME_SIZE          16384
#define H2_DEF_MAX_HEADER_LIST_SIZE    0xffffffff

// ── structs, mirroring the H2F_*/H2C_* offsets in defs.S ───────────
typedef struct {
	uint32_t length;
	uint32_t type;
	uint32_t flags;
	uint32_t stream_id;
} h2_frame_header_t;

typedef struct {
	int64_t last_frame_type;
	int64_t max_rx_frame_size;
	int64_t settings_header_table_size;
	int64_t settings_enable_push;
	int64_t settings_max_concurrent_streams;
	int64_t settings_initial_window_size;
	int64_t settings_max_frame_size;
	int64_t settings_max_header_list_size;
	int64_t ack_received;
} h2_conn_t;

// ── wire frame builders ────────────────────────────────────────────

// Write a 9-byte big-endian frame header (RFC 9113 §4.1).
static void put_wire_header(uint8_t *p, uint32_t length, uint8_t type,
                            uint8_t flags, uint32_t stream_id) {
	p[0] = (uint8_t)(length >> 16);
	p[1] = (uint8_t)(length >> 8);
	p[2] = (uint8_t)length;
	p[3] = type;
	p[4] = flags;
	p[5] = (uint8_t)(stream_id >> 24);
	p[6] = (uint8_t)(stream_id >> 16);
	p[7] = (uint8_t)(stream_id >> 8);
	p[8] = (uint8_t)stream_id;
}

// Write one 6-byte SETTINGS entry (2-byte id + 4-byte value, big-endian).
static void put_setting(uint8_t *p, uint16_t id, uint32_t value) {
	p[0] = (uint8_t)(id >> 8);
	p[1] = (uint8_t)id;
	p[2] = (uint8_t)(value >> 24);
	p[3] = (uint8_t)(value >> 16);
	p[4] = (uint8_t)(value >> 8);
	p[5] = (uint8_t)value;
}

// ── wrappers for asm functions ─────────────────────────────────────

// h2_parse_frame_header(wire=x0, hdr=x1)
static inline void h2_parse_wrapper(const uint8_t *wire, h2_frame_header_t *hdr) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"bl h2_parse_frame_header\n"
		:: "r"(wire), "r"(hdr)
		: "x0", "x1", "x2", "x3", "x4", "x5", "memory");
}

// h2_validate_frame(hdr=x0, conn=x1) → (rc=x0, carry)
static inline int64_t h2_validate_wrapper(h2_frame_header_t *hdr,
                                          h2_conn_t *conn, int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_validate_frame\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(hdr), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "memory");
	*carry_out = carry;
	return rc;
}

// h2_dispatch_frame(hdr=x0, payload=x1, conn=x2) → (rc=x0, carry)
static inline int64_t h2_dispatch_wrapper(h2_frame_header_t *hdr,
                                          const uint8_t *payload,
                                          h2_conn_t *conn, int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"mov x2, %4\n"
		"bl h2_dispatch_frame\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(hdr), "r"(payload), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "memory");
	*carry_out = carry;
	return rc;
}

// ── helpers ────────────────────────────────────────────────────────

// Restore the RFC 9113 §6.5.2 defaults into a test connection struct.
static void reset_conn(h2_conn_t *conn) {
	conn->last_frame_type = 0;
	conn->max_rx_frame_size = H2_DEF_MAX_FRAME_SIZE;
	conn->settings_header_table_size = H2_DEF_HEADER_TABLE_SIZE;
	conn->settings_enable_push = H2_DEF_ENABLE_PUSH;
	conn->settings_max_concurrent_streams = H2_DEF_MAX_CONCURRENT_STREAMS;
	conn->settings_initial_window_size = H2_DEF_INITIAL_WINDOW_SIZE;
	conn->settings_max_frame_size = H2_DEF_MAX_FRAME_SIZE;
	conn->settings_max_header_list_size = H2_DEF_MAX_HEADER_LIST_SIZE;
	conn->ack_received = 0;
}

// ── h2_conn defaults baked into data.S ─────────────────────────────

static inline h2_conn_t *h2_conn_addr(void) {
	h2_conn_t *p;
	asm volatile(
		"adrp x0, h2_conn@PAGE\n"
		"add  x0, x0, h2_conn@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

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
	ASSERT_EQ("last_frame_type", 0, conn->last_frame_type);
}

// ── 4.1 — frame header decoding ────────────────────────────────────

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

// ── 4.2 — frame size validation ────────────────────────────────────

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

// ── 4.3 — frame dispatch ───────────────────────────────────────────

static void test_h2_dispatch_frame(void) {
	TEST_SUITE("h2_dispatch_frame — 4.3");

	static const uint8_t types[] = {
		H2_FRAME_DATA, H2_FRAME_HEADERS, H2_FRAME_PRIORITY, H2_FRAME_RST_STREAM,
		H2_FRAME_SETTINGS, H2_FRAME_PUSH_PROMISE, H2_FRAME_PING, H2_FRAME_GOAWAY,
		H2_FRAME_WINDOW_UPDATE, H2_FRAME_CONTINUATION,
	};
	uint8_t payload[6] = {0};
	h2_conn_t conn;
	reset_conn(&conn);
	h2_frame_header_t hdr;
	hdr.length = 0;
	hdr.flags = 0;
	hdr.stream_id = 0;
	int64_t carry;

	for (int i = 0; i < 10; i++) {
		hdr.type = types[i];
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
}

// ── 4.4 — SETTINGS parsing ─────────────────────────────────────────

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

// ── 4.5 — SETTINGS ACK ─────────────────────────────────────────────

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

// ── 4.2 end-to-end: malformed frames rejected without crashing ─────

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

// ── main ───────────────────────────────────────────────────────────

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
