// Unit tests for src/h2/ — Stage 8: HEADERS → HPACK → the common
// request. h2_handle_headers extracts stream id, the header block and
// the END_STREAM/END_HEADERS flags and feeds the block to the HPACK
// decoder (8.1); h2_build_request decodes the request pseudo-headers
// :method/:path/:scheme/:authority into the protocol-neutral `request`
// struct (8.2); malformed requests are rejected with PROTOCOL_ERROR
// (8.3); and an HTTP/2 /index.html request produces byte-identical
// path/query/authority to the HTTP/1 parse (8.4).

#include "test_h2_common.h"

static void test_h2_headers_hpack(void) {
	TEST_SUITE("h2_handle_headers — 8.1 HEADERS reaches the HPACK decoder");

	uint8_t wire[9];
	uint8_t payload[32];
	// :method GET, :scheme https, :path /index.html,
	// :authority example.com (literal without indexing, indexed name)
	static const uint8_t block[] = {
		0x82, 0x87, 0x85,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	memcpy(payload, block, sizeof(block));
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);
	reset_fields();

	put_wire_header(wire, sizeof(block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// stream id + flags extracted onto the stream entry
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_NOT_NULL("stream 1 created", s);
	ASSERT_EQ("END_STREAM extracted", H2_FLAG_END_STREAM,
	          s->flags & H2_FLAG_END_STREAM);
	ASSERT_EQ("END_HEADERS extracted", H2_FLAG_END_HEADERS,
	          s->flags & H2_FLAG_END_HEADERS);
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s->state);

	// the header block reached the HPACK decoder
	h2_hpack_field_t *f = h2_hpack_fields_addr();
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme https", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "https");
	check_field("field 2 :path /index.html", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":path", "/index.html");
	check_field("field 3 :authority example.com", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":authority", "example.com");
	ASSERT_EQ("exactly 4 fields decoded", 0, f[4].name_len);

	// ... and the request was built from them
	ASSERT_EQ("request method GET", GET_ID, REQ->method);
	ASSERT_EQ("request stream id", 1, REQ->stream_id);
	ASSERT_STR_EQ("request path www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
}

// §6.2 — PADDED and PRIORITY put extra octets in front of the header
// block fragment. Chrome sets PRIORITY on its request HEADERS, so leaving
// those five octets in place hands 0x80 to the HPACK decoder as an
// indexed field with index 0 and the connection dies with
// COMPRESSION_ERROR on the very first request.
static void test_h2_headers_prefix_fields(void) {
	TEST_SUITE("h2_handle_headers — 8.5 PADDED/PRIORITY prefix stripping");

	// :method GET, :scheme https, :path /index.html
	static const uint8_t block[] = { 0x82, 0x87, 0x85 };
	uint8_t wire[9];
	uint8_t payload[64];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;
	unsigned long n;

	// ── PRIORITY alone — the exact five octets Chrome sends ─────────
	static const uint8_t prio[] = { 0x80, 0x00, 0x00, 0x00, 0xff };
	memcpy(payload, prio, sizeof(prio));
	memcpy(payload + sizeof(prio), block, sizeof(block));
	n = sizeof(prio) + sizeof(block);

	reset_streams();
	reset_conn(&conn);
	reset_fields();
	put_wire_header(wire, (uint32_t)n, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS |
	                H2_FLAG_PRIORITY, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("PRIORITY HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	h2_hpack_field_t *f = h2_hpack_fields_addr();
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 2 :path /index.html", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":path", "/index.html");

	// ── PADDED alone — Pad Length octet, then the block, then padding ─
	payload[0] = 4; // Pad Length
	memcpy(payload + 1, block, sizeof(block));
	memset(payload + 1 + sizeof(block), 0, 4);
	n = 1 + sizeof(block) + 4;

	reset_streams();
	reset_conn(&conn);
	reset_fields();
	put_wire_header(wire, (uint32_t)n, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS |
	                H2_FLAG_PADDED, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("PADDED HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	f = h2_hpack_fields_addr();
	check_field("padded field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");

	// ── both flags together — pad length, priority, block, padding ───
	payload[0] = 2;
	memcpy(payload + 1, prio, sizeof(prio));
	memcpy(payload + 1 + sizeof(prio), block, sizeof(block));
	memset(payload + 1 + sizeof(prio) + sizeof(block), 0, 2);
	n = 1 + sizeof(prio) + sizeof(block) + 2;

	reset_streams();
	reset_conn(&conn);
	reset_fields();
	put_wire_header(wire, (uint32_t)n, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS |
	                H2_FLAG_PADDED | H2_FLAG_PRIORITY, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("PADDED+PRIORITY HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	f = h2_hpack_fields_addr();
	check_field("both field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");

	// ── §6.1 — padding longer than the payload is a PROTOCOL_ERROR ──
	payload[0] = 200;
	memcpy(payload + 1, block, sizeof(block));
	n = 1 + sizeof(block);

	reset_streams();
	reset_conn(&conn);
	reset_fields();
	put_wire_header(wire, (uint32_t)n, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS |
	                H2_FLAG_PADDED, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("over-long padding rejected", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// ── §6.2 — PRIORITY set but fewer than 5 octets is FRAME_SIZE ───
	memcpy(payload, prio, 3);
	reset_streams();
	reset_conn(&conn);
	reset_fields();
	put_wire_header(wire, 3, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS |
	                H2_FLAG_PRIORITY, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("truncated priority field rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
}

static void test_h2_pseudo_request(void) {
	TEST_SUITE("h2_build_request — 8.2 pseudo-headers → common request");

	uint8_t wire[9];
	uint8_t payload[32];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// :method GET, :path / — the required pair, nothing else
	reset_streams();
	reset_conn(&conn);
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GET / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == GET_ID", GET_ID, REQ->method);
	ASSERT_EQ("stream_id == 1", 1, REQ->stream_id);
	ASSERT_STR_EQ("path = www/index.html (default file)", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
	ASSERT_EQ("path_length", LITLEN("www/index.html"), REQ->path_length);
	ASSERT_EQ("query == NULL", 0, (int64_t)REQ->query);
	ASSERT_EQ("query_length == 0", 0, REQ->query_length);
	ASSERT_EQ("authority == NULL", 0, (int64_t)REQ->authority);

	// :scheme and :authority are carried along
	reset_streams();
	reset_conn(&conn);
	static const uint8_t full[] = {
		0x82, 0x87, 0x84,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	memcpy(payload, full, sizeof(full));
	put_wire_header(wire, sizeof(full), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GET / with scheme+authority accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream_id == 3", 3, REQ->stream_id);
	ASSERT_STR_EQ("authority = example.com", "example.com",
	              REQ->authority, LITLEN("example.com"));

	// HEAD / — the default file applies to HEAD too (HEAD is not in the
	// RFC 7541 static table, so it must be sent as a literal value)
	reset_streams();
	reset_conn(&conn);
	static const uint8_t head_block[] = {
		0x02, 0x04, 'H', 'E', 'A', 'D', 0x84, // :method HEAD, :path /
	};
	memcpy(payload, head_block, sizeof(head_block));
	put_wire_header(wire, sizeof(head_block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 5);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEAD / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("method == HEAD_ID", HEAD_ID, REQ->method);
	ASSERT_STR_EQ("path = www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));

	// OPTIONS / — no default file, the bare docroot path
	reset_streams();
	reset_conn(&conn);
	static const uint8_t options_block[] = {
		0x02, 0x07, 'O', 'P', 'T', 'I', 'O', 'N', 'S', 0x84,
	};
	memcpy(payload, options_block, sizeof(options_block));
	put_wire_header(wire, sizeof(options_block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 7);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("OPTIONS / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("method == OPTIONS_ID", OPTIONS_ID, REQ->method);
	ASSERT_STR_EQ("path = www/", "www/", REQ->path, LITLEN("www/"));
	ASSERT_EQ("path_length = 4", LITLEN("www/"), REQ->path_length);
}

static void test_h2_pseudo_validate(void) {
	TEST_SUITE("h2_build_request — 8.3 malformed pseudo-headers rejected");

	h2_hpack_field_t f[4];
	int64_t carry;

	// missing :method
	f[0] = field(":path", "/");
	set_fields(f, 1);
	ASSERT_EQ("missing :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 1, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// an empty block — no pseudo-headers at all
	set_fields(f, 0);
	ASSERT_EQ("empty block → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 0, &carry));

	// empty :method counts as missing
	f[0] = field(":method", "");
	f[1] = field(":path", "/");
	set_fields(f, 2);
	ASSERT_EQ("empty :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 2, &carry));

	// missing :path for a normal (GET) request
	f[0] = field(":method", "GET");
	set_fields(f, 1);
	ASSERT_EQ("missing :path → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 1, &carry));

	// duplicate pseudo-headers
	f[0] = field(":method", "GET");
	f[1] = field(":method", "GET");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("duplicate :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// a pseudo-header after a regular header
	f[0] = field(":method", "GET");
	f[1] = field("accept", "text/html");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("pseudo after regular → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// an undefined pseudo-header (:status is response-only)
	f[0] = field(":method", "GET");
	f[1] = field(":status", "200");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("undefined pseudo-header → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// a path that is not origin-form (no leading '/') is malformed
	f[0] = field(":method", "GET");
	f[1] = field(":path", "index.html");
	set_fields(f, 2);
	ASSERT_EQ("non-origin :path → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 2, &carry));

	// BREW is not a normal request — no :path required, like HTTP/1
	f[0] = field(":method", "BREW");
	set_fields(f, 1);
	ASSERT_EQ("BREW without :path accepted", 0,
	          h2_build_request_wrapper(3, 1, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == BREW_ID", BREW_ID, REQ->method);
	ASSERT_EQ("stream_id == 3", 3, REQ->stream_id);
}

static void test_h2_request_equivalence(void) {
	TEST_SUITE("8.4 HTTP/2 request == HTTP/1 request (same internal form)");

	h2_hpack_field_t f[3];
	int64_t carry;
	char path1[64], auth1[64], q1buf[64];

	// ── /index.html, no query ──
	const char *req1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req1, LITLEN("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")));

	int64_t method1 = REQ->method;
	int64_t plen1 = REQ->path_length;
	int64_t qptr1 = (int64_t)REQ->query;
	int64_t qlen1 = REQ->query_length;
	int64_t alen1 = 0;
	while (REQ->authority[alen1]) alen1++;
	memcpy(path1, REQ->path, (unsigned long)plen1);
	memcpy(auth1, REQ->authority, (unsigned long)alen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field(":authority", "example.com");
	set_fields(f, 3);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 3, &carry));

	ASSERT_EQ("method identical", method1, REQ->method);
	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);
	ASSERT_EQ("query identical (NULL)", qptr1, (int64_t)REQ->query);
	ASSERT_EQ("query_length identical", qlen1, REQ->query_length);
	int64_t alen2 = 0;
	while (REQ->authority[alen2]) alen2++;
	ASSERT_EQ("authority length identical", alen1, alen2);
	ASSERT_TRUE("authority bytes identical",
	            memcmp(auth1, REQ->authority, (unsigned long)alen1) == 0);
	// the one intentional difference: HTTP/2 carries the stream id
	ASSERT_EQ("stream_id = 1 (HTTP/2)", 1, REQ->stream_id);

	// ── /index.html?x=1&y=2 — the query is carried raw on both sides ──
	const char *req2 =
		"GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req2, LITLEN(
		          "GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")));

	plen1 = REQ->path_length;
	qlen1 = REQ->query_length;
	memcpy(path1, REQ->path, (unsigned long)plen1);
	memcpy(q1buf, REQ->query, (unsigned long)qlen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html?x=1&y=2");
	f[2] = field(":authority", "example.com");
	set_fields(f, 3);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 3, &carry));

	ASSERT_EQ("query_length identical", qlen1, REQ->query_length);
	ASSERT_TRUE("query bytes identical",
	            memcmp(q1buf, REQ->query, (unsigned long)qlen1) == 0);
	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);

	// ── percent-encoding — both sides decode %XX the same way ──
	const char *req3 = "GET /a%20b HTTP/1.1\r\nHost: localhost\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req3, LITLEN("GET /a%20b HTTP/1.1\r\nHost: localhost\r\n\r\n")));

	plen1 = REQ->path_length;
	memcpy(path1, REQ->path, (unsigned long)plen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/a%20b");
	set_fields(f, 2);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 2, &carry));

	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);
}

int main(void) {
	test_h2_headers_hpack();
	test_h2_headers_prefix_fields();
	test_h2_pseudo_request();
	test_h2_pseudo_validate();
	test_h2_request_equivalence();
	test_summary();
	return 0;
}
