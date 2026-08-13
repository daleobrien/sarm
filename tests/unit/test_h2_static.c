// Unit tests for src/http2.S — Stage 10: complete static responses.
// HEAD (headers only, END_STREAM on the HEADERS frame), 404 (unresolved
// resource), 403 (a path the server refuses to serve), MIME types
// identical to HTTP/1's, and byte ranges — h2_parse_range /
// h2_resolve_range turn a `range` header into a 206 with content-range
// or a 416.

#include "test_h2_common.h"

static void test_h2_head_no_body(void) {
	TEST_SUITE("10.1 HEAD — headers only (END_STREAM on HEADERS, no DATA)");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "HEAD");
	f[1] = field(":path", "/index.html");

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	// HEADERS (9 + 33 block) and nothing else: 42 bytes, no DATA frame
	ASSERT_EQ("42 response bytes — no body", 42, n);
	// flags = END_HEADERS | END_STREAM (0x05)
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	// content-length still reflects the full resource (17), like HTTP/1
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 17 (full resource)", "17", cl, vlen);
}

static void test_h2_head_ignores_range(void) {
	TEST_SUITE("10.5 HEAD + Range — range ignored (HTTP/1 parity)");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "HEAD");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=0-9");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	ASSERT_EQ("42 response bytes — no body", 42, n);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 200 (not 206)", "200", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 17", "17", cl, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_TRUE("no content-range", cr == NULL);
}

static void test_h2_404(void) {
	TEST_SUITE("10.2 GET /does-not-exist — 404");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/does-not-exist");

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	// literal :status 404 + content-length 0 → 9-byte block → 18 bytes
	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 404", "404", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 0", "0", cl, vlen);
}

static void test_h2_403(void) {
	TEST_SUITE("10.3 GET /../etc/passwd — 403 (inaccessible resource)");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/../etc/passwd");

	// the request decodes cleanly — the path failing the traversal check
	// is REQ_FORBIDDEN, not a protocol error
	reset_fields();
	int64_t carry;
	set_fields(f, 2);
	ASSERT_EQ("request builds (no protocol error)", 0,
	          h2_build_request_wrapper(1, 2, &carry));
	ASSERT_EQ("REQ_FORBIDDEN set", 1, REQ->forbidden);

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 403", "403", st, vlen);
}

static void test_h2_mime(void) {
	TEST_SUITE("10.4 MIME types — .html/.css/.js/.svg/.png match HTTP/1");

	static const char *paths[] = {
		"/index.html", "/assets/style.css", "/assets/app.js",
		"/logo.svg", "/logo.png",
	};
	static const char *cts[] = {
		"text/html; charset=utf-8",
		"text/css; charset=utf-8",
		"text/javascript; charset=utf-8",
		"image/svg+xml",
		"image/png",
	};

	for (int i = 0; i < 5; i++) {
		// the HTTP/1 side derives the type from the extension (file.S)
		const char *h1_ct = NULL;
		int64_t h1_ct_len = 0;
		get_filetype_wrapper(paths[i], slen(paths[i]), &h1_ct, &h1_ct_len);

		h2_hpack_field_t f[2];
		f[0] = field(":method", "GET");
		f[1] = field(":path", paths[i]);
		uint8_t got[512];
		long n = serve_request(f, 2, got, sizeof(got));

		hdr_scan_t h;
		scan_block(got + 9, n - 9, &h);
		long vlen = 0;
		const uint8_t *ct = scan_find(&h, 31, &vlen);
		ASSERT_NOT_NULL("content-type present", ct);
		if (!ct) continue;
		ASSERT_TRUE("content-type == HTTP/1 get_filetype",
		            vlen == h1_ct_len &&
		            memcmp(ct, h1_ct, (unsigned long)vlen) == 0);
		ASSERT_TRUE("content-type == expected",
		            vlen == slen(cts[i]) &&
		            memcmp(ct, cts[i], (unsigned long)vlen) == 0);
	}
}

static void test_h2_range(void) {
	TEST_SUITE("10.5 GET + Range: bytes=0-9 — 206 with content-range");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=0-9");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// block: literal :status 206 + content-type + content-length 10 +
	// content-range 0-9/17 → 46 bytes; DATA: 9 + 10 → 74 total
	ASSERT_EQ("74 response bytes", 74, n);
	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	ASSERT_EQ("46-byte HPACK block", 46, blen);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 206", "206", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 10", "10", cl, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 0-9/17", "0-9/17", cr, vlen);

	// the DATA frame carries exactly the requested window
	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 10",
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2],
	          10);
	ASSERT_EQ("DATA type", H2_FRAME_DATA, got[data_off + 3]);
	ASSERT_EQ("DATA END_STREAM", H2_FLAG_END_STREAM, got[data_off + 4]);
	ASSERT_STR_EQ("body = first 10 bytes", "<h1>hello ", got + data_off + 9, 10);
}

static void test_h2_range_open(void) {
	TEST_SUITE("10.5 GET + Range: bytes=10- — open-ended 206");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=10-");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 10-16/17", "10-16/17", cr, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 7", "7", cl, vlen);

	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 7", 7,
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2]);
	ASSERT_STR_EQ("body = h2</h1>", "h2</h1>", got + data_off + 9, 7);
}

static void test_h2_range_suffix(void) {
	TEST_SUITE("10.5 GET + Range: bytes=-5 — suffix 206");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=-5");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 12-16/17", "12-16/17", cr, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 5", "5", cl, vlen);

	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 5", 5,
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2]);
	ASSERT_STR_EQ("body = </h1>", "</h1>", got + data_off + 9, 5);
}

static void test_h2_range_unsatisfiable(void) {
	TEST_SUITE("10.5 GET + Range: bytes=100- — 416");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=100-");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// literal :status 416 + content-length 0 → 9-byte block → 18 bytes
	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 416", "416", st, vlen);
}

static void test_h2_range_invalid(void) {
	TEST_SUITE("10.5 GET + unparsable Range — ignored, full 200");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "garbage");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// the full 200 response: HEADERS (42) + DATA (26)
	ASSERT_EQ("68 response bytes", 68, n);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 200", "200", st, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_TRUE("no content-range", cr == NULL);
}

static void test_h2_parse_range(void) {
	TEST_SUITE("10.5 h2_parse_range — Range header value parsing");

	int64_t end, carry;

	// concrete range
	ASSERT_EQ("bytes=0-99 → start 0", 0,
	          h2_parse_range_wrapper("bytes=0-99", 10, &end, &carry));
	ASSERT_EQ("bytes=0-99 → end 99", 99, end);
	ASSERT_EQ("carry clear", 0, carry);

	// open-ended
	ASSERT_EQ("bytes=100- → start 100", 100,
	          h2_parse_range_wrapper("bytes=100-", 10, &end, &carry));
	ASSERT_EQ("bytes=100- → end -1", -1, end);
	ASSERT_EQ("carry clear", 0, carry);

	// suffix
	ASSERT_EQ("bytes=-50 → start -1", -1,
	          h2_parse_range_wrapper("bytes=-50", 9, &end, &carry));
	ASSERT_EQ("bytes=-50 → end 50", 50, end);
	ASSERT_EQ("carry clear", 0, carry);

	// case-insensitive unit, single-byte range
	ASSERT_EQ("Bytes=0-0 → start 0", 0,
	          h2_parse_range_wrapper("Bytes=0-0", 9, &end, &carry));
	ASSERT_EQ("Bytes=0-0 → end 0", 0, end);
	ASSERT_EQ("carry clear", 0, carry);

	// invalid values — carry set, treated as "no range" (like HTTP/1)
	h2_parse_range_wrapper("garbage", 7, &end, &carry);
	ASSERT_EQ("non-bytes unit rejected", 1, carry);
	h2_parse_range_wrapper("bytes=", 6, &end, &carry);
	ASSERT_EQ("empty value rejected", 1, carry);
	h2_parse_range_wrapper("bytes=abc", 9, &end, &carry);
	ASSERT_EQ("non-digit start rejected", 1, carry);
	h2_parse_range_wrapper("bytes=10-5", 10, &end, &carry);
	ASSERT_EQ("end < start rejected", 1, carry);
	h2_parse_range_wrapper("bytes=0-99,200-299", 19, &end, &carry);
	ASSERT_EQ("multi-range rejected (single range only)", 1, carry);
	h2_parse_range_wrapper("bytes=0", 7, &end, &carry);
	ASSERT_EQ("no dash rejected", 1, carry);
}

static void test_h2_resolve_range(void) {
	TEST_SUITE("10.5 h2_resolve_range — range → 200/206/416");

	int64_t end, status;

	// 17-byte resource (the stub index.html)
	ASSERT_EQ("0-9/17 → start 0", 0, h2_resolve_range_wrapper(0, 9, 17, &end, &status));
	ASSERT_EQ("0-9/17 → end 9", 9, end);
	ASSERT_EQ("0-9/17 → 206", 206, status);

	// end clamped to size-1
	ASSERT_EQ("10-99/17 → start 10", 10,
	          h2_resolve_range_wrapper(10, 99, 17, &end, &status));
	ASSERT_EQ("10-99/17 → end 16", 16, end);
	ASSERT_EQ("10-99/17 → 206", 206, status);

	// open-ended
	ASSERT_EQ("12-/17 → start 12", 12,
	          h2_resolve_range_wrapper(12, -1, 17, &end, &status));
	ASSERT_EQ("12-/17 → end 16", 16, end);
	ASSERT_EQ("12-/17 → 206", 206, status);

	// suffix
	ASSERT_EQ("-5/17 → start 12", 12,
	          h2_resolve_range_wrapper(-1, 5, 17, &end, &status));
	ASSERT_EQ("-5/17 → end 16", 16, end);
	ASSERT_EQ("-5/17 → 206", 206, status);

	// suffix >= size → the whole file, still a 206 (mirrors get.S: the
	// range is clamped to the file, so it's satisfiable — no 200 path)
	ASSERT_EQ("-99/17 → start 0", 0,
	          h2_resolve_range_wrapper(-1, 99, 17, &end, &status));
	ASSERT_EQ("-99/17 → end 16", 16, end);
	ASSERT_EQ("-99/17 → 206", 206, status);

	// start >= size → 416
	ASSERT_EQ("17-/17 → 416", -1,
	          h2_resolve_range_wrapper(17, -1, 17, &end, &status));
	ASSERT_EQ("17-/17 status 416", 416, status);
	ASSERT_EQ("99-100/17 → 416", -1,
	          h2_resolve_range_wrapper(99, 100, 17, &end, &status));
	ASSERT_EQ("99-100/17 status 416", 416, status);

	// bytes=-0 → 416; empty-file edge cases
	ASSERT_EQ("-0/17 → 416", -1, h2_resolve_range_wrapper(-1, 0, 17, &end, &status));
	ASSERT_EQ("-0/17 status 416", 416, status);
	ASSERT_EQ("0-9/0 → 416 (empty file)", -1,
	          h2_resolve_range_wrapper(0, 9, 0, &end, &status));
	ASSERT_EQ("0-9/0 status 416", 416, status);
	ASSERT_EQ("-5/0 → 200 (empty file)", -1,
	          h2_resolve_range_wrapper(-1, 5, 0, &end, &status));
	ASSERT_EQ("-5/0 status 200", 200, status);
}

static void test_h2_write_headers_206(void) {
	TEST_SUITE("10.5 h2_write_headers — 206 (content-length + content-range)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello h2</h1>";
	response_t resp = {
		.status = 206,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),  // total resource size
		.body = body,
		.body_length = 10,               // the 0-9 window
		.range_start = 0,
		.range_end = 9,
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

	// block: 0x08 0x03 "206" | ct (static 31) | content-length 10
	// (static 28) | content-range 0-9/17 (static 30 → 0x0f 0x0f)
	// = 5 + 27 + 5 + 9 = 46 bytes; frame = 9 + 46 = 55
	uint8_t expect[] = {
		0x00, 0x00, 0x2e, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x03, '2', '0', '6',
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '0',
		0x0f, 0x0f, 0x06, '0', '-', '9', '/', '1', '7',
	};
	ASSERT_EQ("55 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the 206 HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

int main(void) {
	test_h2_head_no_body();
	test_h2_head_ignores_range();
	test_h2_404();
	test_h2_403();
	test_h2_mime();
	test_h2_range();
	test_h2_range_open();
	test_h2_range_suffix();
	test_h2_range_unsatisfiable();
	test_h2_range_invalid();
	test_h2_parse_range();
	test_h2_resolve_range();
	test_h2_write_headers_206();
	test_summary();
	return 0;
}
