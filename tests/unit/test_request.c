// Unit tests for src/parse.S parse_request — the protocol-neutral
// request representation (the seam HTTP/2 will later share).
//
// Tests that a raw HTTP/1 header is parsed into the fixed-layout
// `request` struct: method, path, path_length, query, query_length,
// authority, stream_id (always 0 for HTTP/1). The method is detected
// by the parser itself (parse → request → dispatch).

#include "test_harness.h"

// method ids, mirroring defs.S
#define GET_ID     0
#define HEAD_ID    1
#define OPTIONS_ID 2
#define BREW_ID    3
#define UNKNOWN_ID 4

// ── the request struct, mirroring the REQ_* offsets in defs.S ─────
typedef struct {
	int64_t method;
	const char *path;
	int64_t path_length;
	const char *query;
	int64_t query_length;
	const char *authority;
	int64_t stream_id;
} request_t;

// The `request` struct lives in data.S as the Mach-O symbol `request`
// (assembly symbols are not underscore-prefixed on Darwin, while C
// references are), so we load its address via inline asm rather than
// declaring it as a plain extern.
static inline const request_t *request_addr(void) {
	request_t *p;
	asm volatile(
		"adrp x0, request@PAGE\n"
		"add  x0, x0, request@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

#define REQ (request_addr())

#define LITLEN(s) ((int64_t)(sizeof(s) - 1))

// ── wrapper for parse_request ─────────────────────────────────────
// (buf=x0, len=x1) → carry flag
static inline int64_t parse_request_wrapper(const char *buf, int64_t len)
{
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"bl parse_request\n"
		"cset %0, cs\n"
		: "=r"(carry)
		: "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
		  "memory"
	);
	return carry;
}

// ── tests: GET ────────────────────────────────────────────────────

static void test_parse_request_get(void) {
	TEST_SUITE("parse_request — GET");

	const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int64_t len = LITLEN("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == GET_ID", GET_ID, REQ->method);
	ASSERT_EQ("stream_id == 0 (HTTP/1)", 0, REQ->stream_id);
	ASSERT_STR_EQ("path = www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
	ASSERT_EQ("path_length", LITLEN("www/index.html"), REQ->path_length);
	ASSERT_EQ("query == NULL", 0, (int64_t)REQ->query);
	ASSERT_EQ("query_length == 0", 0, REQ->query_length);
	ASSERT_STR_EQ("authority = localhost", "localhost",
	              REQ->authority, LITLEN("localhost"));
}

static void test_parse_request_query(void) {
	TEST_SUITE("parse_request — query string");

	const char *req =
		"GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
	int64_t len = LITLEN(
		"GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_STR_EQ("path = www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
	ASSERT_EQ("path_length", LITLEN("www/index.html"), REQ->path_length);
	ASSERT_STR_EQ("query = x=1&y=2", "x=1&y=2",
	              REQ->query, LITLEN("x=1&y=2"));
	ASSERT_EQ("query_length", LITLEN("x=1&y=2"), REQ->query_length);
	ASSERT_STR_EQ("authority = example.com", "example.com",
	              REQ->authority, LITLEN("example.com"));
	ASSERT_EQ("stream_id == 0", 0, REQ->stream_id);
}

// query strings are NOT percent-decoded — only the path is.
static void test_parse_request_query_raw(void) {
	TEST_SUITE("parse_request — query kept raw");

	const char *req =
		"GET /index.html?q=hello%20world HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int64_t len = LITLEN(
		"GET /index.html?q=hello%20world HTTP/1.1\r\nHost: localhost\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_STR_EQ("query = q=hello%20world", "q=hello%20world",
	              REQ->query, LITLEN("q=hello%20world"));
	ASSERT_EQ("query_length", LITLEN("q=hello%20world"), REQ->query_length);
}

// ── tests: HEAD and OPTIONS ───────────────────────────────────────

static void test_parse_request_head(void) {
	TEST_SUITE("parse_request — HEAD");

	const char *req = "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int64_t len = LITLEN("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == HEAD_ID", HEAD_ID, REQ->method);
	ASSERT_EQ("path default applied", LITLEN("www/index.html"),
	          REQ->path_length);
	ASSERT_EQ("stream_id == 0", 0, REQ->stream_id);
}

static void test_parse_request_options(void) {
	TEST_SUITE("parse_request — OPTIONS");

	const char *req = "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int64_t len = LITLEN("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == OPTIONS_ID", OPTIONS_ID, REQ->method);
	// OPTIONS never gets a default file — bare docroot path.
	ASSERT_STR_EQ("path = www/", "www/", REQ->path, LITLEN("www/"));
	ASSERT_EQ("path_length = 4", LITLEN("www/"), REQ->path_length);

	req = "OPTIONS /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("OPTIONS /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_STR_EQ("path = www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));

	req = "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("asterisk path_length", 1, REQ->path_length);
	ASSERT_EQ("asterisk path", '*', REQ->path[0]);
}

// ── tests: method detection ───────────────────────────────────────

static void test_parse_request_methods(void) {
	TEST_SUITE("parse_request — method detection");

	const char *req;
	int64_t len, carry;

	// unknown methods parse cleanly but record UNKNOWN_ID (dispatch → 501)
	req = "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("POST / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("POST carry clear", 0, carry);
	ASSERT_EQ("POST method == UNKNOWN_ID", UNKNOWN_ID, REQ->method);

	req = "DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("DELETE method == UNKNOWN_ID", UNKNOWN_ID, REQ->method);

	// BREW is detected separately (dispatch → 418)
	req = "BREW / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("BREW / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("BREW carry clear", 0, carry);
	ASSERT_EQ("BREW method == BREW_ID", BREW_ID, REQ->method);
}

// ── tests: authority ──────────────────────────────────────────────

static void test_parse_request_authority(void) {
	TEST_SUITE("parse_request — authority");

	// HTTP/1.0 does not require Host; authority must be NULL.
	const char *req = "GET / HTTP/1.0\r\n\r\n";
	int64_t len = LITLEN("GET / HTTP/1.0\r\n\r\n");
	int64_t carry = parse_request_wrapper(req, len);

	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("authority == NULL", 0, (int64_t)REQ->authority);
	ASSERT_EQ("stream_id == 0", 0, REQ->stream_id);

	// Host with a port is copied verbatim.
	req = "GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
	len = LITLEN("GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_STR_EQ("authority = localhost:8080", "localhost:8080",
	              REQ->authority, LITLEN("localhost:8080"));
}

// ── tests: rejections ─────────────────────────────────────────────

static void test_parse_request_rejects(void) {
	TEST_SUITE("parse_request — rejections");

	const char *req;
	int64_t len, carry;

	// no path within the first 16 bytes
	req = "GET HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("GET HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("no path → carry set", 1, carry);

	// literal path traversal
	req = "GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("../ → carry set", 1, carry);

	// percent-encoded traversal decodes to ../ and is then caught
	req = "GET /%2e%2e%2fetc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n";
	len = LITLEN("GET /%2e%2e%2fetc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_request_wrapper(req, len);
	ASSERT_EQ("%2e%2e%2f → carry set", 1, carry);
}

// ── main ──────────────────────────────────────────────────────────

int main(void) {
	test_parse_request_get();
	test_parse_request_query();
	test_parse_request_query_raw();
	test_parse_request_head();
	test_parse_request_options();
	test_parse_request_methods();
	test_parse_request_authority();
	test_parse_request_rejects();
	test_summary();
	return 0;
}
