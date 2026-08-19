// Unit tests for src/http1/keep_alive.S — http1_should_keep_alive.
//
// This is Plan.md Phase 1, Step 2: the close-rule predicate, tested in
// isolation before anything calls it (Step 3 wires the result into the
// Connection: response header; Step 6 wires it into the read/reset loop).
// The rule itself is documented in src/http1/README.md.

#include "test_harness.h"

// method ids, mirroring defs.S
#define GET_ID     0
#define HEAD_ID    1
#define OPTIONS_ID 2
#define BREW_ID    3
#define UNKNOWN_ID 4

#define LITLEN(s) ((int64_t)(sizeof(s) - 1))

// http1_should_keep_alive uses the standard ABI (args in x0-x3, boolean
// return in x0, no carry signaling), so the tests call it directly.
extern int64_t http1_should_keep_alive(const char *buf, int64_t len,
                                        int64_t method, int64_t status)
    __asm__("http1_should_keep_alive");

// no <string.h> in this harness (its libc strlen would collide with the
// asm strlen's non-standard ABI if util were ever linked in) -- a plain
// C loop is all a NUL-terminated literal needs.
static int64_t c_strlen(const char *s) {
	int64_t n = 0;
	while (s[n]) n++;
	return n;
}

static void check(const char *what, const char *req, int64_t method,
                   int64_t status, int64_t expected) {
	int64_t got = http1_should_keep_alive(req, c_strlen(req), method, status);
	ASSERT_EQ(what, expected, got);
}

// ── plain GET/HEAD/OPTIONS, HTTP/1.1, no Connection header ──────────

static void test_keep_alive_default_11(void) {
	TEST_SUITE("http1_should_keep_alive — HTTP/1.1 defaults to keep-alive");

	check("GET, HTTP/1.1, no Connection header",
	      "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", GET_ID, 200, 1);
	check("HEAD, HTTP/1.1, no Connection header",
	      "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n", HEAD_ID, 200, 1);
	check("OPTIONS, HTTP/1.1, no Connection header",
	      "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n", OPTIONS_ID, 200, 1);
}

// ── method ───────────────────────────────────────────────────────────

static void test_keep_alive_method(void) {
	TEST_SUITE("http1_should_keep_alive — method");

	check("BREW closes even at 200",
	      "BREW / HTTP/1.1\r\nHost: localhost\r\n\r\n", BREW_ID, 418, 0);
	check("UNKNOWN (POST etc) closes even at 200",
	      "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n", UNKNOWN_ID, 501, 0);
}

// ── error statuses that mean the parser lost sync ────────────────────

static void test_keep_alive_error_status(void) {
	TEST_SUITE("http1_should_keep_alive — sync-losing error statuses");

	const char *req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	check("400 closes", req, GET_ID, 400, 0);
	check("408 closes", req, GET_ID, 408, 0);
	check("413 closes", req, GET_ID, 413, 0);
	check("431 closes", req, GET_ID, 431, 0);
	check("500 closes", req, GET_ID, 500, 0);
	// statuses NOT in the lost-sync list must not close on their own
	check("403 does not force close", req, GET_ID, 403, 1);
	check("404 does not force close", req, GET_ID, 404, 1);
	check("416 does not force close", req, GET_ID, 416, 1);
}

// ── body-indicating headers: detect only ─────────────────────────────

static void test_keep_alive_body_headers(void) {
	TEST_SUITE("http1_should_keep_alive — Content-Length / Transfer-Encoding");

	check("Content-Length present closes",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
	      GET_ID, 200, 0);
	check("Transfer-Encoding present closes",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
	      GET_ID, 200, 0);
}

// ── HTTP/1.0 ─────────────────────────────────────────────────────────

static void test_keep_alive_http10(void) {
	TEST_SUITE("http1_should_keep_alive — HTTP/1.0");

	check("HTTP/1.0 with no Connection header closes",
	      "GET / HTTP/1.0\r\n\r\n", GET_ID, 200, 0);
	check("HTTP/1.0 with Connection: keep-alive stays open",
	      "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", GET_ID, 200, 1);
	check("HTTP/1.0 with Connection: close closes",
	      "GET / HTTP/1.0\r\nConnection: close\r\n\r\n", GET_ID, 200, 0);
	check("HTTP/1.0 Connection value is case-insensitive",
	      "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", GET_ID, 200, 1);
}

// ── Connection: close on HTTP/1.1 ────────────────────────────────────

static void test_keep_alive_connection_close(void) {
	TEST_SUITE("http1_should_keep_alive — Connection: close");

	check("HTTP/1.1 with Connection: close closes",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	      GET_ID, 200, 0);
	check("HTTP/1.1 Connection value is case-insensitive",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n",
	      GET_ID, 200, 0);
	check("Connection: keep-alive on HTTP/1.1 stays open (redundant but harmless)",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
	      GET_ID, 200, 1);
}

// ── token boundary: no false match on a longer token ────────────────

static void test_keep_alive_boundary(void) {
	TEST_SUITE("http1_should_keep_alive — Connection value token boundary");

	// "closed-loop" must NOT be treated as "close"
	check("Connection value starting with 'close' but longer is not close",
	      "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: closed-loop\r\n\r\n",
	      GET_ID, 200, 1);
	// "keep-alived" must NOT be treated as "keep-alive"; on HTTP/1.0 that
	// means it does NOT count as the explicit keep-alive the version needs
	check("HTTP/1.0 Connection value starting with 'keep-alive' but longer closes",
	      "GET / HTTP/1.0\r\nConnection: keep-alived\r\n\r\n", GET_ID, 200, 0);
}

// ── zero-length buffer: no request observed ──────────────────────────

static void test_keep_alive_empty_buffer(void) {
	TEST_SUITE("http1_should_keep_alive — zero-length buffer");

	int64_t got = http1_should_keep_alive("", 0, GET_ID, 200);
	ASSERT_EQ("empty buffer closes", 0, got);
}

// ── main ────────────────────────────────────────────────────────────

int main(void) {
	test_keep_alive_default_11();
	test_keep_alive_method();
	test_keep_alive_error_status();
	test_keep_alive_body_headers();
	test_keep_alive_http10();
	test_keep_alive_connection_close();
	test_keep_alive_boundary();
	test_keep_alive_empty_buffer();
	test_summary();
	return 0;
}
