// Unit tests for src/http1/reset_request.S — http1_reset_request.
//
// Plan.md Phase 1, Step 4: every location poisoned with non-zero /
// non-default bytes before the call must come back to zero (or its
// documented initial value) afterward, and the handful of locations the
// routine must NOT touch (clientfd, buf, request_header_len) must survive
// unchanged. See src/http1/README.md for which is which.

#include "test_harness.h"

// sizes mirror the .bss allocations in src/data.S, src/http1/data.S,
// src/parse/data.S and src/parse/parse_range.S (padded to 16-byte
// multiples the same way those files compute them)
#define REQUEST_SIZE            80
#define RESPONSE_SIZE           64
#define FILENAME_BUF_SIZE       4112  // (4096 + 1 + 15) & ~15
#define QUERY_BUF_SIZE          4096
#define AUTHORITY_BUF_SIZE      272   // (256 + 1 + 15) & ~15
#define RANGE_BUF_SIZE          32    // (19 + 15) & ~15
#define HEADER_BUF_SIZE         512

extern void http1_reset_request(void) __asm__("http1_reset_request");

extern uint8_t request[REQUEST_SIZE]        __asm__("request");
extern uint8_t response[RESPONSE_SIZE]      __asm__("response");
extern uint8_t filename_buf[FILENAME_BUF_SIZE]   __asm__("filename_buf");
extern uint8_t query_buf[QUERY_BUF_SIZE]         __asm__("query_buf");
extern uint8_t authority_buf[AUTHORITY_BUF_SIZE] __asm__("authority_buf");
extern uint8_t range_buf[RANGE_BUF_SIZE]         __asm__("range_buf");
extern uint8_t header_buf[HEADER_BUF_SIZE]       __asm__("header_buf");

extern int64_t header_len          __asm__("header_len");
extern int64_t resource_type       __asm__("resource_type");
extern int64_t embedded_content    __asm__("embedded_content");
extern int64_t embedded_ct         __asm__("embedded_ct");
extern int64_t embedded_ct_len     __asm__("embedded_ct_len");
extern int64_t embedded_etag       __asm__("embedded_etag");
extern int64_t embedded_etag_len   __asm__("embedded_etag_len");
extern int64_t embedded_gzip       __asm__("embedded_gzip");
extern int64_t file_des            __asm__("file_des");
extern int64_t connection_mode     __asm__("connection_mode");

// deliberately NOT reset — checked to prove they survive untouched
extern int64_t clientfd            __asm__("clientfd");
extern int64_t request_header_len  __asm__("request_header_len");
extern uint8_t buf[64]             __asm__("buf"); // only need the first bytes

static int is_all_zero(const void *p, unsigned long n) {
	const uint8_t *b = (const uint8_t *)p;
	for (unsigned long i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

// poison every field this routine is supposed to reset, plus the three
// it must leave alone (with a distinct sentinel, checked separately)
static void poison_all(void) {
	memset(request, 0xAA, REQUEST_SIZE);
	memset(response, 0xAA, RESPONSE_SIZE);
	memset(filename_buf, 0xAA, FILENAME_BUF_SIZE);
	memset(query_buf, 0xAA, QUERY_BUF_SIZE);
	memset(authority_buf, 0xAA, AUTHORITY_BUF_SIZE);
	memset(range_buf, 0xAA, RANGE_BUF_SIZE);
	memset(header_buf, 0xAA, HEADER_BUF_SIZE);

	header_len = 0x1111;
	resource_type = 1; // RES_EMBEDDED
	embedded_content = 0x2222;
	embedded_ct = 0x3333;
	embedded_ct_len = 0x4444;
	embedded_etag = 0x5555;
	embedded_etag_len = 0x6666;
	embedded_gzip = 1;
	file_des = 42;
	connection_mode = 99;

	clientfd = 7;
	request_header_len = 123;
	memset(buf, 0xAA, sizeof(buf));
}

static void test_reset_zeroes_buffers(void) {
	TEST_SUITE("http1_reset_request — buffers zeroed");

	poison_all();
	http1_reset_request();

	ASSERT_TRUE("request zeroed", is_all_zero(request, REQUEST_SIZE));
	ASSERT_TRUE("response zeroed", is_all_zero(response, RESPONSE_SIZE));
	ASSERT_TRUE("filename_buf zeroed", is_all_zero(filename_buf, FILENAME_BUF_SIZE));
	ASSERT_TRUE("query_buf zeroed", is_all_zero(query_buf, QUERY_BUF_SIZE));
	ASSERT_TRUE("authority_buf zeroed", is_all_zero(authority_buf, AUTHORITY_BUF_SIZE));
	ASSERT_TRUE("range_buf zeroed", is_all_zero(range_buf, RANGE_BUF_SIZE));
	ASSERT_TRUE("header_buf zeroed", is_all_zero(header_buf, HEADER_BUF_SIZE));
}

static void test_reset_zeroes_scalars(void) {
	TEST_SUITE("http1_reset_request — scalar fields");

	poison_all();
	http1_reset_request();

	ASSERT_EQ("header_len == 0", 0, header_len);
	ASSERT_EQ("resource_type == RES_NONE (0)", 0, resource_type);
	ASSERT_EQ("embedded_content == 0", 0, embedded_content);
	ASSERT_EQ("embedded_ct == 0", 0, embedded_ct);
	ASSERT_EQ("embedded_ct_len == 0", 0, embedded_ct_len);
	ASSERT_EQ("embedded_etag == 0", 0, embedded_etag);
	ASSERT_EQ("embedded_etag_len == 0", 0, embedded_etag_len);
	ASSERT_EQ("embedded_gzip == 0", 0, embedded_gzip);
}

static void test_reset_documented_initial_values(void) {
	TEST_SUITE("http1_reset_request — documented initial values (not zero)");

	poison_all();
	http1_reset_request();

	ASSERT_EQ("file_des == -1 (not open)", -1, file_des);
	ASSERT_EQ("connection_mode == CONNECTION_HTTP1 (0)", 0, connection_mode);
}

static void test_reset_leaves_connection_state_alone(void) {
	TEST_SUITE("http1_reset_request — connection state untouched");

	poison_all();
	http1_reset_request();

	ASSERT_EQ("clientfd unchanged", 7, clientfd);
	ASSERT_EQ("request_header_len unchanged", 123, request_header_len);
	ASSERT_TRUE("buf unchanged", !is_all_zero(buf, sizeof(buf)));
}

// ── main ────────────────────────────────────────────────────────────

int main(void) {
	test_reset_zeroes_buffers();
	test_reset_zeroes_scalars();
	test_reset_documented_initial_values();
	test_reset_leaves_connection_state_alone();
	test_summary();
	return 0;
}
