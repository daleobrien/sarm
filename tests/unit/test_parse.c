// Unit tests for src/parse.S assembly functions
// Tests: parse_header_end, get_header_field, parse_range
//
// NOTE: Avoids libc strlen()/snprintf() due to linking against util.o.

#include "test_harness.h"

// ── helper: compute string length from a literal ───────────────────
#define LITLEN(s) ((int64_t)(sizeof(s) - 1))

// ── helper: build a Range header manually ──────────────────────────
static int64_t build_range_header(char *buf, int64_t bufsz,
                                  int64_t rstart, int64_t rend)
{
	char start_str[20], end_str[20];
	int64_t start_len = 0, end_len = 0;

	if (rstart >= 0) {
		int64_t n = rstart; int pos = 19;
		start_str[pos] = '\0';
		if (n == 0) { start_str[--pos] = '0'; start_len = 1; }
		else { while (n > 0 && pos > 0) {
			start_str[--pos] = (char)('0' + (n % 10)); n /= 10; start_len++;
		}}
		memmove(start_str, start_str + pos, (size_t)start_len);
		start_str[start_len] = '\0';
	}
	if (rend >= 0) {
		int64_t n = rend; int pos = 19;
		end_str[pos] = '\0';
		if (n == 0) { end_str[--pos] = '0'; end_len = 1; }
		else { while (n > 0 && pos > 0) {
			end_str[--pos] = (char)('0' + (n % 10)); n /= 10; end_len++;
		}}
		memmove(end_str, end_str + pos, (size_t)end_len);
		end_str[end_len] = '\0';
	}

	const char *prefix = "GET / HTTP/1.1\r\nRange: bytes=";
	const char *dash   = "-";
	const char *suffix = "\r\n\r\n";

	char *p = buf; const char *end = buf + bufsz;
	for (const char *s = prefix; *s && p < end; s++) *p++ = *s;
	if (rstart >= 0) for (int64_t i = 0; i < start_len && p < end; i++) *p++ = start_str[i];
	for (const char *s = dash; *s && p < end; s++) *p++ = *s;
	if (rend >= 0) for (int64_t i = 0; i < end_len && p < end; i++) *p++ = end_str[i];
	for (const char *s = suffix; *s && p < end; s++) *p++ = *s;
	return p - buf;
}

// ── wrappers for asm functions ─────────────────────────────────────

// parse_header_end(buf=x0, len=x1) → index in x1 (or 0)
static inline int64_t parse_header_end_wrapper(const char *buf, int64_t len) {
	int64_t result;
	asm volatile(
		"mov x0, %1\n"
		"mov x1, %2\n"
		"bl parse_header_end\n"
		"mov %0, x1\n"
		: "=r"(result)
		: "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "memory"
	);
	return result;
}

// get_header_field(hdr=x0, hdr_len=x1, field=x2, field_len=x3)
// → (content=x0, rem=x1, carry=flag)
static inline int64_t get_header_field_wrapper(
	const char *hdr, int64_t hdr_len,
	const char *field, int64_t field_len,
	const char **out_content, int64_t *out_rem)
{
	const char *content; int64_t rem;
	asm volatile(
		"mov x0, %2\n"
		"mov x1, %3\n"
		"mov x2, %4\n"
		"mov x3, %5\n"
		"cmp xzr, xzr\n"
		"bl get_header_field\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		: "=r"(content), "=r"(rem)
		: "r"(hdr), "r"(hdr_len), "r"(field), "r"(field_len)
		: "x0", "x1", "x2", "x3",
		  "x19", "x20", "x21", "x23", "x24", "memory"
	);
	*out_content = content;
	*out_rem = rem;
	int64_t carry;
	asm volatile("cset %0, cs" : "=r"(carry));
	return carry;
}

// parse_range(hdr=x0, hdr_len=x1) → (start=x0, end=x1, carry=flag)
static inline int64_t parse_range_wrapper(
	const char *hdr, int64_t hdr_len,
	int64_t *out_start, int64_t *out_end)
{
	int64_t start, ending;
	asm volatile(
		"mov x0, %2\n"
		"mov x1, %3\n"
		"cmp xzr, xzr\n"
		"bl parse_range\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		: "=r"(start), "=r"(ending)
		: "r"(hdr), "r"(hdr_len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26",
		  "memory"
	);
	*out_start = start;
	*out_end = ending;
	int64_t carry;
	asm volatile("cset %0, cs" : "=r"(carry));
	return carry;
}

// ── tests: parse_header_end ────────────────────────────────────────

static void test_parse_header_end(void) {
	TEST_SUITE("parse_header_end");

	const char *hdr1 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nbody";
	int64_t hdr1_len = LITLEN("GET / HTTP/1.1\r\nHost: localhost\r\n\r\nbody");
	int64_t idx = parse_header_end_wrapper(hdr1, hdr1_len);
	int64_t expected = LITLEN("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	ASSERT_EQ("basic header end found", expected, idx);

	const char *no_end = "GET / HTTP/1.1\r\nHost: x\r\n";
	idx = parse_header_end_wrapper(no_end, LITLEN("GET / HTTP/1.1\r\nHost: x\r\n"));
	ASSERT_EQ("no header end → 0", 0, idx);

	idx = parse_header_end_wrapper("\r\n\r\n", 4);
	ASSERT_EQ("minimal header", 4, idx);

	idx = parse_header_end_wrapper("", 0);
	ASSERT_EQ("empty buffer → 0", 0, idx);

	idx = parse_header_end_wrapper("A\r\n\r\n", 5);
	ASSERT_EQ("header at buffer end", 5, idx);

	idx = parse_header_end_wrapper("\rX\r\n\r\n", 6);
	ASSERT_EQ("\\r mid-header still works", 6, idx);
}

// ── tests: get_header_field ────────────────────────────────────────

static void test_get_header_field(void) {
	TEST_SUITE("get_header_field");

	const char *hdr =
		"GET / HTTP/1.1\r\n"
		"Host: localhost:8080\r\n"
		"Connection: close\r\n"
		"Accept: */*\r\n"
		"\r\n";
	int64_t hdr_len = LITLEN(
		"GET / HTTP/1.1\r\n"
		"Host: localhost:8080\r\n"
		"Connection: close\r\n"
		"Accept: */*\r\n"
		"\r\n");
	const char *content; int64_t rem, carry;

	carry = get_header_field_wrapper(hdr, hdr_len, "Host", 4, &content, &rem);
	ASSERT_EQ("Host field found", 0, carry);
	ASSERT_NOT_NULL("Host content non-null", content);

	carry = get_header_field_wrapper(hdr, hdr_len, "Connection", 10, &content, &rem);
	ASSERT_EQ("Connection field found", 0, carry);

	carry = get_header_field_wrapper(hdr, hdr_len, "Accept", 6, &content, &rem);
	ASSERT_EQ("Accept field found", 0, carry);

	carry = get_header_field_wrapper(hdr, hdr_len, "X-Custom", 8, &content, &rem);
	ASSERT_EQ("X-Custom not found", 1, carry);

	carry = get_header_field_wrapper(hdr, hdr_len, "host", 4, &content, &rem);
	ASSERT_EQ("case-insensitive Host", 0, carry);
}

// ── tests: parse_range ─────────────────────────────────────────────

static void test_parse_range(void) {
	TEST_SUITE("parse_range");

	int64_t start, end, carry;
	char hdr[512]; int64_t hdr_len;

	hdr_len = build_range_header(hdr, sizeof(hdr), 0, 499);
	carry = parse_range_wrapper(hdr, hdr_len, &start, &end);
	ASSERT_EQ("bytes=0-499 carry=0", 0, carry);
	ASSERT_EQ("bytes=0-499 start",  0, start);
	ASSERT_EQ("bytes=0-499 end",    499, end);

	hdr_len = build_range_header(hdr, sizeof(hdr), 100, 200);
	carry = parse_range_wrapper(hdr, hdr_len, &start, &end);
	ASSERT_EQ("bytes=100-200", 0, carry);
	ASSERT_EQ("bytes=100-200 start", 100, start);
	ASSERT_EQ("bytes=100-200 end",   200, end);

	hdr_len = build_range_header(hdr, sizeof(hdr), 0, -1);
	carry = parse_range_wrapper(hdr, hdr_len, &start, &end);
	ASSERT_EQ("bytes=0- open", 0, carry);
	ASSERT_EQ("bytes=0- start", 0, start);
	ASSERT_EQ("bytes=0- end=-1", -1, end);

	hdr_len = build_range_header(hdr, sizeof(hdr), -1, 500);
	carry = parse_range_wrapper(hdr, hdr_len, &start, &end);
	ASSERT_EQ("bytes=-500 carry=0", 0, carry);
	ASSERT_EQ("bytes=-500 start=-1", -1, start);
	ASSERT_EQ("bytes=-500 end",      500, end);

	const char *no_range = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	hdr_len = LITLEN("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
	carry = parse_range_wrapper(no_range, hdr_len, &start, &end);
	ASSERT_EQ("no Range → carry=1", 1, carry);

	hdr_len = build_range_header(hdr, sizeof(hdr), 500, 100);
	carry = parse_range_wrapper(hdr, hdr_len, &start, &end);
	ASSERT_EQ("end < start → carry=1", 1, carry);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_parse_header_end();
	test_get_header_field();
	test_parse_range();
	test_summary();
	return 0;
}
