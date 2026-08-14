// Unit tests for src/util.S assembly functions
// Tests: atoi, atoi_n, itoa, memcpy, streqn, streqn_i, fnv1a_64
// strlen is tested separately in test_strlen.c
//
// NOTE: This file links against util.o which defines its own "strlen" with
// a non-standard calling convention (arg in x1, not x0). Do NOT call libc
// strlen() — use the asm strlen via the wrapper instead.

#include "test_harness.h"

// ── extern assembly functions ──────────────────────────────────────
// Use __asm__() to match the unprefixed symbol names in the asm .o file.

extern int64_t atoi(const char *s)        __asm__("atoi");
extern int64_t atoi_n(const char *s, int64_t len) __asm__("atoi_n");
extern int64_t streqn(const char *a, const char *b, int64_t maxlen) __asm__("streqn");
extern int64_t streqn_i(const char *a, const char *b, int64_t maxlen) __asm__("streqn_i");
extern uint64_t fnv1a_64(const void *buf, int64_t len) __asm__("fnv1a_64");

// ── inline asm wrappers ────────────────────────────────────────────

// itoa(n=x0) → (ptr=x0, len=x1)
static inline void itoa_wrapper(int64_t n, const char **out_ptr, int64_t *out_len) {
	const char *ptr; int64_t len;
	asm volatile(
		"mov x0, %2\n"
		"bl itoa\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		: "=r"(ptr), "=r"(len)
		: "r"(n)
		: "x0", "x1", "x2", "x3", "x4", "x5", "memory"
	);
	*out_ptr = ptr;
	*out_len = len;
}

// memcpy(dst=x0, src=x1, len=x2) — standard ABI, matches C.
static inline void memcpy_asm_wrapper(void *dst, const void *src, int64_t len) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"mov x2, %2\n"
		"bl memcpy\n"
		:
		: "r"(dst), "r"(src), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "memory"
	);
}

// ── tests: atoi ────────────────────────────────────────────────────

static void test_atoi(void) {
	TEST_SUITE("atoi");
	ASSERT_EQ("atoi(\"0\")",      0,  atoi("0"));
	ASSERT_EQ("atoi(\"1\")",      1,  atoi("1"));
	ASSERT_EQ("atoi(\"42\")",     42, atoi("42"));
	ASSERT_EQ("atoi(\"12345\")",  12345, atoi("12345"));
	ASSERT_EQ("atoi(\"999999\")", 999999, atoi("999999"));
	ASSERT_EQ("atoi(\"8080\")",   8080, atoi("8080"));
	ASSERT_EQ("atoi(\"65535\")",  65535, atoi("65535"));
	ASSERT_EQ("atoi(\"abc\")",    0, atoi("abc"));
	ASSERT_EQ("atoi(\"\")",       0, atoi(""));
	ASSERT_EQ("atoi(negative)",   0, atoi("-42"));
}

// ── tests: atoi_n ──────────────────────────────────────────────────

static void test_atoi_n(void) {
	TEST_SUITE("atoi_n");
	ASSERT_EQ("atoi_n(\"42\", 2)",     42,    atoi_n("42", 2));
	ASSERT_EQ("atoi_n(\"123\", 3)",    123,   atoi_n("123", 3));
	ASSERT_EQ("atoi_n(\"1234X\", 4)",  1234,  atoi_n("1234X", 4));
	ASSERT_EQ("atoi_n(\"0\", 1)",      0,     atoi_n("0", 1));
	ASSERT_EQ("atoi_n(\"007\", 3)",    7,     atoi_n("007", 3));
	ASSERT_EQ("atoi_n(\"999\", 3)",    999,   atoi_n("999", 3));
	ASSERT_EQ("atoi_n(20 digits)",     0, atoi_n("12345678901234567890", 20));
	ASSERT_EQ("atoi_n(\"abc\", 3)",    0, atoi_n("abc", 3));
	ASSERT_EQ("atoi_n(\"12x\", 3)",    0, atoi_n("12x", 3));
}

// ── tests: itoa ────────────────────────────────────────────────────

static void test_itoa(void) {
	TEST_SUITE("itoa");
	const char *ptr;
	int64_t len;

	itoa_wrapper(0, &ptr, &len);
	ASSERT_EQ("itoa(0) len",    1, len);
	ASSERT_EQ("itoa(0) char",   '0', ptr[0]);

	itoa_wrapper(42, &ptr, &len);
	ASSERT_EQ("itoa(42) len",   2, len);
	ASSERT_EQ("itoa(42) [0]",   '4', ptr[0]);
	ASSERT_EQ("itoa(42) [1]",   '2', ptr[1]);

	itoa_wrapper(100, &ptr, &len);
	ASSERT_EQ("itoa(100) len",  3, len);

	itoa_wrapper(65535, &ptr, &len);
	ASSERT_EQ("itoa(65535) len", 5, len);
	ASSERT_STR_EQ("itoa(65535)", "65535", ptr, 5);

	itoa_wrapper(8080, &ptr, &len);
	ASSERT_STR_EQ("itoa(8080)", "8080", ptr, len);

	itoa_wrapper(1234567890, &ptr, &len);
	ASSERT_EQ("itoa(big) len",  10, len);
	ASSERT_STR_EQ("itoa(big)", "1234567890", ptr, len);
}

// ── tests: memcpy (asm version) ────────────────────────────────────

static void test_memcpy(void) {
	TEST_SUITE("memcpy (asm)");
	char dst[64];

	memset(dst, 0xFF, sizeof(dst));
	memcpy_asm_wrapper(dst, "hello", 0);
	ASSERT_EQ("memcpy(0 bytes) dst unchanged",
		(int64_t)(unsigned char)dst[0], (int64_t)0xFF);

	memcpy_asm_wrapper(dst, "hello", 5);
	ASSERT_TRUE("memcpy(5) match", memcmp(dst, "hello", 5) == 0);

	const char *src16 = "0123456789ABCDEF";
	memcpy_asm_wrapper(dst, src16, 16);
	ASSERT_TRUE("memcpy(16) match", memcmp(dst, src16, 16) == 0);

	const char *src32 = "abcdefghijklmnopqrstuvwxyz012345";
	memcpy_asm_wrapper(dst, src32, 32);
	ASSERT_TRUE("memcpy(32) match", memcmp(dst, src32, 32) == 0);
}

// ── tests: streqn ──────────────────────────────────────────────────

static void test_streqn(void) {
	TEST_SUITE("streqn (case-sensitive)");
	ASSERT_EQ("streqn exact match",         1, streqn("hello", "hello", 10));
	ASSERT_EQ("streqn mismatch",            0, streqn("hello", "world", 10));
	ASSERT_EQ("streqn prefix match (len)",  1, streqn("hello", "hel", 3));
	ASSERT_EQ("streqn limited no match",    0, streqn("hello", "help", 4));
	ASSERT_EQ("streqn case mismatch",       0, streqn("Hello", "hello", 10));
	ASSERT_EQ("streqn empty strings",       1, streqn("", "", 10));
	ASSERT_EQ("streqn long match",          1, streqn("HTTP/1.1", "HTTP/1.1", 10));
	ASSERT_EQ("streqn long mismatch",       0, streqn("HTTP/1.1", "HTTP/1.0", 10));
	ASSERT_EQ("streqn null terminates",     1, streqn("ab", "ab", 100));
	ASSERT_EQ("streqn different len",       0, streqn("abc", "ab", 100));
}

// ── tests: streqn_i ────────────────────────────────────────────────

static void test_streqn_i(void) {
	TEST_SUITE("streqn_i (case-insensitive)");
	ASSERT_EQ("streqn_i exact",            1, streqn_i("hello", "hello", 10));
	ASSERT_EQ("streqn_i lowercase",        1, streqn_i("HELLO", "hello", 10));
	ASSERT_EQ("streqn_i mixed case",       1, streqn_i("HeLLo", "hEllO", 10));
	ASSERT_EQ("streqn_i mismatch",         0, streqn_i("hello", "world", 10));
	ASSERT_EQ("streqn_i long match",       1, streqn_i("CONTENT-TYPE", "content-type", 15));
	ASSERT_EQ("streqn_i long mismatch",    0, streqn_i("CONTENT-TYPE", "content-len", 15));
	ASSERT_EQ("streqn_i null terminates",  1, streqn_i("HOST", "host", 10));
	ASSERT_EQ("streqn_i limited exact",    1, streqn_i("range", "RANGE", 5));
	ASSERT_EQ("streqn_i prefix",           1, streqn_i("HEADERS", "header", 6));

	// ── NEON vector path (maxlen >= 16) ────────────────────────────
	ASSERT_EQ("streqn_i neon 16 exact",       1, streqn_i("abcdefghijklmnop", "ABCDEFGHIJKLMNOP", 16));
	// Limit hit exactly at a 16-byte boundary; the second string is
	// longer, so a correct implementation must NOT compare the byte past
	// the limit (regression test: the old NEON loop fell into the byte
	// loop with x2 == 0 and compared past the end).
	ASSERT_EQ("streqn_i neon 16 limit",       1, streqn_i("abcdefghijklmnop", "abcdefghijklmnopXYZ", 16));
	ASSERT_EQ("streqn_i neon 17",             1, streqn_i("abcdefghijklmnopq", "ABCDEFGHIJKLMNOPQ", 17));
	ASSERT_EQ("streqn_i neon mismatch@0",     0, streqn_i("abcdefghijklmnop", "xbcdefghijklmnop", 16));
	ASSERT_EQ("streqn_i neon mismatch@5",     0, streqn_i("abcdefghijklmnop", "abcdexghijklmnop", 16));
	ASSERT_EQ("streqn_i neon mismatch@15",    0, streqn_i("abcdefghijklmnop", "abcdefghijklmnox", 16));
	ASSERT_EQ("streqn_i neon 32 match",       1, streqn_i("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF", "abcdefghijklmnopqrstuvwxyzabcdef", 32));
	ASSERT_EQ("streqn_i neon 32 mismatch",    0, streqn_i("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF", "abcdefghijklmnopqrstuvwxyzabXdef", 32));
	ASSERT_EQ("streqn_i neon 33 match",       1, streqn_i("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFG", "abcdefghijklmnopqrstuvwxyzabcdefg", 33));
	ASSERT_EQ("streqn_i neon null@20",        1, streqn_i("AAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaa", 30));
	ASSERT_EQ("streqn_i neon null@20 diff",   0, streqn_i("AAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaa", 30));
	ASSERT_EQ("streqn_i neon null@20 limit",  1, streqn_i("AAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaa", 20));
	ASSERT_EQ("streqn_i neon null@4",         1, streqn_i("abcd", "ABCD", 16));
	ASSERT_EQ("streqn_i neon null@4 diff",    0, streqn_i("abcd", "ABCDE", 16));
}

// ── tests: fnv1a_64 ────────────────────────────────────────────────

static void test_fnv1a_64(void) {
	TEST_SUITE("fnv1a_64");
	ASSERT_EQ_HEX("fnv1a_64(\"\")",
		0xcbf29ce484222325ULL,
		fnv1a_64("", 0));
	ASSERT_EQ_HEX("fnv1a_64(\"a\")",
		0xaf63dc4c8601ec8cULL,
		fnv1a_64("a", 1));
	ASSERT_EQ_HEX("fnv1a_64(\"foobar\")",
		0x85944171f73967e8ULL,
		fnv1a_64("foobar", 6));
	uint64_t h1 = fnv1a_64("hello", 5);
	uint64_t h2 = fnv1a_64("hello", 5);
	ASSERT_EQ_HEX("fnv1a_64 deterministic", h1, h2);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_atoi();
	test_atoi_n();
	test_itoa();
	test_memcpy();
	test_streqn();
	test_streqn_i();
	test_fnv1a_64();
	test_summary();
	return 0;
}
