// Unit tests for src/util.S assembly functions
// Tests: atoi, atoi_n, itoa, fnv1a_64
// strlen is tested separately in test_strlen.c; streqn in test_streqn.c;
// streqn_i in test_streqn_i.c; memcpy in test_memcpy.c
//
// NOTE: This file links against util.o which defines its own "strlen" with
// a non-standard calling convention (arg in x1, not x0). Do NOT call libc
// strlen() — use the asm strlen via the wrapper instead.

#include "test_harness.h"

// ── extern assembly functions ──────────────────────────────────────
// Use __asm__() to match the unprefixed symbol names in the asm .o file.

extern int64_t atoi(const char *s)        __asm__("atoi");
extern int64_t atoi_n(const char *s, int64_t len) __asm__("atoi_n");
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
	test_fnv1a_64();
	test_summary();
	return 0;
}
