// Unit tests for src/util.S assembly functions
// Tests: atoi, atoi_n
// strlen is tested separately in test_strlen.c; streqn in test_streqn.c;
// streqn_i in test_streqn_i.c; memcpy in test_memcpy.c; itoa in test_itoa.c;
// fnv1a_64 in test_fnv1a_64.c
//
// NOTE: This file links against util.o which defines its own "strlen" with
// a non-standard calling convention (arg in x1, not x0). Do NOT call libc
// strlen() — use the asm strlen via the wrapper instead.

#include "test_harness.h"

// ── extern assembly functions ──────────────────────────────────────
// Use __asm__() to match the unprefixed symbol names in the asm .o file.

extern int64_t atoi(const char *s)        __asm__("atoi");
extern int64_t atoi_n(const char *s, int64_t len) __asm__("atoi_n");

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

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_atoi();
	test_atoi_n();
	test_summary();
	return 0;
}
