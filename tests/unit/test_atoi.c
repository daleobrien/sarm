// Unit tests for src/util/atoi.S
//
// atoi(s=x0) converts a NUL-terminated ASCII digit string to an int64_t.
// The first 16 bytes are validated in parallel with a NEON vector load;
// every byte before the NUL terminator must be a digit '0'-'9', and the
// terminator must be the FIRST non-digit byte. Unlike libc atoi, which
// skips leading whitespace/sign and stops at the first non-digit, this
// atoi fails the whole conversion (returns 0) when any non-digit shows
// up before the NUL — so "-42", " 42", "42." and "0x10" all return 0.
// Lengths of 19+ digits overflow the register and return 0; the longest
// valid input is 18 digits (max value 10^18 - 1). Leading zeros are
// allowed and do not change the value.
//
// This suite used to live inside test_util.c; it was split out into its
// own file so the asm atoi gets the same dedicated, exhaustive coverage
// as the other util functions (test_strlen.c, test_itoa.c, ...).

#include "test_harness.h"

// atoi uses the standard ABI (arg in x0, return in x0) and signals
// success purely through the return value — no status flags — so the
// tests call it directly with a plain extern.
extern int64_t atoi(const char *s) __asm__("atoi");

// ── reference implementation ────────────────────────────────────────
// Plain-C version of the atoi contract: leading digits are accumulated,
// the first non-digit must be the NUL terminator, and 19+ digits is an
// error (the register can't hold them). Returns 0 on any error, exactly
// like the asm.
static int64_t ref_atoi(const char *s) {
	int64_t n = 0;
	while (s[n] >= '0' && s[n] <= '9')
		n++;
	if (s[n] != '\0' || n >= 19)
		return 0;
	int64_t v = 0;
	for (int64_t i = 0; i < n; i++)
		v = v * 10 + (s[i] - '0');
	return v;
}

// Returns 1 when the asm result matches the reference. atoi's observable
// output is only x0, so comparing the value is a complete check.
static int check_atoi(const char *s) {
	return atoi(s) == ref_atoi(s);
}

// ── tests: basic cases (moved verbatim from test_util.c) ────────────

static void test_atoi_basic(void) {
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

// ── tests: non-digit rejection ──────────────────────────────────────
// Byte values libc atoi would skip or stop at all fail here: the first
// non-digit byte must be the NUL terminator, so any leading or embedded
// whitespace, sign, separator, or trailing garbage aborts the parse.

static void test_atoi_non_digits(void) {
	TEST_SUITE("atoi non-digit rejection");
	static const char *bads[] = {
		"-42", "+42", " 42", "\t42", "42.", "4.2",
		"0x10", "12 34", "12,34", "42abc", "abc123"
	};
	int ok = 1;
	for (unsigned i = 0; i < sizeof(bads) / sizeof(bads[0]); i++) {
		if (atoi(bads[i]) != 0) {
			if (ok)
				_FAIL("\"%s\" — expected 0, got %lld",
				      bads[i], (long long)atoi(bads[i]));
			ok = 0;
		}
	}
	ASSERT_EQ("all lenient-atoi inputs rejected", 1, ok);

	// High bytes are not digits either (signed char sees them negative;
	// the asm flags any byte >= 10 after subtracting '0').
	char hb[16] = { (char)0xff, '\0' };
	ASSERT_EQ("0xff byte rejected", 0, atoi(hb));
}

// ── tests: length edges & NEON boundary ─────────────────────────────
// Lengths 15/16/17/18 straddle the switch between the 16-byte NEON
// vector path and the scalar tail bytes (16-18), which are checked by a
// byte loop; 19+ digits is an immediate overflow error.

static void test_atoi_length_edges(void) {
	TEST_SUITE("atoi length edges (NEON boundary 16-18)");

	// Every valid length parses exactly that many digits.
	ASSERT_EQ("len 15",       999999999999999LL,    atoi("999999999999999"));
	ASSERT_EQ("len 16",       9999999999999999LL,   atoi("9999999999999999"));
	ASSERT_EQ("len 17",       99999999999999999LL,  atoi("99999999999999999"));
	ASSERT_EQ("len 18",       999999999999999999LL, atoi("999999999999999999"));

	// 19+ digits is an immediate overflow error even if the value would
	// fit (e.g. 10^18): the guard is on digit count, not the value.
	ASSERT_EQ("len 19 overflow", 0, atoi("1000000000000000000"));
	ASSERT_EQ("len 20 overflow", 0, atoi("99999999999999999999"));

	// Non-digit in bytes 16-18 (the scalar tail beyond the 16-byte NEON
	// load) must fail, while digits at those positions extend the value.
	ASSERT_EQ("non-digit at byte 16", 0, atoi("1234567890123456x"));
	ASSERT_EQ("non-digit at byte 17", 0, atoi("12345678901234567x"));
	ASSERT_EQ("non-digit at byte 18", 0, atoi("123456789012345678x"));
}

// ── tests: leading zeros ────────────────────────────────────────────
// Leading zeros don't change the value; an all-zero number is a valid
// conversion (returns 0, but unlike an error it has no non-digit before
// the terminator).

static void test_atoi_leading_zeros(void) {
	TEST_SUITE("atoi leading zeros");
	ASSERT_EQ("atoi(\"0\")",       0, atoi("0"));
	ASSERT_EQ("atoi(\"00\")",      0, atoi("00"));
	ASSERT_EQ("atoi(\"0000000\")", 0, atoi("0000000"));
	ASSERT_EQ("atoi(\"007\")",     7, atoi("007"));
	ASSERT_EQ("atoi(\"00042\")",   42, atoi("00042"));
	ASSERT_EQ("18 zeros",          0, atoi("000000000000000000"));
	ASSERT_EQ("18 zeros + 1",      1, atoi("000000000000000001"));
}

// ── tests: maximum values ───────────────────────────────────────────
// 18 digits is the longest valid input (19+ is rejected up front); the
// largest reachable value is 10^18-1. Values near it verify the madd
// accumulation across the full range the register can hold.

static void test_atoi_max_value(void) {
	TEST_SUITE("atoi max values");
	ASSERT_EQ("max 18 nines",
		999999999999999999LL, atoi("999999999999999999"));
	ASSERT_EQ("18 nines - 1",
		999999999999999998LL, atoi("999999999999999998"));
	ASSERT_EQ("10^17 (18 digits)",
		100000000000000000LL, atoi("100000000000000000"));
	ASSERT_EQ("17 nines",
		99999999999999999LL, atoi("99999999999999999"));
	ASSERT_EQ("16 nines",
		9999999999999999LL, atoi("9999999999999999"));
}

// ── tests: exhaustive sweep vs reference ────────────────────────────
// Digit patterns at every valid length 1-18, a non-digit injected at
// every position, and a length sweep 0-23, all cross-checked against the
// plain-C reference.

static void test_atoi_sweep(void) {
	TEST_SUITE("atoi sweep vs reference");
	char buf[24];
	int ok = 1;

	// Digit patterns at every valid length 1-18, NUL-terminated.
	for (int len = 1; len <= 18; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (char)('0' + (i * 3 + 1) % 10);   // repeating digits
		buf[len] = '\0';
		if (!check_atoi(buf)) {
			if (ok)
				_FAIL("repeating digits, len %d", len);
			ok = 0;
		}
		for (int i = 0; i < len; i++)
			buf[i] = '9';
		buf[len] = '\0';
		if (!check_atoi(buf)) {
			if (ok)
				_FAIL("all nines, len %d", len);
			ok = 0;
		}
		for (int i = 0; i < len; i++)
			buf[i] = '0';
		buf[len] = '\0';
		if (!check_atoi(buf)) {
			if (ok)
				_FAIL("all zeros, len %d", len);
			ok = 0;
		}
	}
	ASSERT_EQ("all digit-pattern cases", 1, ok);

	// Non-digit injected at every position of every length 1-18: the
	// whole conversion must fail (first non-digit is 'x', not NUL).
	ok = 1;
	for (int len = 1; len <= 18; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (char)('0' + (i * 3 + 1) % 10);
		buf[len] = '\0';
		for (int pos = 0; pos < len; pos++) {
			char saved = buf[pos];
			buf[pos] = 'x';
			if (!check_atoi(buf)) {
				if (ok)
					_FAIL("injected non-digit, len %d pos %d", len, pos);
				ok = 0;
			}
			buf[pos] = saved;
		}
	}
	ASSERT_EQ("all non-digit injection cases", 1, ok);

	// Length sweep 0-23 on digit strings: 0 is valid (empty), 1-18 give
	// the value, 19-23 overflow and must return 0.
	ok = 1;
	for (int len = 0; len <= 23; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (char)('0' + (i * 3 + 1) % 10);
		buf[len] = '\0';
		if (!check_atoi(buf)) {
			if (ok)
				_FAIL("length sweep, len %d", len);
			ok = 0;
		}
	}
	ASSERT_EQ("all length-sweep cases (0-23)", 1, ok);
}

// ── tests: buffer alignment ─────────────────────────────────────────
// The NEON path loads the first 16 bytes with ldr q0, [x0]. Sweeping
// every start offset within a 16-byte block guards against any future
// change that might assume a particular alignment. Each offset gets its
// own NUL terminator, and the 64-byte backing buffer keeps the
// unconditional 16-byte vector load in-bounds.

static void test_atoi_alignment(void) {
	TEST_SUITE("atoi alignment sweep (offsets 0-15)");
	char backing[64];
	int ok = 1;

	for (int off = 0; off <= 15; off++) {
		for (int i = 0; i < 18; i++)
			backing[off + i] = (char)('0' + (i * 7 + 1) % 10);
		backing[off + 18] = '\0';
		if (!check_atoi(backing + off)) {
			if (ok)
				_FAIL("offset %d", off);
			ok = 0;
		}
	}
	ASSERT_EQ("all 16 alignments match reference", 1, ok);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_atoi_basic();
	test_atoi_non_digits();
	test_atoi_length_edges();
	test_atoi_leading_zeros();
	test_atoi_max_value();
	test_atoi_sweep();
	test_atoi_alignment();
	test_summary();
	return 0;
}
