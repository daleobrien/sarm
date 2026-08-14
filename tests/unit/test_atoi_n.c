// Unit tests for src/util/atoi_n.S
//
// atoi_n(s=x0, len=x1) converts the first len bytes of s to an int64_t.
// The string does not need to be NUL-terminated: exactly len bytes are
// read, and every one must be an ASCII digit '0'-'9'. Failure — a
// non-digit in range, len==0, or len>=19 (the register can't hold 19+
// digits) — returns 0 with the carry flag SET; success returns the value
// with the carry flag CLEAR. Because a valid "0" also returns 0, callers
// (parse_range, h2_parse_range) must branch on the carry flag, never on
// the return value. Lengths 16-18 use a NEON path that validates the
// first 16 bytes in parallel; lengths 1-15 use a plain scalar loop.
//
// This suite used to live inside test_util.c; it was split out into its
// own file so the asm atoi_n gets the same dedicated, exhaustive
// coverage as the other util functions (test_strlen.c, test_itoa.c, ...).

#include "test_harness.h"

// atoi_n passes its arguments and returns its value in the standard
// registers (s=x0, len=x1, value=x0), so the value can be read with a
// plain extern — but the carry flag is part of the result, so most
// tests go through the wrapper below.
extern int64_t atoi_n(const char *s, int64_t len) __asm__("atoi_n");

// ── inline asm wrapper ─────────────────────────────────────────────
// Calls atoi_n and also captures the carry flag (1 = error, 0 = ok),
// mirroring how parse_range uses it: `bl atoi_n; b.cs no_range`.
// Clobbers match atoi_n.S: x0-x4, v0, v1, v16, v17.
static inline int64_t atoi_n_wrapper(const char *s, int64_t len, int64_t *carry) {
	int64_t result, c;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl atoi_n\n"
		"cset %1, cs\n"
		"mov %0, x0\n"
		: "=r"(result), "=r"(c)
		: "r"(s), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "v0", "v1", "v16", "v17", "memory"
	);
	*carry = c;
	return result;
}

// ── reference implementation ────────────────────────────────────────
// Plain-C version of the atoi_n contract: len 1..18, all bytes digits,
// value accumulated as v = v*10 + d. Sets *ok = 1 on success; returns 0
// with *ok = 0 for len==0, len>=19, or any non-digit (exactly the asm's
// "0 with carry set" on error).

static int64_t ref_atoi_n(const char *s, int64_t len, int64_t *ok) {
	int64_t v = 0;
	*ok = 1;
	if (len <= 0 || len >= 19)
		*ok = 0;
	for (int64_t i = 0; i < len && *ok; i++) {
		char c = s[i];
		if (c < '0' || c > '9') {
			*ok = 0;
			return 0;
		}
		v = v * 10 + (c - '0');
	}
	return *ok ? v : 0;
}

// Returns 1 when the asm result (value + carry) matches the reference.
static int check_atoi_n(const char *s, int64_t len) {
	int64_t ref_ok, ref_v, carry, got;
	ref_v = ref_atoi_n(s, len, &ref_ok);
	got = atoi_n_wrapper(s, len, &carry);
	return got == ref_v && carry == (ref_ok ? 0 : 1);
}

// ── tests: basic cases (moved verbatim from test_util.c) ────────────

static void test_atoi_n_basic(void) {
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

// ── tests: carry flag semantics ─────────────────────────────────────
// The carry flag is atoi_n's success signal: clear on success, set on
// error. This matters because a valid "0" also returns 0 — callers must
// branch on the flag (parse_range: b.cs -> no range), never the value.

static void test_atoi_n_carry(void) {
	TEST_SUITE("atoi_n carry flag");
	int64_t carry;

	atoi_n_wrapper("0", 1, &carry);
	ASSERT_EQ("'0' is valid (carry clear)", 0, carry);

	atoi_n_wrapper("999999999999999999", 18, &carry);
	ASSERT_EQ("18 digits valid (carry clear)", 0, carry);

	atoi_n_wrapper("", 0, &carry);
	ASSERT_EQ("len 0 (carry set)", 1, carry);

	atoi_n_wrapper("abc", 3, &carry);
	ASSERT_EQ("non-digit (carry set)", 1, carry);

	atoi_n_wrapper("1234567890123456789", 19, &carry);
	ASSERT_EQ("len 19 overflow (carry set)", 1, carry);
}

// ── tests: length edges & NEON boundary ─────────────────────────────
// Lengths 15/16/17/18 straddle the switch between the scalar loop and
// the NEON path (16-byte parallel digit validation + scalar tail bytes).

static void test_atoi_n_length_edges(void) {
	TEST_SUITE("atoi_n length edges (NEON boundary 16-18)");
	int64_t carry;

	// Every valid length parses exactly that many digits.
	ASSERT_EQ("len 15",       999999999999999LL,    atoi_n("999999999999999", 15));
	ASSERT_EQ("len 16",       9999999999999999LL,   atoi_n("9999999999999999", 16));
	ASSERT_EQ("len 17",       99999999999999999LL,  atoi_n("99999999999999999", 17));
	ASSERT_EQ("len 18",       999999999999999999LL, atoi_n("999999999999999999", 18));

	// 19+ digits is an immediate overflow error even if the value would
	// fit (e.g. 10^18): the guard is on digit count, not the value.
	ASSERT_EQ("len 19 overflow", 0, atoi_n("1000000000000000000", 19));
	ASSERT_EQ("len 20 overflow", 0, atoi_n("99999999999999999999", 20));

	// Truncation: only len bytes are read; trailing bytes are ignored
	// when len stops short of them, and fatal when len includes them.
	ASSERT_EQ("truncate \"123456789\", len 4", 1234, atoi_n("123456789", 4));
	ASSERT_EQ("trailing non-digit not read",   1234, atoi_n("1234X", 4));
	ASSERT_EQ("trailing non-digit read",       0,   atoi_n("1234X", 5));

	// NEON path: non-digit in byte 17 or 18 (the scalar tail) must fail,
	// while stopping before it must succeed.
	atoi_n_wrapper("1234567890123456X", 17, &carry);
	ASSERT_EQ("17th byte non-digit", 1, carry);
	atoi_n_wrapper("12345678901234567X", 18, &carry);
	ASSERT_EQ("18th byte non-digit", 1, carry);
	atoi_n_wrapper("12345678901234567X", 17, &carry);
	ASSERT_EQ("17 digits, 18th unread", 0, carry);
}

// ── tests: non-digit rejection at every position ────────────────────
// Any byte outside '0'..'9' in the first len bytes fails the whole
// conversion — position doesn't matter, and neither do byte values that
// a libc atoi would skip or stop at (space, '-', '+', tab, NUL, '.').

static void test_atoi_n_non_digits(void) {
	TEST_SUITE("atoi_n non-digit rejection");
	int64_t carry;
	char buf[18];
	int ok = 1;

	// Inject a non-digit at every position 0..17 of an 18-byte buffer
	// and require 0 + carry set (digits elsewhere).
	for (int pos = 0; pos < 18; pos++) {
		for (int i = 0; i < 18; i++)
			buf[i] = (char)('0' + (i + 3) % 10);
		buf[pos] = 'x';
		int64_t got = atoi_n_wrapper(buf, 18, &carry);
		if (got != 0 || carry != 1) {
			if (ok)
				_FAIL("non-digit at pos %d — got %lld, carry %lld",
				      pos, (long long)got, (long long)carry);
			ok = 0;
		}
	}
	ASSERT_EQ("all 18 positions rejected", 1, ok);

	// Byte values libc atoi would treat leniently all fail here.
	static const char *bads[] = { " 42", "-42", "+42", "\t42", "x42", "42." };
	for (unsigned i = 0; i < sizeof(bads) / sizeof(bads[0]); i++) {
		int64_t got = atoi_n_wrapper(bads[i], 3, &carry);
		if (got != 0 || carry != 1) {
			if (ok)
				_FAIL("\"%s\" — got %lld, carry %lld",
				      bads[i], (long long)got, (long long)carry);
			ok = 0;
		}
	}
	ASSERT_EQ("all lenient-atoi byte values rejected", 1, ok);

	// Reading past the NUL of a C string reads the terminator, which is
	// not a digit — an off-by-one length must fail, not silently pass.
	atoi_n_wrapper("123", 4, &carry);
	ASSERT_EQ("len 4 on \"123\" (NUL read)", 1, carry);

	// High bytes (0xff) are not digits either.
	char hb[2] = { (char)0xff, '2' };
	atoi_n_wrapper(hb, 2, &carry);
	ASSERT_EQ("0xff byte rejected", 1, carry);
}

// ── tests: leading zeros ────────────────────────────────────────────
// Leading zeros don't change the value; an all-zero number is a valid
// conversion (returns 0 with carry CLEAR, unlike an error's 0+carry).

static void test_atoi_n_leading_zeros(void) {
	TEST_SUITE("atoi_n leading zeros");
	int64_t carry;

	ASSERT_EQ("atoi_n(\"0\", 1)",       0, atoi_n("0", 1));
	ASSERT_EQ("atoi_n(\"00\", 2)",      0, atoi_n("00", 2));
	ASSERT_EQ("atoi_n(\"0000000\", 7)", 0, atoi_n("0000000", 7));
	ASSERT_EQ("atoi_n(\"007\", 3)",     7, atoi_n("007", 3));

	ASSERT_EQ("18 zeros value", 0, atoi_n("000000000000000000", 18));
	atoi_n_wrapper("000000000000000000", 18, &carry);
	ASSERT_EQ("18 zeros carry clear", 0, carry);
}

// ── tests: maximum values ───────────────────────────────────────────
// 18 digits is the longest valid input (19+ is rejected up front); the
// largest reachable value is 10^18-1. Values near it verify the madd
// accumulation across the full range the register can hold.

static void test_atoi_n_max_value(void) {
	TEST_SUITE("atoi_n max values");
	int64_t carry;

	ASSERT_EQ("max 18 nines",
		999999999999999999LL, atoi_n("999999999999999999", 18));
	ASSERT_EQ("18 nines - 1",
		999999999999999998LL, atoi_n("999999999999999998", 18));
	ASSERT_EQ("10^17 (18 digits)",
		100000000000000000LL, atoi_n("100000000000000000", 18));
	ASSERT_EQ("17 nines",
		99999999999999999LL, atoi_n("99999999999999999", 17));
	ASSERT_EQ("16 nines",
		9999999999999999LL, atoi_n("9999999999999999", 16));

	atoi_n_wrapper("999999999999999999", 18, &carry);
	ASSERT_EQ("max valid carry clear", 0, carry);
}

// ── tests: exhaustive sweep vs reference ────────────────────────────
// Every length 1-18 of several digit patterns, plus a non-digit injected
// at every position, cross-checked against the plain-C reference (value
// and carry). Error lengths 0 and 19-23 are swept too.

static void test_atoi_n_sweep(void) {
	TEST_SUITE("atoi_n sweep vs reference (len 1-18)");
	char buf[24];
	int ok = 1;

	// Digit patterns: repeating digits, all nines, all zeros.
	for (int len = 1; len <= 18; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (char)('0' + (i * 3 + 1) % 10);   // repeating digits
		if (!check_atoi_n(buf, len)) {
			if (ok)
				_FAIL("repeating digits, len %d", len);
			ok = 0;
		}
		for (int i = 0; i < len; i++)
			buf[i] = '9';
		if (!check_atoi_n(buf, len)) {
			if (ok)
				_FAIL("all nines, len %d", len);
			ok = 0;
		}
		for (int i = 0; i < len; i++)
			buf[i] = '0';
		if (!check_atoi_n(buf, len)) {
			if (ok)
				_FAIL("all zeros, len %d", len);
			ok = 0;
		}
	}
	ASSERT_EQ("all digit-pattern cases", 1, ok);

	// Non-digit injected at every position of every length 1-18.
	ok = 1;
	for (int len = 1; len <= 18; len++) {
		for (int i = 0; i < len; i++)
			buf[i] = (char)('0' + (i * 3 + 1) % 10);
		for (int pos = 0; pos < len; pos++) {
			char saved = buf[pos];
			buf[pos] = 'x';
			if (!check_atoi_n(buf, len)) {
				if (ok)
					_FAIL("injected non-digit, len %d pos %d", len, pos);
				ok = 0;
			}
			buf[pos] = saved;
		}
	}
	ASSERT_EQ("all non-digit injection cases", 1, ok);

	// Error lengths 0 and 19-23, and the valid lengths 1-18, on a
	// 23-byte all-digit buffer.
	ok = 1;
	for (int64_t len = 0; len <= 23; len++) {
		if (!check_atoi_n("01234567890123456789012", len)) {
			if (ok)
				_FAIL("length sweep, len %lld", (long long)len);
			ok = 0;
		}
	}
	ASSERT_EQ("all length-sweep cases (0-23)", 1, ok);
}

// ── tests: buffer alignment ─────────────────────────────────────────
// The NEON path loads the first 16 bytes with ldr q0, [x0]. Sweeping
// every start offset within a 16-byte block guards against any future
// change that might assume a particular alignment.

static void test_atoi_n_alignment(void) {
	TEST_SUITE("atoi_n alignment sweep (offsets 0-15)");
	char backing[64];
	int ok = 1;

	// 18 digits so every offset exercises the NEON path + scalar tail.
	for (int i = 0; i < 64; i++)
		backing[i] = (char)('0' + (i * 7 + 1) % 10);

	for (int off = 0; off <= 15; off++) {
		if (!check_atoi_n(backing + off, 18)) {
			if (ok)
				_FAIL("offset %d", off);
			ok = 0;
		}
	}
	ASSERT_EQ("all 16 alignments match reference", 1, ok);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_atoi_n_basic();
	test_atoi_n_carry();
	test_atoi_n_length_edges();
	test_atoi_n_non_digits();
	test_atoi_n_leading_zeros();
	test_atoi_n_max_value();
	test_atoi_n_sweep();
	test_atoi_n_alignment();
	test_summary();
	return 0;
}
