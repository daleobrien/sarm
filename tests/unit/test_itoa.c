// Unit tests for src/util/itoa.S
//
// itoa(n) converts an integer to decimal digits, writing them backwards
// into a static 20-byte buffer (itoa_buf) starting at its end, and
// returns (ptr=x0, len=x1) — NOT NUL-terminated. The division is udiv
// (unsigned), so the input is treated as a uint64_t bit pattern: a
// negative int64_t input converts as its two's-complement value (e.g.
// -1 → 18446744073709551615, exactly filling the 20-byte buffer).
//
// This suite used to live inside test_util.c; it was split out into its
// own file so the asm itoa gets the same dedicated, exhaustive coverage
// as the other util functions (test_strlen.c, test_memcpy.c, ...).

#include "test_harness.h"

// ── inline asm wrapper ─────────────────────────────────────────────
// itoa(n=x0) → (ptr=x0, len=x1). Non-standard ABI: two return values.
// n is passed as uint64_t to match the udiv-based unsigned division.
// Clobbers match itoa.S: x0, x1, x2, x3, x4, x5.
static inline void itoa_wrapper(uint64_t n, const char **out_ptr, int64_t *out_len) {
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

// ── reference conversion ───────────────────────────────────────────
// Plain-C unsigned decimal converter, cross-checks the asm digit-by-
// digit. Returns the digit count; `out` must hold at least 21 bytes.

static int ref_itoa(uint64_t n, char *out) {
	char rev[20];
	int len = 0;
	if (n == 0) {
		out[0] = '0';
		return 1;
	}
	while (n > 0) {
		rev[len++] = (char)('0' + (n % 10));
		n /= 10;
	}
	for (int i = 0; i < len; i++)
		out[i] = rev[len - 1 - i];
	return len;
}

// ── tests: basic cases (moved verbatim from test_util.c) ────────────

static void test_itoa_basic(void) {
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

// ── tests: small values & digit-count edges ─────────────────────────

static void test_itoa_small(void) {
	TEST_SUITE("itoa small values");
	const char *ptr; int64_t len;
	char expected[21];
	int ok = 1;

	// Every single digit, then the 1→2 and 2→3 digit boundaries.
	for (int d = 0; d <= 9; d++) {
		int elen = ref_itoa((uint64_t)d, expected);
		itoa_wrapper((uint64_t)d, &ptr, &len);
		if (len != elen || memcmp(ptr, expected, (unsigned long)elen) != 0) {
			ok = 0;
			_FAIL("single digit %d — got %lld bytes", d, (long long)len);
		}
	}

	static const uint64_t vals[] = {
		9, 10, 11, 99, 100, 101, 999, 1000, 1001,
		9999, 10000, 65535, 99999, 100000,
	};
	for (unsigned i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
		int elen = ref_itoa(vals[i], expected);
		itoa_wrapper(vals[i], &ptr, &len);
		if (len != elen || memcmp(ptr, expected, (unsigned long)elen) != 0) {
			ok = 0;
			_FAIL("value %llu — got %lld bytes", (unsigned long long)vals[i],
			      (long long)len);
		}
	}
	ASSERT_EQ("all small-value cases", 1, ok);
}

// ── tests: powers of 10 & digit-count boundaries ───────────────────
// 10^n (n+1 digits) and 10^n - 1 (all nines, n digits) straddle every
// digit-count boundary from 1 up to the 20-digit buffer limit.

static void test_itoa_powers_of_ten(void) {
	TEST_SUITE("itoa powers of 10 & boundaries");
	const char *ptr; int64_t len;
	char expected[21];
	int ok = 1;

	// 10^n for n = 0..19: "1" followed by n zeros.
	uint64_t p = 1;
	for (int n = 0; n <= 19; n++) {
		int elen = ref_itoa(p, expected);
		itoa_wrapper(p, &ptr, &len);
		if (len != elen || memcmp(ptr, expected, (unsigned long)elen) != 0) {
			ok = 0;
			_FAIL("10^%d — got %lld bytes", n, (long long)len);
		}
		p *= 10;
	}

	// 10^n - 1 (all nines) for n = 1..19: exactly n digits.
	p = 9;
	for (int n = 1; n <= 19; n++) {
		int elen = ref_itoa(p, expected);
		itoa_wrapper(p, &ptr, &len);
		if (len != elen || memcmp(ptr, expected, (unsigned long)elen) != 0) {
			ok = 0;
			_FAIL("10^%d-1 — got %lld bytes", n, (long long)len);
		}
		p = p * 10 + 9;
	}

	ASSERT_EQ("all power-of-10 boundary cases", 1, ok);
}

// ── tests: max values & negative-as-unsigned ───────────────────────
// udiv treats x0 as unsigned, so large uint64_t values and negative
// int64_t inputs (their two's-complement bit patterns) must convert
// correctly, including the 20-digit values that fill itoa_buf exactly.

static void test_itoa_max_values(void) {
	TEST_SUITE("itoa max values & negatives-as-unsigned");
	const char *ptr; int64_t len;

	itoa_wrapper(UINT64_MAX, &ptr, &len);
	ASSERT_EQ("itoa(UINT64_MAX) len", 20, len);
	ASSERT_STR_EQ("itoa(UINT64_MAX)", "18446744073709551615", ptr, 20);

	itoa_wrapper(UINT64_MAX - 1, &ptr, &len);
	ASSERT_EQ("itoa(UINT64_MAX-1) len", 20, len);
	ASSERT_STR_EQ("itoa(UINT64_MAX-1)", "18446744073709551614", ptr, 20);

	itoa_wrapper((uint64_t)-42, &ptr, &len);
	ASSERT_EQ("itoa(-42 as unsigned) len", 20, len);
	ASSERT_STR_EQ("itoa(-42 as unsigned)", "18446744073709551574", ptr, 20);

	// 10^19 and neighbors: the two 20-digit values around the 19-digit
	// boundary, plus a couple of large mixed-digit numbers.
	itoa_wrapper(10000000000000000000ULL, &ptr, &len);
	ASSERT_EQ("itoa(10^19) len", 20, len);
	ASSERT_STR_EQ("itoa(10^19)", "10000000000000000000", ptr, 20);

	itoa_wrapper(9999999999999999999ULL, &ptr, &len);
	ASSERT_EQ("itoa(10^19-1) len", 19, len);
	ASSERT_STR_EQ("itoa(10^19-1)", "9999999999999999999", ptr, 19);

	itoa_wrapper(1234567890123456789ULL, &ptr, &len);
	ASSERT_EQ("itoa(1234567890123456789) len", 19, len);
	ASSERT_STR_EQ("itoa(1234567890123456789)", "1234567890123456789", ptr, 19);

	itoa_wrapper(12345678901234567890ULL, &ptr, &len);
	ASSERT_EQ("itoa(12345678901234567890) len", 20, len);
	ASSERT_STR_EQ("itoa(12345678901234567890)", "12345678901234567890", ptr, 20);
}

// ── tests: exhaustive sweep 0-999999 ───────────────────────────────
// Every value in the range is cross-checked digit-by-digit against the
// C reference, which catches wrong-length and off-by-one digit bugs.

static void test_itoa_sweep(void) {
	TEST_SUITE("itoa exhaustive sweep 0-999999");
	const char *ptr; int64_t len;
	char expected[21];
	int ok = 1;

	for (uint64_t n = 0; n < 1000000; n++) {
		int elen = ref_itoa(n, expected);
		itoa_wrapper(n, &ptr, &len);
		if (len != elen || memcmp(ptr, expected, (unsigned long)elen) != 0) {
			if (ok)
				_FAIL("first mismatch at n=%llu (len %lld, expected %d)",
				      (unsigned long long)n, (long long)len, elen);
			ok = 0;
		}
	}
	ASSERT_EQ("all 1000000 sweep cases", 1, ok);
}

// ── tests: shared buffer reuse & pointer invariant ─────────────────
// itoa writes into one static 20-byte buffer, so the returned range
// must be consistent across calls: ptr + len always equals the buffer
// end, a short result must not leak digits from a previous longer call,
// and repeated calls must be deterministic.

static void test_itoa_shared_buffer(void) {
	TEST_SUITE("itoa shared buffer & pointer invariant");
	const char *ptr; int64_t len;
	const char *buf_end = NULL;
	char expected[21];
	int ok = 1;

	for (int i = 0; i < 5000; i++) {
		uint64_t n = (uint64_t)i * 3721 + 17;
		int elen = ref_itoa(n, expected);
		itoa_wrapper(n, &ptr, &len);
		const char *end = ptr + len;
		if (buf_end == NULL)
			buf_end = end;
		if (end != buf_end || len != elen ||
		    memcmp(ptr, expected, (unsigned long)elen) != 0) {
			ok = 0;
			_FAIL("call %d (n=%llu) — ptr+len moved or digits wrong",
			      i, (unsigned long long)n);
			break;
		}
	}
	ASSERT_EQ("ptr+len invariant + digits over 5000 calls", 1, ok);

	// A short result after a 20-digit result must only report its own
	// digits (leftover buffer bytes sit outside the returned range).
	itoa_wrapper(UINT64_MAX, &ptr, &len);
	ASSERT_EQ("max fills all 20 bytes", 20, len);
	itoa_wrapper(7, &ptr, &len);
	ASSERT_EQ("short after long: len", 1, len);
	ASSERT_EQ("short after long: char", '7', ptr[0]);

	// Determinism: two calls with the same input give the same digits.
	itoa_wrapper(123456789, &ptr, &len);
	ASSERT_STR_EQ("deterministic (1st)", "123456789", ptr, 9);
	itoa_wrapper(123456789, &ptr, &len);
	ASSERT_STR_EQ("deterministic (2nd)", "123456789", ptr, 9);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_itoa_basic();
	test_itoa_small();
	test_itoa_powers_of_ten();
	test_itoa_max_values();
	test_itoa_sweep();
	test_itoa_shared_buffer();
	test_summary();
	return 0;
}
