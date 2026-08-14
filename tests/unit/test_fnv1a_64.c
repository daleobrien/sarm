// Unit tests for src/util/fnv1a_64.S
//
// fnv1a_64(buf=x0, len=x1) computes the FNV-1a 64-bit hash of a byte
// buffer using the standard C ABI (see fnv1a_64.S): the FNV offset
// basis 0xcbf29ce484222325 is folded with every byte via xor then a
// 64x64->64 multiply by the FNV prime 0x100000001b3. The length is
// explicit, so NUL bytes inside the buffer are hashed like any other
// byte (no string semantics). The implementation processes bytes in an
// unrolled 4-byte loop with a scalar tail, so lengths 4, 8, 12, ...
// straddle a loop boundary.
//
// This suite used to live inside test_util.c; it was split out into its
// own file so the asm fnv1a_64 gets the same dedicated, exhaustive
// coverage as the other util functions (test_strlen.c, test_itoa.c, ...).

#include "test_harness.h"

// fnv1a_64 uses the standard ABI (buf=x0, len=x1, return x0), so it can
// be declared as a normal extern and called directly.
extern uint64_t fnv1a_64(const void *buf, int64_t len) __asm__("fnv1a_64");

// ── reference implementation ────────────────────────────────────────
// Plain-C FNV-1a 64-bit, cross-checks the asm byte-for-byte. h *= prime
// wraps mod 2^64, matching the asm's `mul` (64x64 -> low 64 bits), and
// h ^= byte matches `eor x3, x3, x2` with x2 zero-extended by ldrb.

static uint64_t ref_fnv1a_64(const uint8_t *buf, int64_t len) {
	uint64_t h = 0xcbf29ce484222325ULL;
	for (int64_t i = 0; i < len; i++) {
		h ^= buf[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

// Returns the first length (0..max_len) at which the asm result differs
// from the reference, or -1 if every length matches.
static int check_len_sweep(const uint8_t *buf, int max_len) {
	for (int len = 0; len <= max_len; len++) {
		if (fnv1a_64(buf, len) != ref_fnv1a_64(buf, len))
			return len;
	}
	return -1;
}

// ── tests: known answers (moved verbatim from test_util.c) ──────────

static void test_fnv1a_64_known(void) {
	TEST_SUITE("fnv1a_64 known answers");
	ASSERT_EQ_HEX("fnv1a_64(\"\")",
		0xcbf29ce484222325ULL,
		fnv1a_64("", 0));
	ASSERT_EQ_HEX("fnv1a_64(\"a\")",
		0xaf63dc4c8601ec8cULL,
		fnv1a_64("a", 1));
	ASSERT_EQ_HEX("fnv1a_64(\"foobar\")",
		0x85944171f73967e8ULL,
		fnv1a_64("foobar", 6));
	// "foob" is exactly one 4-byte loop iteration (loop-boundary length).
	ASSERT_EQ_HEX("fnv1a_64(\"foob\")",
		0xdd120e790c2512afULL,
		fnv1a_64("foob", sizeof("foob") - 1));
	ASSERT_EQ_HEX("fnv1a_64(\"hello\")",
		0xa430d84680aabd0bULL,
		fnv1a_64("hello", sizeof("hello") - 1));
	ASSERT_EQ_HEX("fnv1a_64(\"foobarbaz\")",
		0x664062d5ac871055ULL,
		fnv1a_64("foobarbaz", sizeof("foobarbaz") - 1));
	ASSERT_EQ_HEX("fnv1a_64(\"chunked\")",
		0xe64e4a5f7769edf3ULL,
		fnv1a_64("chunked", sizeof("chunked") - 1));
}

// ── tests: length sweep vs reference ────────────────────────────────
// Sweeps every length 0-66 across several byte patterns, hitting every
// 4-byte-loop boundary (4, 8, 12, 16, 17, 19, 20, ...) and the scalar
// tail, all cross-checked against the C reference.

static void test_fnv1a_64_sweep(void) {
	TEST_SUITE("fnv1a_64 length sweep vs reference (0-66)");
	uint8_t buf[96];
	int bad;

	for (int i = 0; i < 96; i++)
		buf[i] = (uint8_t)i;                       // incrementing 0x00..0x5f
	bad = check_len_sweep(buf, 66);
	ASSERT_EQ("incrementing bytes, len 0-66", -1, bad);

	memset(buf, 0x00, sizeof(buf));                // every byte a NUL
	bad = check_len_sweep(buf, 66);
	ASSERT_EQ("all-NUL bytes, len 0-66", -1, bad);

	memset(buf, 0xFF, sizeof(buf));                // every byte 0xFF
	bad = check_len_sweep(buf, 66);
	ASSERT_EQ("all-0xFF bytes, len 0-66", -1, bad);

	for (int i = 0; i < 96; i++)
		buf[i] = (uint8_t)("0123456789"[i % 10]); // repeating ASCII
	bad = check_len_sweep(buf, 66);
	ASSERT_EQ("repeating ASCII, len 0-66", -1, bad);
}

// ── tests: binary data & embedded NULs ──────────────────────────────
// fnv1a_64 hashes an explicit length, so embedded NUL bytes and other
// non-ASCII values must be folded in like any other byte — unlike a
// string hash, NULs cannot terminate the scan.

static void test_fnv1a_64_binary(void) {
	TEST_SUITE("fnv1a_64 binary data & embedded NULs");
	static const uint8_t bin[16] = {
		0x00, 0x01, 0x02, 0x03, 'a', 0x00, 'b', 0x00,
		0xff, 0x00, 0x80, 0x7f, 0x10, 0x20, 0x30, 0x40,
	};

	// Every prefix length of the binary buffer must match the reference.
	int bad = check_len_sweep(bin, 16);
	ASSERT_EQ("binary buffer, len 0-16 vs reference", -1, bad);

	// Known answers for a few binary prefixes (computed independently).
	static const uint8_t two_nuls[2] = { 0x00, 0x00 };
	ASSERT_EQ_HEX("fnv1a_64({0x00,0x00})",
		0x08328807b4eb6fedULL,
		fnv1a_64(two_nuls, 2));

	static const uint8_t eight_bytes[8] = { 0x00, 0x01, 0x02, 0x03,
						0x04, 0x05, 0x06, 0x07 };
	ASSERT_EQ_HEX("fnv1a_64({0x00..0x07})",
		0xa4dc49e2b28ecb7dULL,
		fnv1a_64(eight_bytes, 8));

	static const uint8_t four_ff[4] = { 0xff, 0xff, 0xff, 0xff };
	ASSERT_EQ_HEX("fnv1a_64({0xff}x4)",
		0x994f76653e2a3951ULL,
		fnv1a_64(four_ff, 4));
}

// ── tests: buffer alignment ─────────────────────────────────────────
// The 4-byte loop reads with ldrb, which is alignment-agnostic, but
// sweeping every start offset within a 16-byte block guards against any
// future wide-load optimization that might assume alignment.

static void test_fnv1a_64_alignment(void) {
	TEST_SUITE("fnv1a_64 alignment sweep (offsets 0-15)");
	uint8_t backing[96];
	for (int i = 0; i < 96; i++)
		backing[i] = (uint8_t)(i * 7 + 3);        // arbitrary pattern

	int ok = 1;
	for (int off = 0; off <= 15; off++) {
		uint64_t want = ref_fnv1a_64(backing + off, 32);
		uint64_t got = fnv1a_64(backing + off, 32);
		if (got != want) {
			ok = 0;
			_FAIL("offset %d — got 0x%llx, want 0x%llx", off,
			      (unsigned long long)got, (unsigned long long)want);
			break;
		}
	}
	ASSERT_EQ("all 16 alignments match reference", 1, ok);
}

// ── tests: long input ───────────────────────────────────────────────
// A 4096-byte buffer exercises the 4-byte loop over a full page (plus
// the scalar tail); 4095 and 4097 straddle the exact page length.

static void test_fnv1a_64_long(void) {
	TEST_SUITE("fnv1a_64 long input (~4096 bytes)");
	uint8_t buf[4100];
	for (int i = 0; i < 4100; i++)
		buf[i] = (uint8_t)(i * 31 + (i >> 8));

	ASSERT_EQ_HEX("fnv1a_64(4095) vs reference",
		ref_fnv1a_64(buf, 4095),
		fnv1a_64(buf, 4095));
	ASSERT_EQ_HEX("fnv1a_64(4096) vs reference",
		ref_fnv1a_64(buf, 4096),
		fnv1a_64(buf, 4096));
	ASSERT_EQ_HEX("fnv1a_64(4097) vs reference",
		ref_fnv1a_64(buf, 4097),
		fnv1a_64(buf, 4097));
}

// ── tests: determinism ──────────────────────────────────────────────

static void test_fnv1a_64_deterministic(void) {
	TEST_SUITE("fnv1a_64 determinism");
	uint64_t h1 = fnv1a_64("hello", sizeof("hello") - 1);
	uint64_t h2 = fnv1a_64("hello", sizeof("hello") - 1);
	ASSERT_EQ_HEX("fnv1a_64 deterministic", h1, h2);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_fnv1a_64_known();
	test_fnv1a_64_sweep();
	test_fnv1a_64_binary();
	test_fnv1a_64_alignment();
	test_fnv1a_64_long();
	test_fnv1a_64_deterministic();
	test_summary();
	return 0;
}
