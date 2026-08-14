// Unit tests for src/util/streqn_i.S
//
// streqn_i(a, b, maxlen) compares up to `maxlen` bytes of two strings
// case-insensitively (ASCII A-Z folded to lowercase on both sides),
// stopping at the first NUL byte or mismatch. Returns 1 on match,
// 0 otherwise.
//
// The implementation (see streqn_i.S) uses a 16-byte-wide NEON loop when
// maxlen >= 16 and a byte-at-a-time loop for shorter inputs and for the
// tail of a chunk that triggered a NUL/mismatch stop condition.
//
// NOTE: This file links against util.o which defines its own "strlen"
// with a non-standard calling convention (arg in x1, not x0). Do NOT call
// libc strlen(). memset/memcmp come from libc (not defined in util) and
// are safe to call.

#include "test_harness.h"

// streqn_i uses the standard ABI (a=x0, b=x1, maxlen=x2, return x0),
// so it can be declared as a normal extern and called directly.
extern int64_t streqn_i(const char *a, const char *b, int64_t maxlen) __asm__("streqn_i");

// ── tests: basic case-insensitive semantics ────────────────────────

static void test_streqn_i_basic(void) {
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
}

// ── tests: NEON vector path (maxlen >= 16) ─────────────────────────

static void test_streqn_i_neon(void) {
	TEST_SUITE("streqn_i NEON vector path");
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

// ── tests: maxlen limits ───────────────────────────────────────────

static void test_streqn_i_maxlen(void) {
	TEST_SUITE("streqn_i maxlen limits");

	// maxlen == 0 compares nothing -> always a match, even for
	// completely different strings.
	ASSERT_EQ("streqn_i maxlen=0 diff",    1, streqn_i("abc", "xyz", 0));
	ASSERT_EQ("streqn_i maxlen=0 same",    1, streqn_i("abc", "abc", 0));
	ASSERT_EQ("streqn_i maxlen=0 empty",   1, streqn_i("", "", 0));

	// maxlen == 1 compares only the first byte.
	ASSERT_EQ("streqn_i maxlen=1 fold",    1, streqn_i("AbC", "aBc", 1));
	ASSERT_EQ("streqn_i maxlen=1 mismatch", 0, streqn_i("AbC", "xbc", 1));

	// A limit that cuts off before a later mismatch is still a match.
	ASSERT_EQ("streqn_i limit cuts early", 1, streqn_i("abc", "abd", 2));
	ASSERT_EQ("streqn_i limit at mismatch", 0, streqn_i("abc", "abd", 3));
	ASSERT_EQ("streqn_i prefix vs longer", 1, streqn_i("abcdef", "abcXYZ", 3));
	ASSERT_EQ("streqn_i header prefix",    1, streqn_i("CONTENT-TYPE", "content-length", 8));

	// The byte loop (maxlen < 16) and the NEON loop (maxlen >= 16) must
	// agree on the same inputs, and a mismatch at the byte-15/16
	// threshold flips exactly when the limit reaches it.
	ASSERT_EQ("streqn_i 15-byte limit",    1, streqn_i("qwertyuiopasdfgh", "QWERTYUIOPASDFGH", 15));
	ASSERT_EQ("streqn_i 16-byte limit",    1, streqn_i("qwertyuiopasdfgh", "QWERTYUIOPASDFGH", 16));
	ASSERT_EQ("streqn_i mismatch@15 lim15", 1, streqn_i("abcdefghijklmnop", "abcdefghijklmnox", 15));
	ASSERT_EQ("streqn_i mismatch@15 lim16", 0, streqn_i("abcdefghijklmnop", "abcdefghijklmnox", 16));
}

// ── tests: case folding bounds ─────────────────────────────────────

static void test_streqn_i_case_folding(void) {
	TEST_SUITE("streqn_i case folding bounds");

	// Full A-Z / a-z alphabet, both directions.
	char up[32], lo[32];
	memset(up, 'u', sizeof(up));
	memset(lo, 'l', sizeof(lo));
	for (int i = 0; i < 26; i++) {
		up[i] = (char)('A' + i);
		lo[i] = (char)('a' + i);
	}
	up[26] = 0; lo[26] = 0;
	ASSERT_EQ("streqn_i A-Z vs a-z",   1, streqn_i(up, lo, 26));
	ASSERT_EQ("streqn_i a-z vs A-Z",   1, streqn_i(lo, up, 26));

	// Characters just outside the fold range must NOT fold. The
	// 0x20-apart pairs '@'/'`', '['/'{' are the classic off-by-one
	// bugs for a case-insensitive compare.
	ASSERT_EQ("streqn_i '@' vs '`'",   0, streqn_i("@", "`", 2));
	ASSERT_EQ("streqn_i '[' vs '{'",   0, streqn_i("[", "{", 2));
	ASSERT_EQ("streqn_i '@' == '@'",   1, streqn_i("@", "@", 2));
	ASSERT_EQ("streqn_i '`' == '`'",   1, streqn_i("`", "`", 2));
	ASSERT_EQ("streqn_i '[' == '['",   1, streqn_i("[", "[", 2));
	ASSERT_EQ("streqn_i '{' == '{'",   1, streqn_i("{", "{", 2));
	ASSERT_EQ("streqn_i 'A' vs '@'",   0, streqn_i("A", "@", 2));
	ASSERT_EQ("streqn_i 'Z' vs '['",   0, streqn_i("Z", "[", 2));
	ASSERT_EQ("streqn_i 'a' vs '`'",   0, streqn_i("a", "`", 2));
	ASSERT_EQ("streqn_i 'z' vs '{'",   0, streqn_i("z", "{", 2));

	// Digits and punctuation are compared byte-for-byte (the fold
	// applies only to A-Z)...
	ASSERT_EQ("streqn_i digits",       1, streqn_i("12345", "12345", 10));
	ASSERT_EQ("streqn_i digits fold",  1, streqn_i("1A2B3", "1a2b3", 10));
	ASSERT_EQ("streqn_i punct",        1, streqn_i("GET /x", "get /x", 10));
	ASSERT_EQ("streqn_i punct sens",   0, streqn_i("GET /x", "get /y", 10));
	ASSERT_EQ("streqn_i tab",          1, streqn_i("a\tb", "A\tb", 5));

	// High-bit bytes (0x80-0xFF) must never be folded and must compare
	// exactly. The NEON path uses unsigned range compares, so this also
	// exercises the cmhs handling of the 0x80-0xFF range.
	char h1[64], h2[64];
	memset(h1, 'h', sizeof(h1));
	memset(h2, 'H', sizeof(h2));

	h1[0] = (char)0xE9; h1[1] = 0;
	h2[0] = (char)0xE9; h2[1] = 0;
	ASSERT_EQ("streqn_i 0xE9 == 0xE9",  1, streqn_i(h1, h2, 16));
	h2[0] = (char)0xC9;
	ASSERT_EQ("streqn_i 0xE9 vs 0xC9",  0, streqn_i(h1, h2, 16));

	// 0x20 apart but both outside A-Z -> must NOT fold to equal.
	h1[0] = (char)0x80; h2[0] = (char)0xA0;
	ASSERT_EQ("streqn_i 0x80 vs 0xA0",  0, streqn_i(h1, h2, 16));
	h1[0] = (char)0x90; h2[0] = (char)0xB0;
	ASSERT_EQ("streqn_i 0x90 vs 0xB0",  0, streqn_i(h1, h2, 16));
	h1[0] = (char)0x7F; h2[0] = (char)0x5F;
	ASSERT_EQ("streqn_i DEL vs '_'",    0, streqn_i(h1, h2, 16));

	// High-bit byte at the END of a NEON chunk (byte 15): the chunk's
	// stop mask must see the mismatch, not fold 0xE9 into 0xC9.
	memset(h1, 'a', 16);
	memset(h2, 'A', 16);
	h1[15] = (char)0xE9; h1[16] = 0;
	h2[15] = (char)0xC9; h2[16] = 0;
	ASSERT_EQ("streqn_i neon 0xE9@15 vs 0xC9", 0, streqn_i(h1, h2, 16));
	h2[15] = (char)0xE9;
	ASSERT_EQ("streqn_i neon 0xE9@15 == 0xE9", 1, streqn_i(h1, h2, 16));
}

// ── tests: NUL handling ────────────────────────────────────────────

static void test_streqn_i_nul(void) {
	TEST_SUITE("streqn_i NUL handling");

	// Byte loop path (maxlen < 16): comparison stops at the first NUL
	// in either string; two NULs at the same position are a match.
	ASSERT_EQ("streqn_i embedded NUL",   1, streqn_i("ab\0cd", "ab\0ef", 10));
	ASSERT_EQ("streqn_i NUL then tail",  1, streqn_i("ab\0", "ab\0c", 10));
	ASSERT_EQ("streqn_i NUL vs char",    0, streqn_i("ab\0c", "abc", 10));
	ASSERT_EQ("streqn_i one shorter",    0, streqn_i("abc", "ab", 10));
	ASSERT_EQ("streqn_i empty both",     1, streqn_i("", "", 10));
	ASSERT_EQ("streqn_i empty vs a",     0, streqn_i("", "a", 10));
	ASSERT_EQ("streqn_i empty maxlen0",  1, streqn_i("", "", 0));

	// NEON path: sweep the NUL position through the first 16-byte chunk.
	// When both strings carry their NUL at the same byte the comparison
	// ends there with a match; when only one does, it is a mismatch. The
	// prefix bytes before the NUL are identical on both sides so the
	// comparison can actually reach the NUL.
	char a[64], b[64];
	int ok = 1;
	for (int p = 0; p < 16; p++) {
		memset(a, 'x', sizeof(a));
		memset(b, 'x', sizeof(b));
		a[p] = 0;
		b[p] = 0;
		if (!streqn_i(a, b, 24)) { ok = 0; _FAIL("NUL@%d both — expected match", p); }
		a[p] = 0;
		b[p] = 'y';
		if (streqn_i(a, b, 24)) { ok = 0; _FAIL("NUL@%d vs char — expected mismatch", p); }
	}
	ASSERT_EQ("NUL sweep 0-15 (match & mismatch)", 1, ok);

	// NUL one byte apart: the strings genuinely differ in length.
	memset(a, 'x', sizeof(a));
	memset(b, 'x', sizeof(b));
	a[15] = 0;
	b[16] = 0;
	ASSERT_EQ("streqn_i NUL@15 vs NUL@16", 0, streqn_i(a, b, 24));

	// NUL in the second chunk, including its boundary bytes (16, 31)
	// and the first byte past it (32).
	static const int npos2[] = { 16, 20, 31, 32 };
	for (unsigned i = 0; i < sizeof(npos2) / sizeof(npos2[0]); i++) {
		int p = npos2[i];
		memset(a, 'x', sizeof(a));
		memset(b, 'x', sizeof(b));
		a[p] = 0;
		b[p] = 0;
		if (!streqn_i(a, b, 40)) { ok = 0; _FAIL("NUL@%d both (chunk 2) — expected match", p); }
		a[p] = 0;
		b[p] = 'x';
		if (streqn_i(a, b, 40)) { ok = 0; _FAIL("NUL@%d vs char (chunk 2) — expected mismatch", p); }
	}
	ASSERT_EQ("NUL sweep chunk 2", 1, ok);
}

// ── tests: mismatch positions ──────────────────────────────────────

static void test_streqn_i_mismatch_positions(void) {
	TEST_SUITE("streqn_i mismatch positions");

	// A single differing byte must be caught at every position of a
	// 16-byte NEON chunk, and a limit that stops before the mismatch
	// must still match ('A' vs 'X' folds to 'a' vs 'x').
	char a[64], b[64];
	int ok = 1;
	for (int p = 0; p < 16; p++) {
		memset(a, 'A', sizeof(a));
		memset(b, 'a', sizeof(b));
		a[16] = 0; b[16] = 0;
		b[p] = 'X';
		if (streqn_i(a, b, 16)) { ok = 0; _FAIL("mismatch@%d lim16 — expected mismatch", p); }
		if (p < 15) {
			if (streqn_i(a, b, 15)) { ok = 0; _FAIL("mismatch@%d lim15 — expected mismatch", p); }
		} else {
			if (!streqn_i(a, b, 15)) { ok = 0; _FAIL("mismatch@%d lim15 — expected match", p); }
		}
	}

	// Mismatch in the second NEON chunk (bytes 16-31).
	for (int p = 16; p < 32; p++) {
		memset(a, 'A', sizeof(a));
		memset(b, 'a', sizeof(b));
		a[32] = 0; b[32] = 0;
		b[p] = 'X';
		if (streqn_i(a, b, 32)) { ok = 0; _FAIL("mismatch@%d chunk2 — expected mismatch", p); }
	}
	ASSERT_EQ("all 16+16 mismatch positions", 1, ok);
}

// ── tests: byte-loop tail after a clean NEON chunk ─────────────────

static void test_streqn_i_byte_tail(void) {
	TEST_SUITE("streqn_i NEON chunk + byte tail");

	// 16 identical bytes, then the interesting byte in the tail: the
	// NEON loop must hand the tail to the byte loop unmodified.
	char a[64], b[64];

	// Match through the tail: both NUL at byte 16 (end of the chunk).
	memset(a, 'q', sizeof(a));
	memset(b, 'Q', sizeof(b));
	a[16] = 0; b[16] = 0;
	ASSERT_EQ("streqn_i 16+tail NUL",    1, streqn_i(a, b, 20));
	// One side keeps going past the NUL -> mismatch.
	b[16] = 'q'; b[17] = 0;
	ASSERT_EQ("streqn_i 16+NUL vs q",    0, streqn_i(a, b, 20));

	// Case folding and mismatch in the tail.
	memset(a, 'q', sizeof(a));
	memset(b, 'Q', sizeof(b));
	a[16] = 'Z'; a[17] = 0;
	b[16] = 'z'; b[17] = 0;
	ASSERT_EQ("streqn_i tail fold",      1, streqn_i(a, b, 20));
	b[16] = 'y';
	ASSERT_EQ("streqn_i tail mismatch",  0, streqn_i(a, b, 20));

	// NUL a few bytes into the tail (byte 18), both sides.
	memset(a, 'q', sizeof(a));
	memset(b, 'Q', sizeof(b));
	a[18] = 0; b[18] = 0;
	ASSERT_EQ("streqn_i tail NUL@18",    1, streqn_i(a, b, 30));
	b[18] = 'q';
	ASSERT_EQ("streqn_i tail NUL@18 vs q", 0, streqn_i(a, b, 30));

	// Limit cutting through the tail: the mismatch at byte 16 is a
	// match when maxlen = 16 and a mismatch when maxlen = 17.
	memset(a, 'q', sizeof(a));
	memset(b, 'Q', sizeof(b));
	a[16] = 'x'; a[17] = 0;
	b[16] = 'y'; b[17] = 0;
	ASSERT_EQ("streqn_i tail cut lim16", 1, streqn_i(a, b, 16));
	ASSERT_EQ("streqn_i tail cut lim17", 0, streqn_i(a, b, 17));
}

// ── tests: alignment sweep ─────────────────────────────────────────
// Real callers (get_header_field, get_filetype, h2_parse_range) pass
// pointers into buffers that are not necessarily 16-byte aligned, and
// the NEON path loads whole 16-byte chunks from wherever the pointers
// point. Sweep every start offset 0-15 for both strings.

static void test_streqn_i_alignment(void) {
	TEST_SUITE("streqn_i alignment (offsets 0-15 both strings)");
	char a[96], b[96];
	int ok = 1;

	for (int off_a = 0; off_a < 16; off_a++) {
		for (int off_b = 0; off_b < 16; off_b++) {
			// 16-byte NEON match, both strings unaligned.
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 16; i++) {
				a[off_a + i] = (char)('a' + i);
				b[off_b + i] = (char)('A' + i);
			}
			if (!streqn_i(a + off_a, b + off_b, 16)) {
				ok = 0;
				_FAIL("match off_a=%d off_b=%d — expected match", off_a, off_b);
			}

			// Mismatch at byte 5 of the same chunk.
			b[off_b + 5] = 'X';
			if (streqn_i(a + off_a, b + off_b, 16)) {
				ok = 0;
				_FAIL("mismatch off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}

			// NUL at byte 15 in both strings, limit past the chunk.
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 15; i++) {
				a[off_a + i] = (char)('a' + i);
				b[off_b + i] = (char)('A' + i);
			}
			a[off_a + 15] = 0;
			b[off_b + 15] = 0;
			if (!streqn_i(a + off_a, b + off_b, 32)) {
				ok = 0;
				_FAIL("NUL@15 match off_a=%d off_b=%d — expected match", off_a, off_b);
			}
			b[off_b + 15] = 'X';
			if (streqn_i(a + off_a, b + off_b, 32)) {
				ok = 0;
				_FAIL("NUL@15 vs X off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}

			// Two NEON chunks + a 1-byte tail (33 bytes total).
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 33; i++) {
				a[off_a + i] = (char)('a' + (i % 26));
				b[off_b + i] = (char)('A' + (i % 26));
			}
			if (!streqn_i(a + off_a, b + off_b, 33)) {
				ok = 0;
				_FAIL("33B match off_a=%d off_b=%d — expected match", off_a, off_b);
			}
			// Mismatch in the second chunk (byte 20).
			b[off_b + 20] = '!';
			if (streqn_i(a + off_a, b + off_b, 33)) {
				ok = 0;
				_FAIL("33B mismatch@20 off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}
		}
	}
	ASSERT_EQ("all 256 alignment cases", 1, ok);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_streqn_i_basic();
	test_streqn_i_neon();
	test_streqn_i_maxlen();
	test_streqn_i_case_folding();
	test_streqn_i_nul();
	test_streqn_i_mismatch_positions();
	test_streqn_i_byte_tail();
	test_streqn_i_alignment();
	test_summary();
	return 0;
}
