// Unit tests for src/util/streqn.S
//
// streqn(a, b, maxlen) compares up to `maxlen` bytes of two strings
// case-sensitively, stopping at the first NUL byte (in either string)
// or mismatch. Returns 1 on match, 0 otherwise. Semantics match
// strncmp(a, b, maxlen) == 0.
//
// The implementation (see streqn.S) uses a 16-byte-wide NEON loop when
// maxlen >= 16 and a byte-at-a-time loop for shorter inputs and for the
// tail of a chunk that triggered a NUL/mismatch stop condition.
//
// This suite used to live inside test_util.c; it was split out into its
// own file (mirroring test_streqn_i.c for the case-insensitive variant)
// so the two asm functions get equal, symmetric coverage.

#include "test_harness.h"

// streqn uses the standard ABI (a=x0, b=x1, maxlen=x2, return x0),
// so it can be declared as a normal extern and called directly.
extern int64_t streqn(const char *a, const char *b, int64_t maxlen) __asm__("streqn");

// ── tests: basic case-sensitive semantics ────────────────────────────

static void test_streqn_basic(void) {
	TEST_SUITE("streqn (case-sensitive)");
	ASSERT_EQ("streqn exact match",         1, streqn("hello", "hello", 10));
	ASSERT_EQ("streqn mismatch",            0, streqn("hello", "world", 10));
	ASSERT_EQ("streqn prefix match (len)",  1, streqn("hello", "hel", 3));
	ASSERT_EQ("streqn limited no match",    0, streqn("hello", "help", 4));
	ASSERT_EQ("streqn case mismatch",       0, streqn("Hello", "hello", 10));
	ASSERT_EQ("streqn empty strings",       1, streqn("", "", 10));
	ASSERT_EQ("streqn empty vs non-empty",  0, streqn("", "a", 10));
	ASSERT_EQ("streqn long match",          1, streqn("HTTP/1.1", "HTTP/1.1", 10));
	ASSERT_EQ("streqn long mismatch",       0, streqn("HTTP/1.1", "HTTP/1.0", 10));
	ASSERT_EQ("streqn null terminates",     1, streqn("ab", "ab", 100));
	ASSERT_EQ("streqn different len",       0, streqn("abc", "ab", 100));
}

// ── tests: NEON vector path ──────────────────────────────────────────

static void test_streqn_neon(void) {
	TEST_SUITE("streqn NEON vector path");
	ASSERT_EQ("streqn neon 16 exact",       1, streqn("abcdefghijklmnop", "abcdefghijklmnop", 16));
	// Limit hit exactly at a 16-byte boundary; the second string is
	// longer, so a correct implementation must NOT compare the byte past
	// the limit (regression test: the old NEON loop fell into the byte
	// loop with x2 == 0 and compared past the end).
	ASSERT_EQ("streqn neon 16 limit",       1, streqn("abcdefghijklmnop", "abcdefghijklmnopXYZ", 16));
	ASSERT_EQ("streqn neon 17",             1, streqn("abcdefghijklmnopq", "abcdefghijklmnopq", 17));
	ASSERT_EQ("streqn neon mismatch@0",     0, streqn("abcdefghijklmnop", "xbcdefghijklmnop", 16));
	ASSERT_EQ("streqn neon mismatch@5",     0, streqn("abcdefghijklmnop", "abcdexghijklmnop", 16));
	ASSERT_EQ("streqn neon mismatch@15",    0, streqn("abcdefghijklmnop", "abcdefghijklmnox", 16));
	// The whole 16-byte chunk differs only by case: streqn must NOT fold
	// (streqn_i would match here).
	ASSERT_EQ("streqn neon case@0",         0, streqn("ABCDEFGHIJKLMNOP", "abcdefghijklmnop", 16));
	ASSERT_EQ("streqn neon 32 match",       1, streqn("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF", 32));
	ASSERT_EQ("streqn neon 32 mismatch",    0, streqn("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF", "ABCDEFGHIJKLMNOPQRSTUVWXYZABXDEF", 32));
	ASSERT_EQ("streqn neon 33 match",       1, streqn("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFG", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFG", 33));
	ASSERT_EQ("streqn neon null@20",        1, streqn("AAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAA", 30));
	ASSERT_EQ("streqn neon null@20 diff",   0, streqn("AAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAA", 30));
	ASSERT_EQ("streqn neon null@20 limit",  1, streqn("AAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAA", 20));
	ASSERT_EQ("streqn neon null@4",         1, streqn("abcd", "abcd", 16));
	ASSERT_EQ("streqn neon null@4 diff",    0, streqn("abcd", "abcde", 16));
}

// ── tests: maxlen limits ─────────────────────────────────────────────

static void test_streqn_maxlen(void) {
	TEST_SUITE("streqn maxlen limits");

	// maxlen == 0 compares nothing -> always a match, even for
	// completely different strings.
	ASSERT_EQ("streqn maxlen=0 diff",    1, streqn("abc", "xyz", 0));
	ASSERT_EQ("streqn maxlen=0 same",    1, streqn("abc", "abc", 0));
	ASSERT_EQ("streqn maxlen=0 empty",   1, streqn("", "", 0));
	// ... and case difference is irrelevant when nothing is compared.
	ASSERT_EQ("streqn maxlen=0 case",    1, streqn("A", "a", 0));

	// maxlen == 1 compares only the first byte.
	ASSERT_EQ("streqn maxlen=1",         1, streqn("AbC", "AbC", 1));
	ASSERT_EQ("streqn maxlen=1 mismatch", 0, streqn("AbC", "xbc", 1));
	ASSERT_EQ("streqn maxlen=1 case",    0, streqn("A", "a", 1));

	// A limit that cuts off before a later mismatch is still a match.
	ASSERT_EQ("streqn limit cuts early", 1, streqn("abc", "abd", 2));
	ASSERT_EQ("streqn limit at mismatch", 0, streqn("abc", "abd", 3));
	ASSERT_EQ("streqn prefix vs longer", 1, streqn("abcdef", "abcXYZ", 3));
	ASSERT_EQ("streqn header prefix",    1, streqn("CONTENT-TYPE", "CONTENT-LENGTH", 8));

	// The byte loop (maxlen < 16) and the NEON loop (maxlen >= 16) must
	// agree on the same inputs, and a mismatch at the byte-15/16
	// threshold flips exactly when the limit reaches it.
	ASSERT_EQ("streqn 15-byte limit",    1, streqn("qwertyuiopasdfgh", "qwertyuiopasdfgh", 15));
	ASSERT_EQ("streqn 16-byte limit",    1, streqn("qwertyuiopasdfgh", "qwertyuiopasdfgh", 16));
	ASSERT_EQ("streqn mismatch@15 lim15", 1, streqn("abcdefghijklmnop", "abcdefghijklmnox", 15));
	ASSERT_EQ("streqn mismatch@15 lim16", 0, streqn("abcdefghijklmnop", "abcdefghijklmnox", 16));
}

// ── tests: case sensitivity ──────────────────────────────────────────
// The whole point of streqn (vs streqn_i): bytes are compared exactly.

static void test_streqn_case_sensitive(void) {
	TEST_SUITE("streqn case sensitivity bounds");

	// Full A-Z / a-z alphabet: opposite case must NOT match, same case
	// must. The alphabet runs through the NEON path (16 + 10 bytes).
	char up[32], lo[32];
	memset(up, 'u', sizeof(up));
	memset(lo, 'l', sizeof(lo));
	for (int i = 0; i < 26; i++) {
		up[i] = (char)('A' + i);
		lo[i] = (char)('a' + i);
	}
	up[26] = 0; lo[26] = 0;
	ASSERT_EQ("streqn A-Z vs a-z",   0, streqn(up, lo, 26));
	ASSERT_EQ("streqn a-z vs A-Z",   0, streqn(lo, up, 26));
	ASSERT_EQ("streqn A-Z vs A-Z",   1, streqn(up, up, 26));
	ASSERT_EQ("streqn a-z vs a-z",   1, streqn(lo, lo, 26));

	// Single bytes at the edges of the fold range. For a case-sensitive
	// compare these are plain byte compares: 0x20-apart pairs differ,
	// equal bytes match.
	ASSERT_EQ("streqn 'A' vs 'a'",   0, streqn("A", "a", 2));
	ASSERT_EQ("streqn 'Z' vs 'z'",   0, streqn("Z", "z", 2));
	ASSERT_EQ("streqn 'a' vs 'A'",   0, streqn("a", "A", 2));
	ASSERT_EQ("streqn 'z' vs 'Z'",   0, streqn("z", "Z", 2));
	ASSERT_EQ("streqn 'A' vs '@'",   0, streqn("A", "@", 2));
	ASSERT_EQ("streqn 'Z' vs '['",   0, streqn("Z", "[", 2));
	ASSERT_EQ("streqn '@' vs '`'",   0, streqn("@", "`", 2));
	ASSERT_EQ("streqn '[' vs '{'",   0, streqn("[", "{", 2));
	ASSERT_EQ("streqn '@' == '@'",   1, streqn("@", "@", 2));
	ASSERT_EQ("streqn '[' == '['",   1, streqn("[", "[", 2));

	// Digits, punctuation and control chars are compared byte-for-byte.
	ASSERT_EQ("streqn digits",       1, streqn("12345", "12345", 10));
	ASSERT_EQ("streqn digits case",  0, streqn("1A2B3", "1a2b3", 10));
	ASSERT_EQ("streqn punct",        1, streqn("GET /x", "GET /x", 10));
	ASSERT_EQ("streqn punct sens",   0, streqn("GET /x", "GET /y", 10));
	ASSERT_EQ("streqn tab",          1, streqn("a\tb", "a\tb", 5));

	// High-bit bytes (0x80-0xFF) compare exactly, including inside a
	// NEON chunk (the equality compare is signedness-agnostic).
	char h1[64], h2[64];
	memset(h1, 'h', sizeof(h1));
	memset(h2, 'h', sizeof(h2));

	h1[0] = (char)0xE9; h1[1] = 0;
	h2[0] = (char)0xE9; h2[1] = 0;
	ASSERT_EQ("streqn 0xE9 == 0xE9",  1, streqn(h1, h2, 16));
	h2[0] = (char)0xC9;
	ASSERT_EQ("streqn 0xE9 vs 0xC9",  0, streqn(h1, h2, 16));

	h1[0] = (char)0x80; h2[0] = (char)0xA0;
	ASSERT_EQ("streqn 0x80 vs 0xA0",  0, streqn(h1, h2, 16));
	h1[0] = (char)0x90; h2[0] = (char)0xB0;
	ASSERT_EQ("streqn 0x90 vs 0xB0",  0, streqn(h1, h2, 16));
	h1[0] = (char)0x7F; h2[0] = (char)0x5F;
	ASSERT_EQ("streqn DEL vs '_'",    0, streqn(h1, h2, 16));

	// High-bit byte at the END of a NEON chunk (byte 15): the chunk's
	// stop mask must see the mismatch, not compare past the limit.
	memset(h1, 'a', 16);
	memset(h2, 'a', 16);
	h1[15] = (char)0xE9; h1[16] = 0;
	h2[15] = (char)0xC9; h2[16] = 0;
	ASSERT_EQ("streqn neon 0xE9@15 vs 0xC9", 0, streqn(h1, h2, 16));
	h2[15] = (char)0xE9;
	ASSERT_EQ("streqn neon 0xE9@15 == 0xE9", 1, streqn(h1, h2, 16));
}

// ── tests: NUL handling ──────────────────────────────────────────────

static void test_streqn_nul(void) {
	TEST_SUITE("streqn NUL handling");

	// Byte loop path (maxlen < 16): comparison stops at the first NUL
	// in either string; two NULs at the same position are a match.
	ASSERT_EQ("streqn embedded NUL",   1, streqn("ab\0cd", "ab\0ef", 10));
	ASSERT_EQ("streqn NUL then tail",  1, streqn("ab\0", "ab\0c", 10));
	ASSERT_EQ("streqn NUL vs char",    0, streqn("ab\0c", "abc", 10));
	ASSERT_EQ("streqn char vs NUL",    0, streqn("abc", "ab\0c", 10));
	ASSERT_EQ("streqn one shorter",    0, streqn("abc", "ab", 10));
	ASSERT_EQ("streqn empty both",     1, streqn("", "", 10));
	ASSERT_EQ("streqn empty vs a",     0, streqn("", "a", 10));
	ASSERT_EQ("streqn empty maxlen0",  1, streqn("", "", 0));

	// NEON path: sweep the NUL position through the first 16-byte chunk.
	// The NEON loop detects NULs on str1 only and catches a str1-only
	// NUL vs str2 char via the equality mask, so exercise both
	// directions. The prefix bytes before the NUL are identical on both
	// sides so the comparison can actually reach the NUL.
	char a[64], b[64];
	int ok = 1;
	for (int p = 0; p < 16; p++) {
		memset(a, 'x', sizeof(a));
		memset(b, 'x', sizeof(b));
		a[p] = 0;
		b[p] = 0;
		if (!streqn(a, b, 24)) { ok = 0; _FAIL("NUL@%d both — expected match", p); }
		a[p] = 0;
		b[p] = 'y';
		if (streqn(a, b, 24)) { ok = 0; _FAIL("NUL@%d vs char — expected mismatch", p); }
		a[p] = 'y';
		b[p] = 0;
		if (streqn(a, b, 24)) { ok = 0; _FAIL("char vs NUL@%d — expected mismatch", p); }
	}
	ASSERT_EQ("NUL sweep 0-15 (match & both mismatch dirs)", 1, ok);

	// NUL one byte apart: the strings genuinely differ in length.
	memset(a, 'x', sizeof(a));
	memset(b, 'x', sizeof(b));
	a[15] = 0;
	b[16] = 0;
	ASSERT_EQ("streqn NUL@15 vs NUL@16", 0, streqn(a, b, 24));

	// NUL in the second chunk, including its boundary bytes (16, 31)
	// and the first byte past it (32).
	static const int npos2[] = { 16, 20, 31, 32 };
	for (unsigned i = 0; i < sizeof(npos2) / sizeof(npos2[0]); i++) {
		int p = npos2[i];
		memset(a, 'x', sizeof(a));
		memset(b, 'x', sizeof(b));
		a[p] = 0;
		b[p] = 0;
		if (!streqn(a, b, 40)) { ok = 0; _FAIL("NUL@%d both (chunk 2) — expected match", p); }
		a[p] = 0;
		b[p] = 'x';
		if (streqn(a, b, 40)) { ok = 0; _FAIL("NUL@%d vs char (chunk 2) — expected mismatch", p); }
		a[p] = 'x';
		b[p] = 0;
		if (streqn(a, b, 40)) { ok = 0; _FAIL("char vs NUL@%d (chunk 2) — expected mismatch", p); }
	}
	ASSERT_EQ("NUL sweep chunk 2", 1, ok);
}

// ── tests: mismatch positions ────────────────────────────────────────

static void test_streqn_mismatch_positions(void) {
	TEST_SUITE("streqn mismatch positions");

	// A single differing byte must be caught at every position of a
	// 16-byte NEON chunk, and a limit that stops before the mismatch
	// must still match.
	char a[64], b[64];
	int ok = 1;
	for (int p = 0; p < 16; p++) {
		memset(a, 'A', sizeof(a));
		memset(b, 'A', sizeof(b));
		a[16] = 0; b[16] = 0;
		b[p] = 'X';
		if (streqn(a, b, 16)) { ok = 0; _FAIL("mismatch@%d lim16 — expected mismatch", p); }
		if (p < 15) {
			if (streqn(a, b, 15)) { ok = 0; _FAIL("mismatch@%d lim15 — expected mismatch", p); }
		} else {
			if (!streqn(a, b, 15)) { ok = 0; _FAIL("mismatch@%d lim15 — expected match", p); }
		}
	}

	// Mismatch in the second NEON chunk (bytes 16-31).
	for (int p = 16; p < 32; p++) {
		memset(a, 'A', sizeof(a));
		memset(b, 'A', sizeof(b));
		a[32] = 0; b[32] = 0;
		b[p] = 'X';
		if (streqn(a, b, 32)) { ok = 0; _FAIL("mismatch@%d chunk2 — expected mismatch", p); }
	}
	ASSERT_EQ("all 16+16 mismatch positions", 1, ok);
}

// ── tests: byte-loop tail after a clean NEON chunk ───────────────────

static void test_streqn_byte_tail(void) {
	TEST_SUITE("streqn NEON chunk + byte tail");

	// 16 identical bytes, then the interesting byte in the tail: the
	// NEON loop must hand the tail to the byte loop unmodified.
	char a[64], b[64];

	// Match through the tail: both NUL at byte 16 (end of the chunk).
	memset(a, 'q', sizeof(a));
	memset(b, 'q', sizeof(b));
	a[16] = 0; b[16] = 0;
	ASSERT_EQ("streqn 16+tail NUL",   1, streqn(a, b, 20));
	// One side keeps going past the NUL -> mismatch.
	b[16] = 'q'; b[17] = 0;
	ASSERT_EQ("streqn 16+NUL vs q",   0, streqn(a, b, 20));

	// Match and mismatch in the tail.
	memset(a, 'q', sizeof(a));
	memset(b, 'q', sizeof(b));
	a[16] = 'Z'; a[17] = 0;
	b[16] = 'Z'; b[17] = 0;
	ASSERT_EQ("streqn tail match",    1, streqn(a, b, 20));
	b[16] = 'y';
	ASSERT_EQ("streqn tail mismatch", 0, streqn(a, b, 20));

	// NUL a few bytes into the tail (byte 18), both sides.
	memset(a, 'q', sizeof(a));
	memset(b, 'q', sizeof(b));
	a[18] = 0; b[18] = 0;
	ASSERT_EQ("streqn tail NUL@18",   1, streqn(a, b, 30));
	b[18] = 'q';
	ASSERT_EQ("streqn tail NUL@18 vs q", 0, streqn(a, b, 30));

	// Limit cutting through the tail: the mismatch at byte 16 is a
	// match when maxlen = 16 and a mismatch when maxlen = 17.
	memset(a, 'q', sizeof(a));
	memset(b, 'q', sizeof(b));
	a[16] = 'x'; a[17] = 0;
	b[16] = 'y'; b[17] = 0;
	ASSERT_EQ("streqn tail cut lim16", 1, streqn(a, b, 16));
	ASSERT_EQ("streqn tail cut lim17", 0, streqn(a, b, 17));
}

// ── tests: alignment sweep ───────────────────────────────────────────
// Real callers (lookup_embedded) pass pointers into buffers that are not
// necessarily 16-byte aligned, and the NEON path loads whole 16-byte
// chunks from wherever the pointers point. Sweep every start offset
// 0-15 for both strings. Note both buffers hold identical bytes here —
// streqn is case-sensitive, so unlike the streqn_i suite there is no
// 'a' vs 'A' pairing to fold.

static void test_streqn_alignment(void) {
	TEST_SUITE("streqn alignment (offsets 0-15 both strings)");
	char a[96], b[96];
	int ok = 1;

	for (int off_a = 0; off_a < 16; off_a++) {
		for (int off_b = 0; off_b < 16; off_b++) {
			// 16-byte NEON match, both strings unaligned.
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 16; i++) {
				a[off_a + i] = (char)('a' + i);
				b[off_b + i] = (char)('a' + i);
			}
			if (!streqn(a + off_a, b + off_b, 16)) {
				ok = 0;
				_FAIL("match off_a=%d off_b=%d — expected match", off_a, off_b);
			}

			// Mismatch at byte 5 of the same chunk.
			b[off_b + 5] = 'X';
			if (streqn(a + off_a, b + off_b, 16)) {
				ok = 0;
				_FAIL("mismatch off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}

			// NUL at byte 15 in both strings, limit past the chunk.
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 15; i++) {
				a[off_a + i] = (char)('a' + i);
				b[off_b + i] = (char)('a' + i);
			}
			a[off_a + 15] = 0;
			b[off_b + 15] = 0;
			if (!streqn(a + off_a, b + off_b, 32)) {
				ok = 0;
				_FAIL("NUL@15 match off_a=%d off_b=%d — expected match", off_a, off_b);
			}
			b[off_b + 15] = 'X';
			if (streqn(a + off_a, b + off_b, 32)) {
				ok = 0;
				_FAIL("NUL@15 vs X off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}

			// Two NEON chunks + a 1-byte tail (33 bytes total).
			memset(a, 'Z', sizeof(a));
			memset(b, 'Z', sizeof(b));
			for (int i = 0; i < 33; i++) {
				a[off_a + i] = (char)('a' + (i % 26));
				b[off_b + i] = (char)('a' + (i % 26));
			}
			if (!streqn(a + off_a, b + off_b, 33)) {
				ok = 0;
				_FAIL("33B match off_a=%d off_b=%d — expected match", off_a, off_b);
			}
			// Mismatch in the second chunk (byte 20).
			b[off_b + 20] = '!';
			if (streqn(a + off_a, b + off_b, 33)) {
				ok = 0;
				_FAIL("33B mismatch@20 off_a=%d off_b=%d — expected mismatch", off_a, off_b);
			}
		}
	}
	ASSERT_EQ("all 256 alignment cases", 1, ok);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_streqn_basic();
	test_streqn_neon();
	test_streqn_maxlen();
	test_streqn_case_sensitive();
	test_streqn_nul();
	test_streqn_mismatch_positions();
	test_streqn_byte_tail();
	test_streqn_alignment();
	test_summary();
	return 0;
}
