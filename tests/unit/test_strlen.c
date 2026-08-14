// Unit tests for src/util/strlen.S
//
// NOTE: This file links against util.o which defines its own "strlen" with
// a non-standard calling convention (arg in x1, not x0). Do NOT call libc
// strlen() — use the asm strlen via the wrapper instead.

#include "test_harness.h"

// ── inline asm wrapper ─────────────────────────────────────────────
// strlen(s=x1) → x0. Non-standard ABI: arg in x1.
// Clobbers match strlen.S: x0, x2, x3, v0, v1, v2 (plus x1 for the arg).
static inline int64_t strlen_asm_call(const char *s) {
	int64_t result;
	asm volatile(
		"mov x1, %1\n"
		"bl strlen\n"
		"mov %0, x0\n"
		: "=r"(result)
		: "r"(s)
		: "x0", "x1", "x2", "x3", "v0", "v1", "v2", "memory"
	);
	return result;
}

// ── tests: strlen (asm version, x1 ABI) ────────────────────────────

static void test_strlen(void) {
	TEST_SUITE("strlen (asm, x1 ABI)");
	ASSERT_EQ("strlen(\"\")",        0,  strlen_asm_call(""));
	ASSERT_EQ("strlen(\"a\")",       1,  strlen_asm_call("a"));
	ASSERT_EQ("strlen(\"hello\")",   5,  strlen_asm_call("hello"));
	ASSERT_EQ("strlen(\"hello world\")", 11, strlen_asm_call("hello world"));
}

// ── tests: alignment sweep ─────────────────────────────────────────
// The asm starts with a page-safe fragment pass when the string start is
// not 16-byte aligned, then switches to the NEON loop. Sweep every start
// offset within a 16-byte block and every short length to cover the
// fragment's shift-out-junk logic at all 16 alignments.

static void test_strlen_alignment(void) {
	TEST_SUITE("strlen alignment (offsets 0-15)");
	char buf[64];
	int ok = 1;

	for (int64_t off = 0; off < 16; off++) {
		for (int64_t len = 0; len < 16; len++) {
			memset(buf, 'A', sizeof(buf));
			buf[off + len] = 0;
			int64_t got = strlen_asm_call(buf + off);
			if (got != len) {
				ok = 0;
				_FAIL("align off=%lld len=%lld — got %lld",
				      (long long)off, (long long)len, (long long)got);
			}
		}
	}
	ASSERT_EQ("all 256 alignment cases", 1, ok);
}

// ── tests: long strings & 16-byte chunk boundaries ─────────────────
// The NEON loop scans 16 bytes per iteration; these lengths straddle the
// chunk boundaries so the NUL is found at the first/last byte of a chunk,
// and long runs place the NUL several chunks in.

static void test_strlen_long(void) {
	TEST_SUITE("strlen long strings & chunk boundaries");
	char buf[256];
	int ok = 1;

	static const int64_t lens[] = { 15, 16, 17, 31, 32, 33, 47, 48, 49,
		63, 64, 65, 127, 128, 129, 200, 255 };
	for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		int64_t len = lens[i];
		memset(buf, 'B', (unsigned long)len);
		buf[len] = 0;
		int64_t got = strlen_asm_call(buf);
		if (got != len) {
			ok = 0;
			_FAIL("len=%lld — got %lld", (long long)len, (long long)got);
		}
	}

	// Unaligned starts whose NUL lands in a later 16-byte chunk: the
	// fragment pass advances, then the main loop finds the NUL.
	memset(buf, 'C', 103);
	buf[103] = 0;
	ASSERT_EQ("unaligned off=3 len=100",  100, strlen_asm_call(buf + 3));
	memset(buf, 'C', 107);
	buf[107] = 0;
	ASSERT_EQ("unaligned off=7 len=100",  100, strlen_asm_call(buf + 7));
	memset(buf, 'C', 115);
	buf[115] = 0;
	ASSERT_EQ("unaligned off=15 len=100", 100, strlen_asm_call(buf + 15));

	// Unaligned starts at chunk-boundary lengths. The NUL goes at
	// off + len so the string really is len bytes long.
	static const int64_t ulens[] = { 1, 15, 16, 17, 31, 32, 33, 63, 64, 65 };
	for (unsigned i = 0; i < sizeof(ulens) / sizeof(ulens[0]); i++) {
		int64_t len = ulens[i];
		memset(buf, 'D', (unsigned long)(9 + len));
		buf[9 + len] = 0;
		int64_t got = strlen_asm_call(buf + 9);
		if (got != len) {
			ok = 0;
			_FAIL("unaligned off=9 len=%lld — got %lld",
			      (long long)len, (long long)got);
		}
	}
	ASSERT_EQ("all boundary cases", 1, ok);
}

// ── tests: multi-byte & high-bit bytes ─────────────────────────────
// strlen counts bytes, and the NUL detection (cmeq #0) is byte-wise, so
// bytes >= 0x80 and multi-byte UTF-8 sequences must never be mistaken for
// a terminator.

static void test_strlen_bytes(void) {
	TEST_SUITE("strlen multi-byte & high-bit bytes");

	// UTF-8 multi-byte sequences — length is in bytes, not characters.
	ASSERT_EQ("strlen(\"café\")",     5,  strlen_asm_call("café"));
	ASSERT_EQ("strlen(\"héllo\")",    6,  strlen_asm_call("héllo"));
	ASSERT_EQ("strlen(\"你好\")",     6,  strlen_asm_call("你好"));
	ASSERT_EQ("strlen(\"你好世界\")", 12, strlen_asm_call("你好世界"));

	char buf[64];

	// High-bit bytes in the first chunk and in the unaligned fragment.
	buf[0] = (char)0xFF; buf[1] = (char)0x80; buf[2] = 'A'; buf[3] = 0;
	ASSERT_EQ("strlen(FF 80 'A' \\0)", 3, strlen_asm_call(buf));

	buf[0] = (char)0x80; buf[1] = (char)0x81; buf[2] = 0;
	ASSERT_EQ("strlen(80 81 \\0)", 2, strlen_asm_call(buf));

	// Unaligned start, 40 high-bit bytes then the NUL in a later chunk.
	memset(buf, 0x80, 45);
	buf[45] = 0;
	ASSERT_EQ("unaligned off=5, 40 x 0x80", 40, strlen_asm_call(buf + 5));
}

// ── tests: embedded NUL ────────────────────────────────────────────
// strlen stops at the first NUL byte regardless of what follows.

static void test_strlen_embedded_nul(void) {
	TEST_SUITE("strlen embedded NUL");

	ASSERT_EQ("strlen(\"abc\\0def\")", 3, strlen_asm_call("abc\0def"));

	char buf[32];
	memset(buf, 'E', sizeof(buf));
	buf[0] = 'x'; buf[1] = 0; buf[2] = 'y';
	ASSERT_EQ("strlen('x' \\0 'y')", 1, strlen_asm_call(buf));

	// NUL at the very first byte — empty string despite trailing data.
	memset(buf, 'F', sizeof(buf));
	buf[0] = 0;
	ASSERT_EQ("strlen(\\0 'F'...)", 0, strlen_asm_call(buf));
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_strlen();
	test_strlen_alignment();
	test_strlen_long();
	test_strlen_bytes();
	test_strlen_embedded_nul();
	test_summary();
	return 0;
}
