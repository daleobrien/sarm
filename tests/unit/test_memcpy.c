// Unit tests for src/util/memcpy.S
//
// memcpy(dst=x0, src=x1, len=x2) copies `len` bytes from src to dst using
// the standard C ABI. The implementation (see memcpy.S) copies in 16-byte
// ldp/stp chunks while len >= 16, then finishes any remaining 1-15 bytes
// with a byte-at-a-time loop; len == 0 is a no-op.
//
// This suite used to live inside test_util.c; it was split out into its
// own file so the asm memcpy gets the same dedicated, exhaustive coverage
// as the other util functions (test_strlen.c, test_streqn.c, ...).

#include "test_harness.h"

// ── inline asm wrapper ─────────────────────────────────────────────
// memcpy(dst=x0, src=x1, len=x2) — standard ABI, matches C.
// Clobbers match memcpy.S: x0, x1, x3, x4 (x2 holds len and is consumed).
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

// ── tests: basic cases (moved verbatim from test_util.c) ────────────

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

// ── tests: length sweep ────────────────────────────────────────────
// Every length 0-65 covers all three code paths: the len==0 early return,
// the byte-at-a-time loop (1-15), the first 16-byte chunk, and each
// chunk+remainder boundary (17/31/33/47/49/63/65). The destination is
// pre-filled with a sentinel so any overrun past `len` is caught.

static void test_memcpy_lengths(void) {
	TEST_SUITE("memcpy length sweep (0-65, byte loop ↔ 16-byte chunks)");
	uint8_t src[96], dst[96];
	for (int i = 0; i < (int)sizeof(src); i++)
		src[i] = (uint8_t)((i * 7) & 0xFF);

	int ok = 1;
	for (int64_t len = 0; len <= 65; len++) {
		memset(dst, 0xAA, sizeof(dst));
		memcpy_asm_wrapper(dst, src, len);

		if (memcmp(dst, src, (unsigned long)len) != 0) {
			ok = 0;
			_FAIL("len=%lld — content mismatch", (long long)len);
			continue;
		}
		// every byte past `len` must still be the sentinel (no overrun)
		for (int64_t i = len; i < (int64_t)sizeof(dst); i++) {
			if (dst[i] != 0xAA) {
				ok = 0;
				_FAIL("len=%lld — overrun at byte %lld (got 0x%02x)",
				      (long long)len, (long long)i, (unsigned)dst[i]);
				break;
			}
		}
	}
	ASSERT_EQ("all 66 lengths correct, no overrun", 1, ok);
}

// ── tests: long copies & binary content ─────────────────────────────
// Multi-chunk copies; sources filled with a byte pattern, all NULs and
// all 0xFF so binary (non-string) content is proven to copy through, and
// the source itself is verified untouched afterwards.

static void test_memcpy_long(void) {
	TEST_SUITE("memcpy long copies & binary content");
	uint8_t src[4096 + 16], dst[4096 + 16];
	int ok = 1;

	static const int64_t lens[] = {
		100, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1000, 4096
	};

	for (unsigned t = 0; t < sizeof(lens) / sizeof(lens[0]); t++) {
		int64_t len = lens[t];

		// pattern: byte i = (i*73 + 19) & 0xFF — every residue class
		for (int64_t i = 0; i < len; i++)
			src[i] = (uint8_t)((i * 73 + 19) & 0xFF);
		memset(dst, 0xAA, sizeof(dst));
		memcpy_asm_wrapper(dst, src, len);
		if (memcmp(dst, src, (unsigned long)len) != 0) {
			ok = 0;
			_FAIL("pattern len=%lld — content mismatch", (long long)len);
		} else if (dst[len] != 0xAA) {
			ok = 0;
			_FAIL("pattern len=%lld — overrun", (long long)len);
		}
		// the source must not be modified by the copy
		for (int64_t i = 0; i < len; i++) {
			if (src[i] != (uint8_t)((i * 73 + 19) & 0xFF)) {
				ok = 0;
				_FAIL("pattern len=%lld — source modified", (long long)len);
				break;
			}
		}

		// all-NUL source — embedded NUL bytes must copy through
		memset(src, 0, (unsigned long)len);
		memset(dst, 0xAA, sizeof(dst));
		memcpy_asm_wrapper(dst, src, len);
		if (memcmp(dst, src, (unsigned long)len) != 0) {
			ok = 0;
			_FAIL("NUL-filled len=%lld — content mismatch", (long long)len);
		} else if (dst[len] != 0xAA) {
			ok = 0;
			_FAIL("NUL-filled len=%lld — overrun", (long long)len);
		}

		// all-0xFF source — no sign/width confusion in the loads
		memset(src, 0xFF, (unsigned long)len);
		memset(dst, 0xAA, sizeof(dst));
		memcpy_asm_wrapper(dst, src, len);
		if (memcmp(dst, src, (unsigned long)len) != 0) {
			ok = 0;
			_FAIL("0xFF-filled len=%lld — content mismatch", (long long)len);
		} else if (dst[len] != 0xAA) {
			ok = 0;
			_FAIL("0xFF-filled len=%lld — overrun", (long long)len);
		}
	}
	ASSERT_EQ("all 12 long lengths × 3 fill patterns", 1, ok);
}

// ── tests: alignment sweep ─────────────────────────────────────────
// The asm jumps straight into 16-byte ldp/stp chunks without aligning
// either pointer, so a standard memcpy contract demands arbitrary src/dst
// offsets work. Sweep every offset in a 16-byte block on both sides
// (16x16 pairs) over lengths that use the byte loop, exactly one chunk,
// and chunks plus tails. Verified to pass on arm64 macOS/Linux (alignment
// checking disabled in user space); catches ports to stricter hardware.

static void test_memcpy_alignment(void) {
	TEST_SUITE("memcpy alignment sweep (src/dst offsets 0-15)");
	uint8_t src[16 + 64 + 16], dst[16 + 64 + 16];
	int ok = 1;

	for (int i = 0; i < (int)sizeof(src); i++)
		src[i] = (uint8_t)((i * 11 + 3) & 0xFF);

	static const int64_t lens[] = { 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 64 };

	for (int soff = 0; soff < 16; soff++) {
		for (int doff = 0; doff < 16; doff++) {
			for (unsigned li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
				int64_t len = lens[li];
				memset(dst, 0xAA, sizeof(dst));
				memcpy_asm_wrapper(dst + doff, src + soff, len);
				if (memcmp(dst + doff, src + soff, (unsigned long)len) != 0) {
					ok = 0;
					_FAIL("soff=%d doff=%d len=%lld — mismatch",
					      soff, doff, (long long)len);
				}
			}
		}
	}
	ASSERT_EQ("all 256 offset pairs × 11 lengths", 1, ok);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_memcpy();
	test_memcpy_lengths();
	test_memcpy_long();
	test_memcpy_alignment();
	test_summary();
	return 0;
}
