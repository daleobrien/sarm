// Candidate driver: the hand-written asm memcpy (src/util/memcpy.S).
//
// The wrapper declares x0-x6 clobbered so unrolled/NEON candidate
// variants that use extra scratch registers are safe.
#include "driver.h"

void copy_bytes(void *dst, const void *src, int64_t len) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"mov x2, %2\n"
		"bl memcpy\n"
		:
		: "r"(dst), "r"(src), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "memory");
}
