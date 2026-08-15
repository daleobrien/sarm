// Benchmark for src/util/memcpy.S -- prints machine-readable JSON.
//
// Protocol (OPTIMISATION.MD, "One change I'd make to the Python
// prototype"): emit {"function":..., "runtime_ns":..., "sizes": {...}}
// plus a RESULT_NS= fallback line. The optimizer parses either.
//
// The asm wrapper declares x0-x6 clobbered so unrolled/NEON candidate
// variants that use more scratch registers are safe against the
// compiler's register allocator.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// memcpy(dst=x0, src=x1, len=x2) -- standard ABI.
static inline void asm_memcpy(void *dst, const void *src, int64_t len) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"mov x2, %2\n"
		"bl memcpy\n"
		:
		: "r"(dst), "r"(src), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "memory");
}

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double bench_size(int64_t len, int iterations, uint8_t *src, uint8_t *dst) {
	double best = 1e18;
	for (int r = 0; r < 7; r++) {
		uint64_t t0 = now_ns();
		for (int i = 0; i < iterations; i++)
			asm_memcpy(dst, src, len);
		uint64_t t1 = now_ns();
		double per_op = (double)(t1 - t0) / (double)iterations;
		if (per_op < best)
			best = per_op;
	}
	return best;
}

int main(void) {
	static const int64_t sizes[] = {16, 64, 256, 1024, 4096, 65536};
	const int n_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

	uint8_t *src = aligned_alloc(64, 1 << 20);
	uint8_t *dst = aligned_alloc(64, 1 << 20);
	if (!src || !dst) {
		fprintf(stderr, "allocation failed\n");
		return 1;
	}
	for (int i = 0; i < (1 << 20); i++) {
		src[i] = (uint8_t)((i * 131 + 17) & 0xFF);
		dst[i] = 0xAA;
	}

	// Warm up (also catches wrong-code before we print anything).
	asm_memcpy(dst, src, 4096);
	if (dst[0] != src[0] || dst[4095] != src[4095]) {
		fprintf(stderr, "sanity copy mismatch\n");
		return 1;
	}

	double sum = 0.0;
	printf("{\"function\":\"memcpy\",\"sizes\":{");
	for (int s = 0; s < n_sizes; s++) {
		int64_t len = sizes[s];
		int iterations = (int)(20000000 / (len < 16 ? 16 : len));
		if (iterations < 100)
			iterations = 100;
		if (iterations > 2000000)
			iterations = 2000000;
		double per = bench_size(len, iterations, src, dst);
		sum += per;
		if (s)
			printf(",");
		printf("\"%lld\":%.3f", (long long)len, per);
	}
	double runtime_ns = sum / (double)n_sizes;
	printf("},\"runtime_ns\":%.3f}\n", runtime_ns);
	printf("RESULT_NS=%.3f\n", runtime_ns);

	free(src);
	free(dst);
	return 0;
}
