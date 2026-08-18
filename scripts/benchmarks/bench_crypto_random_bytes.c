// Benchmark for src/crypto/random.S -- prints machine-readable JSON.
//
// crypto_random_bytes does not touch the vector registers, so a plain
// AAPCS64 call with x0-x18/x30 declared clobbered is enough -- unlike
// bench_primitives.c's trampoline, no v0-v31 clobber is needed. It is a
// real open("/dev/urandom")+read+close per call, so unlike the arithmetic
// primitives elsewhere in this directory this number is dominated by
// syscall cost, not instruction count (prompts/05 measured ~8.3-8.5 us/call
// here, three orders of magnitude above the field-arithmetic primitives
// this directory otherwise benchmarks).
//
// Protocol (OPTIMISATION.MD, "One change I'd make to the Python
// prototype"): emit {"function":..., "runtime_ns":..., "sizes": {...}}
// plus a RESULT_NS= fallback line. The optimizer parses either.
//
// Build and run:
//   make bench_crypto_random_bytes && ./_bench_bin/bench_crypto_random_bytes

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define ASM_SYM(name) extern const char name[] __asm__(#name)
ASM_SYM(crypto_random_bytes);

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// crypto_random_bytes(buf=x0, len=x1) -- carry-flag return, ignored here;
// a failing read would leave buf's contents visibly wrong under -check,
// but there is nothing to check against for random bytes, so this
// benchmark times it and trusts the unit suite (tests/unit/test_crypto_random)
// for correctness.
static inline void asm_crypto_random_bytes(void *buf, int64_t len) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"bl crypto_random_bytes\n"
		:
		: "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30",
		  "cc", "memory");
}

static double bench_len(int64_t len, int iterations, uint8_t *buf) {
	double best = 1e18;
	for (int r = 0; r < 9; r++) {
		uint64_t t0 = now_ns();
		for (int i = 0; i < iterations; i++)
			asm_crypto_random_bytes(buf, len);
		uint64_t t1 = now_ns();
		double per_op = (double)(t1 - t0) / (double)iterations;
		if (per_op < best)
			best = per_op;
	}
	return best;
}

int main(void) {
	static uint8_t buf[64];

	// Warm up / sanity: two calls should not produce identical output
	// (astronomically unlikely for a real CSPRNG, and the cheapest
	// smoke test that the device is actually being read).
	static uint8_t a[32], b[32];
	asm_crypto_random_bytes(a, 32);
	asm_crypto_random_bytes(b, 32);
	int same = 1;
	for (int i = 0; i < 32; i++)
		if (a[i] != b[i]) { same = 0; break; }
	if (same) {
		fprintf(stderr, "  !! crypto_random_bytes produced identical "
		                "32-byte outputs twice in a row\n");
		return 1;
	}

	static const int64_t sizes[] = {16, 32, 64};
	const int n_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

	double sum = 0.0;
	printf("{\"function\":\"crypto_random_bytes\",\"sizes\":{");
	for (int s = 0; s < n_sizes; s++) {
		int64_t len = sizes[s];
		double per = bench_len(len, 2000, buf);
		sum += per;
		if (s)
			printf(",");
		printf("\"%lld\":%.1f", (long long)len, per);
	}
	double runtime_ns = sum / (double)n_sizes;
	printf("},\"runtime_ns\":%.1f}\n", runtime_ns);
	printf("RESULT_NS=%.1f\n", runtime_ns);
	return 0;
}
