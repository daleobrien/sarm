// Benchmark for src/crypto/aes128/encrypt.S -- the AES-only component of
// AES-GCM cost (~9% measured, docs/PROFILE.MD), isolated from GHASH so the
// two can't be conflated (prompts/02-benchmark-substrate.md).
//
// Build and run:
//   make -C scripts/benchmarks bench_aes128_encrypt
//   ./scripts/benchmarks/_bench_bin/bench_aes128_encrypt

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// aes128_key_expand(x0=key[16], x1=rk_out[176])
// aes128_encrypt(x0=in[16], x1=rk[176], x2=out[16])
//
// sarm's assembly symbols carry no leading underscore (unlike Darwin's
// default C mangling), so a plain `extern` here would make the C compiler
// look for the wrong linker name -- __asm__("name") pins the literal
// symbol, matching bench_primitives.c's ASM_SYM pattern.
extern void aes128_key_expand(const void *key, void *rk)
	__asm__("aes128_key_expand");
extern void aes128_encrypt(const void *in, const void *rk, void *out)
	__asm__("aes128_encrypt");

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// aes128_encrypt uses v8-v11 as round-key registers and does not restore
// them (encrypt.S's own header) -- AAPCS64 makes the low 64 bits of v8-v15
// callee-saved, so C code that keeps a value live in that range across the
// call risks corruption. The timing loop is inline asm with v0-v31
// declared clobbered, matching bench_primitives.c's bench_call.
static uint64_t timed_calls(const void *in, const void *rk, void *out,
                            uint64_t iters) {
	uint64_t n = iters;
	uint64_t t0 = now_ns();
	__asm__ __volatile__(
		"1:\n"
		"  mov x0, %[in]\n"
		"  mov x1, %[rk]\n"
		"  mov x2, %[out]\n"
		"  bl aes128_encrypt\n"
		"  subs %[n], %[n], #1\n"
		"  b.ne 1b\n"
		: [n] "+r"(n)
		: [in] "r"(in), [rk] "r"(rk), [out] "r"(out)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x9", "x10", "x11",
		  "x12", "x13", "x14", "x15", "x16", "x17", "x30", "cc", "memory",
		  "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
		  "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",
		  "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28",
		  "v29", "v30", "v31");
	return now_ns() - t0;
}

int main(void) {
	// FIPS-197 Appendix B AES-128 known-answer test.
	static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	                                0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
	                                0x0e, 0x0f};
	static const uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	                               0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
	                               0xee, 0xff};
	static const uint8_t expect_ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
	                                      0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
	                                      0x70, 0xb4, 0xc5, 0x5a};

	uint8_t rk[176], ct[16];
	aes128_key_expand(key, rk);
	aes128_encrypt(pt, rk, ct);
	if (memcmp(ct, expect_ct, 16) != 0) {
		fprintf(stderr, "  !! FIPS-197 known-answer check FAILED -- "
		                "refusing to report timings\n");
		return 1;
	}

	uint8_t in[16], out[16];
	memcpy(in, pt, 16);

	double best = 1e18;
	const uint64_t iters = 5000000;
	for (int r = 0; r < 7; r++) {
		double ns = (double)timed_calls(in, rk, out, iters) / (double)iters;
		if (ns < best)
			best = ns;
	}

	printf("{\"function\":\"aes128_encrypt\",\"runtime_ns\":%.3f}\n", best);
	printf("RESULT_NS=%.3f\n", best);
	return 0;
}
