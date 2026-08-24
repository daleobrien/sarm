// Benchmark for src/crypto/gcm/encrypt.S:aes_gcm_encrypt -- complete
// AES-128-GCM seal across realistic TLS record sizes, 16 B to 16 KB
// (docs/SCRIPTS.md). Companion to bench_aes128_encrypt
// (AES-only) and bench_gcm_ghash_run (GHASH-only, through the real
// .Lgcm_ghash_run call path) -- together the three distinguish AES-only,
// GHASH-only and complete AES-GCM cost, so a candidate change can be
// confirmed to target the ~79% GHASH component (docs/HISTORY.md) rather
// than the ~9% AES-chain one.
//
// Build and run:
//   make -C scripts/benchmarks bench_aes_gcm_encrypt
//   ./scripts/benchmarks/_bench_bin/bench_aes_gcm_encrypt

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "asm_sym.h"

// aes_gcm_encrypt(x0=key[16], x1=iv[12], x2=aad, x3=aad_len, x4=pt,
//                  x5=pt_len, x6=ct_out, x7=tag_out[16])
// aes_gcm_decrypt has the matching seal-reversed signature; used here only
// as an independent round-trip correctness check (encrypt.S:14-23,
// decrypt.S -- not read in full here, but bench_primitives.c already
// establishes the round-trip protocol this driver reuses).
extern void aes_gcm_encrypt(const void *key, const void *iv, const void *aad,
                            int64_t aad_len, const void *pt, int64_t pt_len,
                            void *ct, void *tag)
	__asm__("aes_gcm_encrypt");
extern int64_t aes_gcm_decrypt(const void *key, const void *iv,
                               const void *aad, int64_t aad_len,
                               const void *ct, int64_t ct_len,
                               const void *tag, void *pt)
	__asm__("aes_gcm_decrypt");

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// aes_gcm_encrypt takes 8 arguments -- more live register operands than
// the compiler can allocate around a fully-clobbered inline-asm block (it
// refuses with "inline assembly requires more registers than available").
// bench_primitives.c hits the same wall and solves it by passing arguments
// through a global array loaded inside the asm via one known register;
// this reuses that pattern instead of inventing a second one.
//
// aes_gcm_encrypt calls into aes128_encrypt, which used to leave v8-v11
// dirty -- AAPCS64 makes those callee-saved, so any C double/float kept
// live across the call was at risk. That is fixed (round keys moved to
// v1-v7/v22-v25), but v0-v31 stay declared clobbered below: nothing
// FP-shaped should ever be live across a call into hand-written assembly,
// regardless of which registers the callee happens to use today.
// Non-static: a `static` array with no C-visible reads is fair game for
// the optimizer to drop (only the asm block below reads it, invisibly to
// the compiler), the same reason bench_primitives.c's bargs/bret are
// plain externally-linked globals rather than static.
uint64_t gcm_args[8];

static uint64_t timed_calls(uint64_t iters) {
	uint64_t n = iters;
	uint64_t t0 = now_ns();
	__asm__ __volatile__(
		"1:\n"
		ASM_ADDR_C("x8", "gcm_args")
		"  ldp  x0, x1, [x8]\n"
		"  ldp  x2, x3, [x8, #16]\n"
		"  ldp  x4, x5, [x8, #32]\n"
		"  ldp  x6, x7, [x8, #48]\n"
		"  bl   aes_gcm_encrypt\n"
		"  subs %[n], %[n], #1\n"
		"  b.ne 1b\n"
		: [n] "+r"(n)
		:
		// x19-x28 are NOT clobbered here: aes_gcm_encrypt's own header
		// documents them "saved/restored" -- it preserves their value
		// across the call, same property bench_primitives.c's bench_call
		// relies on for every primitive it times. Leaving them out is
		// also what leaves the compiler a register to place [n] in --
		// every other GPR below is genuinely clobbered.
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
		  "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30",
		  "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		  "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16",
		  "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25",
		  "v26", "v27", "v28", "v29", "v30", "v31");
	return now_ns() - t0;
}

int main(void) {
	static const int64_t sizes[] = {16, 64, 256, 1024, 4096, 16384};
	const int n_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

	uint8_t key[16], iv[12], aad[13];
	for (int i = 0; i < 16; i++)
		key[i] = (uint8_t)(i * 7 + 1);
	for (int i = 0; i < 12; i++)
		iv[i] = (uint8_t)(i * 5 + 3);
	for (int i = 0; i < 13; i++)
		aad[i] = (uint8_t)(i + 0x17);

	uint8_t *pt = aligned_alloc(64, 1 << 15);
	uint8_t *ct = aligned_alloc(64, 1 << 15);
	uint8_t *rt = aligned_alloc(64, 1 << 15);
	if (!pt || !ct || !rt) {
		fprintf(stderr, "allocation failed\n");
		return 1;
	}
	for (int i = 0; i < (1 << 15); i++)
		pt[i] = (uint8_t)((i * 131 + 17) & 0xFF);

	// Round-trip correctness at every size before trusting any timing.
	int failures = 0;
	uint8_t tag[16];
	for (int s = 0; s < n_sizes; s++) {
		int64_t len = sizes[s];
		aes_gcm_encrypt(key, iv, aad, sizeof aad, pt, len, ct, tag);
		memset(rt, 0, len);
		int64_t ok =
			aes_gcm_decrypt(key, iv, aad, sizeof aad, ct, len, tag, rt);
		if (ok != 1 || memcmp(pt, rt, len) != 0) {
			fprintf(stderr,
			        "  !! aes_gcm round trip FAILED at %lld bytes\n",
			        (long long)len);
			failures++;
		}
	}
	if (failures) {
		fprintf(stderr,
		        "  %d correctness check(s) FAILED -- refusing to report "
		        "timings\n",
		        failures);
		return 1;
	}

	double per_size_ns[6];
	for (int s = 0; s < n_sizes; s++) {
		int64_t len = sizes[s];
		int64_t iters = 20000000 / (len < 16 ? 16 : len);
		if (iters < 50)
			iters = 50;
		if (iters > 200000)
			iters = 200000;

		gcm_args[0] = (uint64_t)key;
		gcm_args[1] = (uint64_t)iv;
		gcm_args[2] = (uint64_t)aad;
		gcm_args[3] = (uint64_t)sizeof aad;
		gcm_args[4] = (uint64_t)pt;
		gcm_args[5] = (uint64_t)len;
		gcm_args[6] = (uint64_t)ct;
		gcm_args[7] = (uint64_t)tag;

		double best = 1e18;
		for (int r = 0; r < 7; r++) {
			double ns = (double)timed_calls(iters) / (double)iters;
			if (ns < best)
				best = ns;
		}
		per_size_ns[s] = best;
	}

	double sum_ns = 0.0;
	printf("{\"function\":\"aes_gcm_encrypt\",\"sizes\":{");
	for (int s = 0; s < n_sizes; s++) {
		sum_ns += per_size_ns[s];
		if (s)
			printf(",");
		printf("\"%lld\":%.3f", (long long)sizes[s], per_size_ns[s]);
	}
	// Primary metric: mean per-call runtime across the declared size set,
	// the same simple-mean protocol bench_memcpy.c uses -- the number the
	// optimizer's improvement gate compares against.
	double runtime_ns = sum_ns / (double)n_sizes;
	printf("},\"runtime_ns\":%.3f}\n", runtime_ns);
	printf("RESULT_NS=%.3f\n", runtime_ns);

	free(pt);
	free(ct);
	free(rt);
	return 0;
}
