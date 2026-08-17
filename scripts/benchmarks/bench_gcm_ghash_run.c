// Benchmark for the real GHASH implementation, .Lgcm_ghash_run
// (src/crypto/gcm/data.S:131) -- prompts/02-benchmark-substrate.md.
//
// Every GCM caller (aes_gcm_encrypt, aes_gcm_decrypt, and the standalone
// `ghash` entry point) reaches this local label directly; it is the actual
// server code path, not the unused standalone `ghash` symbol
// (src/crypto/gcm/ghash.S:38, no in-tree caller -- see
// docs/ANALYSIS-TOOLING.MD's "`ghash` does not shadow it"). This driver
// calls into it through gcm_ghash_run_probe.S, which #includes data.S to
// reach the local label and reproduces its documented entry conditions
// exactly (see that file's header) -- it is the same instructions as
// production, isolated from AES so multi-block GHASH work (prompt 03) can
// be measured independently of AES throughput work.
//
// `.Lgcm_ghash_run` has no `--function`-safe filename under
// arm-optimize.py's `bench_<function>.c` convention (the leading `.L`
// makes an awkward literal filename), so this benchmark is not
// auto-discovered. Invoke it explicitly, e.g.:
//
//   python3 scripts/arm-optimize.py --function .Lgcm_ghash_run \
//     --source src/crypto/gcm/data.S \
//     --benchmark "make -s -C scripts/benchmarks bench_gcm_ghash_run" "&&" \
//                 "./scripts/benchmarks/_bench_bin/bench_gcm_ghash_run"
//
// Build and run directly:
//   make -C scripts/benchmarks bench_gcm_ghash_run
//   ./scripts/benchmarks/_bench_bin/bench_gcm_ghash_run

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// sarm's assembly symbols carry no leading underscore (unlike Darwin's
// default C mangling); __asm__("name") pins the literal linker name,
// matching bench_primitives.c's ASM_SYM pattern.
extern void bench_ghash_run_timed(const void *data, int64_t len,
                                  const void *H, int64_t iters)
	__asm__("bench_ghash_run_timed");
extern void bench_ghash_run_once(const void *H, const void *aad,
                                 int64_t aad_len, const void *ct,
                                 int64_t ct_len, void *out)
	__asm__("bench_ghash_run_once");
// The unused-in-production standalone symbol, linked only as this probe's
// correctness oracle (same math, independent entry point).
extern void ghash(const void *h, const void *aad, int64_t aad_len,
                  const void *ct, int64_t ct_len, void *out)
	__asm__("ghash");

static uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double bench_size(const uint8_t *data, int64_t len, const uint8_t *H,
                         int64_t iters) {
	double best = 1e18;
	for (int r = 0; r < 7; r++) {
		uint64_t t0 = now_ns();
		bench_ghash_run_timed(data, len, H, iters);
		uint64_t t1 = now_ns();
		double per_call = (double)(t1 - t0) / (double)iters;
		if (per_call < best)
			best = per_call;
	}
	return best;
}

int main(void) {
	static const int64_t sizes[] = {16, 64, 256, 1024, 4096, 16384};
	const int n_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

	uint8_t H[16];
	for (int i = 0; i < 16; i++)
		H[i] = (uint8_t)(i * 11 + 5);

	uint8_t *data = aligned_alloc(64, 1 << 20);
	if (!data) {
		fprintf(stderr, "allocation failed\n");
		return 1;
	}
	for (int i = 0; i < (1 << 20); i++)
		data[i] = (uint8_t)((i * 131 + 17) & 0xFF);

	// Correctness: bench_ghash_run_once must agree with the real `ghash`
	// global byte-for-byte across block-count and tail-length edge cases.
	// A benchmark that cannot prove it exercises the right calling
	// convention is worse than none (prompts/02-benchmark-substrate.md).
	static const int64_t check_lens[] = {0, 1, 15, 16, 17, 63, 64, 65, 1024};
	int failures = 0;
	for (size_t i = 0; i < sizeof(check_lens) / sizeof(check_lens[0]); i++) {
		int64_t len = check_lens[i];
		uint8_t want[16], got[16];
		ghash(H, data, len, data, 0, want);
		bench_ghash_run_once(H, data, len, data, 0, got);
		if (memcmp(want, got, 16) != 0) {
			fprintf(stderr,
			        "  !! bench_ghash_run_once mismatch at len=%lld\n",
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

	double per_block[6];
	printf("{\"function\":\"gcm_ghash_run\",\"sizes\":{");
	for (int s = 0; s < n_sizes; s++) {
		int64_t len = sizes[s];
		int64_t iters = 20000000 / (len < 16 ? 16 : len);
		if (iters < 50)
			iters = 50;
		if (iters > 500000)
			iters = 500000;
		double per_call = bench_size(data, len, H, iters);
		int64_t blocks = (len + 15) / 16;
		per_block[s] = per_call / (double)blocks;
		if (s)
			printf(",");
		printf("\"%lld\":{\"per_call_ns\":%.3f,\"per_block_ns\":%.3f}",
		       (long long)len, per_call, per_block[s]);
	}
	// Primary metric: steady-state per-16-byte-block cost at the largest
	// (most-blocks) size, not a mean across sizes. .Lgcm_ghash_run's loop
	// is a serialized multiply-then-reduce Horner chain
	// (prompts/03-aes-gcm-throughput.md) -- a single-block call has no
	// preceding iteration to serialize against, so small sizes read
	// artificially cheap per block (confirmed here: ~2.2 ns/block at 16 B
	// vs ~8.0 ns/block at 16 KB) and would understate the real cost if
	// averaged in. The largest size is the steady-state throughput number
	// prompt 03's multi-block restructuring is judged against.
	double runtime_ns = per_block[n_sizes - 1];
	printf("},\"runtime_ns\":%.3f}\n", runtime_ns);
	printf("RESULT_NS=%.3f\n", runtime_ns);

	free(data);
	return 0;
}
