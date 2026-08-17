// Benchmark for p256_fe_mul (src/crypto/p256/sqr_mul.S:188) that also
// reports p256_bn_mul and p256_reduce in the same run, so the fraction
// of p256_fe_mul's time spent in reduction vs multiplication can be
// computed directly (prompts/02-benchmark-substrate.md: "the benchmark
// must let you compute what fraction of p256_fe_mul's time is
// reduction versus multiplication, both before and after prompt 04's
// change"). p256_reduce is reached through p256_reduce_probe.S (see
// that file for why -- it has no `.global`); the real p256_fe_mul and
// p256_bn_mul are the ordinary `.global` symbols, linked directly.
//
// All P-256 field arithmetic here is integer-only; a plain `extern` C
// call is ABI-safe (see bench_p256_reduce.c).
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_fe_mul
//   ./scripts/benchmarks/_bench_bin/bench_p256_fe_mul

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_fe_mul(uint64_t *out, const uint64_t *a, const uint64_t *b)
    __asm__("p256_fe_mul");
extern void p256_bn_mul(uint64_t *out, const uint64_t *a, int64_t na,
                        const uint64_t *b, int64_t nb)
    __asm__("p256_bn_mul");
extern void bench_p256_reduce_entry(uint64_t *out, const uint64_t *T)
    __asm__("bench_p256_reduce_entry");

static const uint64_t GX[4] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};
static const uint64_t GY[4] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    // Correctness: bn_mul(a,b) then the probe's reduce must equal the
    // real p256_fe_mul(a,b) -- the same cross-check bench_p256_reduce.c
    // uses, run here too since this file calls the probe directly.
    uint64_t T[8], via_probe[4], via_real[4];
    p256_bn_mul(T, GX, 4, GY, 4);
    bench_p256_reduce_entry(via_probe, T);
    p256_fe_mul(via_real, GX, GY);
    if (memcmp(via_probe, via_real, sizeof via_probe) != 0) {
        fprintf(stderr,
                "p256_reduce probe disagrees with the real p256_fe_mul -- "
                "numbers below would not be trustworthy\n");
        return 1;
    }

    // Warm up each path.
    uint64_t out[4];
    p256_fe_mul(out, GX, GY);
    p256_bn_mul(T, GX, 4, GY, 4);
    bench_p256_reduce_entry(out, T);

    const int iterations = 2000000;

    double best_fe_mul = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_fe_mul(out, GX, GY);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_fe_mul) best_fe_mul = per;
    }

    double best_bn_mul = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_bn_mul(T, GX, 4, GY, 4);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_bn_mul) best_bn_mul = per;
    }

    // T is fixed (GX*GY) for the reduce-only timing, matching how
    // bench_p256_reduce.c isolates it.
    p256_bn_mul(T, GX, 4, GY, 4);
    double best_reduce = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            bench_p256_reduce_entry(out, T);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_reduce) best_reduce = per;
    }

    double reduce_share_pct = best_reduce / best_fe_mul * 100.0;
    double mul_share_pct = best_bn_mul / best_fe_mul * 100.0;

    printf("{\"function\":\"p256_fe_mul\",\"runtime_ns\":%.4f,"
           "\"p256_bn_mul_ns\":%.4f,\"p256_reduce_ns\":%.4f,"
           "\"reduce_share_pct\":%.2f,\"multiply_share_pct\":%.2f}\n",
           best_fe_mul, best_bn_mul, best_reduce, reduce_share_pct,
           mul_share_pct);
    printf("RESULT_NS=%.4f\n", best_fe_mul);
    fprintf(stderr,
            "  p256_fe_mul   %8.3f ns\n"
            "  p256_bn_mul   %8.3f ns  (%.1f%% of fe_mul)\n"
            "  p256_reduce   %8.3f ns  (%.1f%% of fe_mul)\n",
            best_fe_mul, best_bn_mul, mul_share_pct, best_reduce,
            reduce_share_pct);
    return 0;
}
