// Isolated benchmark for p256_reduce (src/crypto/p256/sqr_mul.S:37),
// the prompt 04 target -- prompts/02-benchmark-substrate.md.
//
// p256_reduce has no `.global` (see p256_reduce_probe.S for why that
// matters and how this driver reaches it anyway, through
// bench_p256_reduce_entry). All P-256 field arithmetic here is
// integer-only (ADDS/ADCS/MUL/UMULH; no NEON), so unlike the AES/GCM
// benchmarks a plain `extern` C call is ABI-safe -- no v8-v15 hazard to
// route around with an inline-asm trampoline.
//
// Correctness: p256_reduce's job is "reduce an 8-limb product mod p".
// Rather than reimplement Barrett (or whatever prompt 04 replaces it
// with) as an oracle, this cross-checks against the real, independently
// callable p256_fe_mul, which does exactly "p256_bn_mul then
// p256_reduce" internally (sqr_mul.S:198-207): computing the same
// 8-limb product via the real p256_bn_mul and reducing it through this
// probe must equal calling the real p256_fe_mul directly. A mismatch
// means either this probe's entry conditions are wrong or p256_reduce
// itself is broken -- either way, not safe to trust the timing.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_reduce
//   ./scripts/benchmarks/_bench_bin/bench_p256_reduce

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_bn_mul(uint64_t *out, const uint64_t *a, int64_t na,
                        const uint64_t *b, int64_t nb)
    __asm__("p256_bn_mul");
extern void bench_p256_reduce_entry(uint64_t *out, const uint64_t *T)
    __asm__("bench_p256_reduce_entry");
extern void p256_fe_mul(uint64_t *out, const uint64_t *a, const uint64_t *b)
    __asm__("p256_fe_mul");

// P-256 base point, little-endian 4-limb form (bench_primitives.c).
static const uint64_t GX[4] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};
static const uint64_t GY[4] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int check_case(const uint64_t *a, const uint64_t *b) {
    uint64_t T[8], via_probe[4], via_real[4];
    p256_bn_mul(T, a, 4, b, 4);
    bench_p256_reduce_entry(via_probe, T);
    p256_fe_mul(via_real, a, b);
    return memcmp(via_probe, via_real, sizeof via_probe) == 0;
}

int main(void) {
    // GX*GX and GX*GY: two representative field-element products (this
    // repo's own basepoint), plus 0*0 as a degenerate edge case.
    static const uint64_t zero[4] = {0, 0, 0, 0};
    if (!check_case(GX, GX) || !check_case(GX, GY) || !check_case(zero, zero)) {
        fprintf(stderr,
                "p256_reduce probe disagrees with the real p256_fe_mul -- "
                "the number below would not be trustworthy\n");
        return 1;
    }

    uint64_t T[8], out[4];
    p256_bn_mul(T, GX, 4, GY, 4);

    // Warm up.
    bench_p256_reduce_entry(out, T);

    const int iterations = 3000000;
    double best = 1e18, worst = 0.0;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            bench_p256_reduce_entry(out, T);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best) best = per;
        if (per > worst) worst = per;
    }

    printf("{\"function\":\"p256_reduce\",\"runtime_ns\":%.4f,"
           "\"spread_pct\":%.2f}\n",
           best, (worst - best) / best * 100.0);
    printf("RESULT_NS=%.4f\n", best);
    return 0;
}
