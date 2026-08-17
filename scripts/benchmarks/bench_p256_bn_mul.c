// Isolated, per-call benchmark for p256_bn_mul
// (src/crypto/p256/bn_mul.S:38) -- prompts/02-benchmark-substrate.md.
// Not a register-optimization target itself (it is a hot leaf with no
// frame -- see prompt 05); this exists to let bench_p256_fe_mul.c and
// bench_p256_reduce.c isolate multiplication cost from reduction cost.
// Reports the 4x4 shape p256_fe_mul actually uses as the primary number,
// plus the 5x5/5x4 shapes p256_reduce's Barrett implementation uses
// internally today, for completeness.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_bn_mul
//   ./scripts/benchmarks/_bench_bin/bench_p256_bn_mul

#include <stdint.h>
#include <stdio.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_bn_mul(uint64_t *out, const uint64_t *a, int64_t na,
                        const uint64_t *b, int64_t nb)
    __asm__("p256_bn_mul");

static const uint64_t GX[5] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL,
                               0x1122334455667788ULL};
static const uint64_t GY[5] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL,
                               0x99aabbccddeeff00ULL};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double bench_shape(int64_t na, int64_t nb, int iterations) {
    uint64_t out[10];
    double best = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_bn_mul(out, GX, na, GY, nb);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best) best = per;
    }
    return best;
}

int main(void) {
    // Sanity: a nonzero product for a nonzero input.
    uint64_t out[8];
    p256_bn_mul(out, GX, 4, GY, 4);
    if (out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 0) {
        fprintf(stderr,
                "p256_bn_mul produced an all-zero product for nonzero "
                "inputs -- the number below would not be trustworthy\n");
        return 1;
    }

    double ns_4x4 = bench_shape(4, 4, 4000000);
    double ns_5x5 = bench_shape(5, 5, 3000000);
    double ns_5x4 = bench_shape(5, 4, 3000000);

    printf("{\"function\":\"p256_bn_mul\",\"runtime_ns\":%.4f,"
           "\"shapes\":{\"4x4\":%.4f,\"5x5\":%.4f,\"5x4\":%.4f}}\n",
           ns_4x4, ns_4x4, ns_5x5, ns_5x4);
    printf("RESULT_NS=%.4f\n", ns_4x4);
    return 0;
}
