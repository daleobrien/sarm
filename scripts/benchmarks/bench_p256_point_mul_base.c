// Benchmark for p256_point_mul_base (src/crypto/p256_point/mul_base.S),
// the 4-bit fixed-base comb, against the generic double-and-add
// p256_point_mul (src/crypto/p256_point/mul.S) it replaces on the k*G
// path. Reports both so the speedup is one subtraction away, and so a
// regression in either shows up in the same run.
//
// Correctness is checked before anything is timed, and it is checked
// the only way that matters here: the comb and the generic routine must
// agree bit-for-bit on every scalar measured, including the ones with
// many zero nibbles (which exercise the comb's infinity masking) and a
// scalar above n (which is what p256_ecdsa_sign_with_k actually passes,
// since it feeds the nonce straight from p256_fe_frombytes without
// reducing mod n).
//
// Links against libsarm.a for the same reason bench_p256_point_mul
// does: scalar multiplication reaches the whole P-256 field/point
// chain. All arithmetic is integer-only, so a plain `extern` C call is
// ABI-safe.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_point_mul_base
//   ./scripts/benchmarks/_bench_bin/bench_p256_point_mul_base

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_point_mul_base(uint64_t *outx, uint64_t *outy,
                                const uint64_t *k)
    __asm__("p256_point_mul_base");
extern void p256_point_mul(uint64_t *outx, uint64_t *outy,
                           const uint64_t *k, const uint64_t *inx,
                           const uint64_t *iny)
    __asm__("p256_point_mul");

static const uint64_t GX[4] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};
static const uint64_t GY[4] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL};

// The scalar the timing loop uses -- a representative private key, well
// inside [1, n-1]. Same value bench_p256_point_mul times, so the two
// benchmarks' "generator" numbers are directly comparable.
static const uint64_t DA[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL,
                               0x0f1e2d3c4b5a6978ULL, 0x1122334455667788ULL};

// Scalars checked for agreement before timing. Ordinary, tiny (leading
// zero nibbles -> the infinity-masking path), sparse-nibble, and one
// above n.
static const uint64_t CHECK_K[][4] = {
    {0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x0f1e2d3c4b5a6978ULL,
     0x1122334455667788ULL},
    {0x0000000000000001ULL, 0, 0, 0},
    {0x000000000000000fULL, 0, 0, 0},
    {0x0000000000000010ULL, 0, 0, 0},
    {0xdeadbeefULL, 0, 0, 0},
    {0x0f0f0f0f0f0f0f0fULL, 0x0f0f0f0f0f0f0f0fULL, 0x0f0f0f0f0f0f0f0fULL,
     0x0f0f0f0f0f0f0f0fULL},
    // n - 1
    {0xf3b9cac2fc632550ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
     0xffffffff00000000ULL},
    // 2^256 - 1: above n, unreduced, which signing does pass through
    {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
     0xffffffffffffffffULL},
};
#define NCHECK ((int)(sizeof CHECK_K / sizeof CHECK_K[0]))

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    uint64_t bx[4], by[4], gx[4], gy[4];

    for (int i = 0; i < NCHECK; i++) {
        p256_point_mul_base(bx, by, CHECK_K[i]);
        p256_point_mul(gx, gy, CHECK_K[i], GX, GY);
        if (memcmp(bx, gx, sizeof bx) != 0 || memcmp(by, gy, sizeof by) != 0) {
            fprintf(stderr,
                    "comb and double-and-add disagree on scalar %d -- the "
                    "numbers below would not be trustworthy\n", i);
            return 1;
        }
    }

    p256_point_mul_base(bx, by, DA);
    if ((bx[0] | bx[1] | bx[2] | bx[3]) == 0) {
        fprintf(stderr,
                "p256_point_mul_base(DA) produced the identity -- the "
                "numbers below would not be trustworthy\n");
        return 1;
    }

    const int iterations = 400;

    double best_comb = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_point_mul_base(bx, by, DA);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_comb) best_comb = per;
    }

    double best_generic = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_point_mul(gx, gy, DA, GX, GY);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_generic) best_generic = per;
    }

    printf("{\"function\":\"p256_point_mul_base\",\"runtime_ns\":%.3f,"
           "\"cases\":{\"comb\":%.3f,\"double_and_add\":%.3f,"
           "\"speedup\":%.3f}}\n",
           best_comb, best_comb, best_generic, best_generic / best_comb);
    printf("RESULT_NS=%.3f\n", best_comb);
    return 0;
}
