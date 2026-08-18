// Benchmark for p256_scalar_inv (src/crypto/p256_scalar/inv.S), the
// Fermat inversion mod n that an ECDSA signature spends on k^-1.
//
// Reports three numbers so a change to either half of the cost is
// visible separately: the inversion itself, the Montgomery multiply it
// is now built from (src/crypto/p256_scalar/mont_mul.S), and the
// Barrett p256_scalar_mul it used to be built from. inv/mont_mul is
// the chain length actually being paid for, which should track the 300
// modular multiplications the chain schedules; mont_mul vs scalar_mul
// is the per-multiply win on its own.
//
// Correctness is checked before anything is timed, and through code the
// measurement does not share: a * a^-1 must be 1 mod n as computed by
// p256_scalar_mul, which is Barrett and has no Montgomery step. A
// timing number from a broken inversion would be meaningless, and an
// inversion is exactly the kind of routine that can be fast and wrong.
//
// Links against libsarm.a because inversion reaches p256_scalar_reduce
// and the generated chain/constants as well. All arithmetic is
// integer-only, so a plain `extern` C call is ABI-safe.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_scalar_inv
//   ./scripts/benchmarks/_bench_bin/bench_p256_scalar_inv

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_scalar_inv(uint64_t *out, const uint64_t *a)
    __asm__("p256_scalar_inv");
extern void p256_scalar_mul(uint64_t *out, const uint64_t *a, const uint64_t *b)
    __asm__("p256_scalar_mul");
extern void p256_scalar_mont_mul(uint64_t *out, const uint64_t *a,
                                 const uint64_t *b)
    __asm__("p256_scalar_mont_mul");

// A representative nonce, well inside [1, n-1].
static const uint64_t K[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL,
                              0x0f1e2d3c4b5a6978ULL, 0x1122334455667788ULL};
static const uint64_t B[4] = {0x1111111111111111ULL, 0x2222222222222222ULL,
                              0x3333333333333333ULL, 0x0444444444444444ULL};

// Inputs checked for a * a^-1 == 1 before timing. Ordinary, tiny, n-1,
// and 2^256-1 -- the last is above n and unreduced, which is what
// p256_ecdsa_sign_with_k actually passes, since it feeds the nonce
// straight from p256_fe_frombytes without reducing mod n.
static const uint64_t CHECK[][4] = {
    {0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x0f1e2d3c4b5a6978ULL,
     0x1122334455667788ULL},
    {1, 0, 0, 0},
    {2, 0, 0, 0},
    {0xdeadbeefULL, 0, 0, 0},
    // n - 1
    {0xf3b9cac2fc632550ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
     0xffffffff00000000ULL},
    // 2^256 - 1
    {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
     0xffffffffffffffffULL},
};
#define NCHECK ((int)(sizeof CHECK / sizeof CHECK[0]))

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    uint64_t out[4], t[4];

    for (int i = 0; i < NCHECK; i++) {
        p256_scalar_inv(out, CHECK[i]);
        p256_scalar_mul(t, CHECK[i], out);
        if (t[0] != 1 || t[1] != 0 || t[2] != 0 || t[3] != 0) {
            fprintf(stderr,
                    "a * a^-1 != 1 for input %d -- the numbers below would "
                    "not be trustworthy\n", i);
            return 1;
        }
    }

    // Warm up: the first inversion after load pays for the page-ins of
    // the chain table and of mont_mul itself, which is a real cost but
    // not the steady-state one this measures.
    for (int i = 0; i < 20; i++) p256_scalar_inv(out, K);

    double best_inv = 1e18;
    for (int r = 0; r < 7; r++) {
        const int n = 400;
        uint64_t t0 = now_ns();
        for (int i = 0; i < n; i++) p256_scalar_inv(out, K);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / n;
        if (per < best_inv) best_inv = per;
    }

    double best_mont = 1e18;
    for (int r = 0; r < 7; r++) {
        const int n = 20000;
        uint64_t t0 = now_ns();
        for (int i = 0; i < n; i++) p256_scalar_mont_mul(out, K, B);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / n;
        if (per < best_mont) best_mont = per;
    }

    double best_barrett = 1e18;
    for (int r = 0; r < 7; r++) {
        const int n = 20000;
        uint64_t t0 = now_ns();
        for (int i = 0; i < n; i++) p256_scalar_mul(out, K, B);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / n;
        if (per < best_barrett) best_barrett = per;
    }

    printf("{\"function\":\"p256_scalar_inv\",\"runtime_ns\":%.3f,"
           "\"cases\":{\"inv\":%.3f,\"mont_mul\":%.3f,\"barrett_mul\":%.3f,"
           "\"mults_per_inv\":%.1f,\"mont_speedup\":%.3f}}\n",
           best_inv, best_inv, best_mont, best_barrett,
           best_inv / best_mont, best_barrett / best_mont);
    printf("RESULT_NS=%.3f\n", best_inv);
    return 0;
}
