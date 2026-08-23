// Benchmark for p256_ecdsa_sign_with_k (src/crypto/p256_ecdsa/sign.S:36)
// -- docs/SCRIPTS.md. Complete ECDSA sign: z = hash
// mod n, k*G, r = Rx mod n, s = k^-1*(z+r*d) mod n -- exercises
// p256_point_mul plus the scalar-field chain, so the end-to-end effect
// of prompt 04's reduction change on signing is measurable, not just
// the p256_reduce/p256_fe_mul microbenchmark effect.
//
// Links against libsarm.a (the whole src/ tree). All P-256 arithmetic
// here is integer-only; a plain `extern` C call is ABI-safe.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_ecdsa_sign_with_k
//   ./scripts/benchmarks/_bench_bin/bench_p256_ecdsa_sign_with_k

#include <stdint.h>
#include <stdio.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern int64_t p256_ecdsa_sign_with_k(uint8_t *sig_r, uint8_t *sig_s,
                                      const uint8_t *hash,
                                      const uint8_t *d, const uint8_t *k)
    __asm__("p256_ecdsa_sign_with_k");

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    static uint8_t sig_r[32], sig_s[32], hash[32], d[32], nonce[32];
    for (int i = 0; i < 32; i++) {
        hash[i] = (uint8_t)(i + 1);
        d[i] = (uint8_t)(0x40 + i);
        nonce[i] = (uint8_t)(0x80 + i);
    }
    d[0] = 0x01;
    nonce[0] = 0x01;   // keep both well inside [1, n-1]

    int64_t status = p256_ecdsa_sign_with_k(sig_r, sig_s, hash, d, nonce);
    if (status != 0) {
        fprintf(stderr,
                "p256_ecdsa_sign_with_k returned failure (%lld) on a "
                "known-good input -- the number below would not be "
                "trustworthy\n",
                (long long)status);
        return 1;
    }

    const int iterations = 300;
    double best = 1e18, worst = 0.0;
    for (int r = 0; r < 15; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_ecdsa_sign_with_k(sig_r, sig_s, hash, d, nonce);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best) best = per;
        if (per > worst) worst = per;
    }

    printf("{\"function\":\"p256_ecdsa_sign_with_k\",\"runtime_ns\":%.3f,"
           "\"spread_pct\":%.2f}\n",
           best, (worst - best) / best * 100.0);
    printf("RESULT_NS=%.3f\n", best);
    return 0;
}
