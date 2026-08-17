// Benchmark for p256_point_mul (src/crypto/p256_point/mul.S:26) --
// prompts/02-benchmark-substrate.md. Reports two numbers:
//
//   - "generator": k*G against the fixed basepoint, the operation
//     ECDSA signing and key generation use.
//   - "ecdh": a full two-party ECDH exchange -- dA*G, dB*G, then
//     dA*(dB*G) and dB*(dA*G) -- so the *second* scalar multiplication
//     (against a peer's point, not the fixed generator) is measured
//     too. That second call is what a real P-256 handshake actually
//     pays beyond signing: shared-secret derivation against whatever
//     point the peer sent. Correctness is the ECDH property itself:
//     both parties must derive the same shared x-coordinate.
//
// This is the practical scope for "complete P-256 handshake operations"
// this file covers: real leaf-operation cost for both key-generation-
// shaped and shared-secret-shaped scalar multiplication, without
// standing up a new end-to-end TLS harness (tests/test_protocols.sh and
// tests/h2_browser_sim.py already exercise real handshakes end-to-end;
// this is the microbenchmark half prompt 04 needs to isolate
// p256_point_mul's own contribution).
//
// Links against libsarm.a (the whole src/ tree, built once by this
// Makefile's existing bench_primitives rule) since point_mul reaches the
// full P-256 field/point/scalar chain. All P-256 arithmetic here is
// integer-only; a plain `extern` C call is ABI-safe.
//
// Build and run:
//   make -C scripts/benchmarks bench_p256_point_mul
//   ./scripts/benchmarks/_bench_bin/bench_p256_point_mul

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// sarm's assembly labels carry no leading underscore, unlike the
// default Darwin C-symbol mangling; __asm__("name") pins the literal
// linker name (bench_primitives.c's ASM_SYM pattern).
extern void p256_point_mul(uint64_t *outx, uint64_t *outy,
                           const uint64_t *k, const uint64_t *inx,
                           const uint64_t *iny)
    __asm__("p256_point_mul");

static const uint64_t GX[4] = {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
                               0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};
static const uint64_t GY[4] = {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
                               0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL};
// Two representative "private scalars", well inside [1, n-1].
static const uint64_t DA[4] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL,
                               0x0f1e2d3c4b5a6978ULL, 0x1122334455667788ULL};
static const uint64_t DB[4] = {0x9988776655443322ULL, 0x1100ffeeddccbbaaULL,
                               0x5566778899aabbccULL, 0x0102030405060708ULL};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    uint64_t outx[4], outy[4];

    // Sanity: k*G must be a nonzero point.
    p256_point_mul(outx, outy, DA, GX, GY);
    if ((outx[0] | outx[1] | outx[2] | outx[3]) == 0) {
        fprintf(stderr,
                "p256_point_mul(DA, G) produced the identity -- the "
                "numbers below would not be trustworthy\n");
        return 1;
    }

    // Correctness: the ECDH property. dA*(dB*G) == dB*(dA*G).
    uint64_t pubA_x[4], pubA_y[4], pubB_x[4], pubB_y[4];
    uint64_t ssA_x[4], ssA_y[4], ssB_x[4], ssB_y[4];
    p256_point_mul(pubA_x, pubA_y, DA, GX, GY);
    p256_point_mul(pubB_x, pubB_y, DB, GX, GY);
    p256_point_mul(ssA_x, ssA_y, DA, pubB_x, pubB_y);
    p256_point_mul(ssB_x, ssB_y, DB, pubA_x, pubA_y);
    if (memcmp(ssA_x, ssB_x, sizeof ssA_x) != 0) {
        fprintf(stderr,
                "ECDH shared secrets disagree -- the numbers below "
                "would not be trustworthy\n");
        return 1;
    }

    const int iterations = 400;

    double best_gen = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_point_mul(outx, outy, DA, GX, GY);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_gen) best_gen = per;
    }

    double best_ecdh = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            p256_point_mul(ssA_x, ssA_y, DA, pubB_x, pubB_y);
        uint64_t t1 = now_ns();
        double per = (double)(t1 - t0) / (double)iterations;
        if (per < best_ecdh) best_ecdh = per;
    }

    printf("{\"function\":\"p256_point_mul\",\"runtime_ns\":%.3f,"
           "\"cases\":{\"generator\":%.3f,\"ecdh\":%.3f}}\n",
           best_gen, best_gen, best_ecdh);
    printf("RESULT_NS=%.3f\n", best_gen);
    return 0;
}
