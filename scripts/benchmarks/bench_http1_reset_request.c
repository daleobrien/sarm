// Benchmark for src/http1/reset_request.S -- docs/SCRIPTS.md.
//
// http1_reset_request runs once between every request on a kept-alive
// HTTP/1 connection, and it was the top sarm symbol in an HTTP/1 profile.
// It clears roughly 9.2 KB of per-request state, of which 8.2 KB is
// filename_buf and query_buf -- two 4 KB buffers that a real request fills
// a few dozen bytes of.
//
// So the case that matters is a realistic path length, and the shape of
// the answer is "how much does the cost still depend on the buffer size
// rather than on the path". A long path is measured too, to confirm the
// used-prefix scan degrades to the old behaviour rather than beating it by
// cheating.
//
// The buffers are refilled between timed iterations exactly as parse_path
// leaves them -- bytes then a NUL -- because the reset's cost is now a
// function of that content.
//
// Build and run:
//   make -C scripts/benchmarks bench_http1_reset_request
//   ./scripts/benchmarks/_bench_bin/bench_http1_reset_request

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "asm_sym.h"

#define FILENAME_BUF_SIZE 4096
#define QUERY_BUF_SIZE 4096

static inline uint8_t *filename_buf_addr(void) {
    uint8_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "filename_buf") : "=r"(p));
    return p;
}

static inline uint8_t *query_buf_addr(void) {
    uint8_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "query_buf") : "=r"(p));
    return p;
}

static inline void asm_reset_request(void) {
    asm volatile("bl http1_reset_request"
                 ::: "x0", "x1", "x2", "x3", "x4", "x9", "x29", "x30",
                     "cc", "memory");
}

static inline void asm_scrub(void) {
    asm volatile("bl http1_scrub_path_buffers"
                 ::: "x0", "x1", "x29", "x30", "cc", "memory");
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Leave the buffers the way parse_path does: `len` bytes then a NUL.
static void fill_paths(int len) {
    uint8_t *f = filename_buf_addr();
    uint8_t *q = query_buf_addr();
    memset(f, 'a', (size_t)len);
    f[len] = 0;
    memset(q, 'b', (size_t)len);
    q[len] = 0;
}

// Reported cost is one refill plus one reset, not the reset alone.
//
// The reset's cost now depends on what is in the buffer, so the buffer has
// to be put back between iterations, and the refill lands inside the timed
// loop. Subtracting a separately-timed refill was the obvious fix and the
// wrong one: the quantity being measured is a few tens of nanoseconds, so
// differencing two much larger loop timings inflated the relative noise
// past what measure_noise_floor.py will accept.
//
// Timing the pair straight through is stable, and it still compares what
// it needs to -- the refill is byte-for-byte identical work whichever
// version of the reset is linked, so a difference between two runs of this
// benchmark is entirely the reset. It just means the absolute number here
// is an upper bound on the reset's own cost rather than the cost itself.
static double bench_len(int len, int iterations) {
    double best = 1e18;
    for (int r = 0; r < 15; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++) {
            fill_paths(len);
            asm_reset_request();
        }
        uint64_t t1 = now_ns();
        double ns = (double)(t1 - t0) / (double)iterations;
        if (ns < best)
            best = ns;
    }
    return best;
}

int main(void) {
    const int iters = 400000;
    asm_scrub();

    struct { const char *name; int len; } cases[] = {
        { "path_16", 16 },
        { "path_64", 64 },
        { "path_256", 256 },
        { "path_4095", 4095 },   // fills the buffer: the old cost
    };

    printf("{\"function\":\"http1_reset_request\",\"cases\":{");
    double typical = 0.0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        double net = bench_len(cases[i].len, iters);
        if (i == 1)
            typical = net;
        printf("%s\"%s\":%.3f", i ? "," : "", cases[i].name, net);
    }
    printf("},\"runtime_ns\":%.3f}\n", typical);
    printf("RESULT_NS=%.3f\n", typical);
    return 0;
}
