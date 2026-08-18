// Benchmark for src/file/lookup_embedded.S -- prompts/10-embedded-lookup.md.
//
// Measures the cleaned-up linear scan against the real six-entry asset
// table (src/embedded.S, built by embed_www.sh) with representative
// request paths: a hit at every table position (cost grows with scan
// depth) plus a realistic miss (full scan, no match). Prints
// machine-readable JSON matching bench_memcpy.c's protocol.
//
// Build and run:
//   make -C scripts/benchmarks bench_lookup_embedded
//   ./scripts/benchmarks/_bench_bin/bench_lookup_embedded

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// lookup_embedded(path=x0, len=x1) ->
//   (content_ptr=x0, content_size=x1, ct_ptr=x2, ct_len=x3, gzip=x4,
//    etag_ptr=x5, etag_len=x6, carry: 1 = not found, 0 = found)
static inline int64_t asm_lookup_embedded(const char *path, int64_t len) {
    int64_t carry;
    asm volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl lookup_embedded\n"
        "cset %0, cs\n"
        : "=r"(carry)
        : "r"(path), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x9", "x10",
          "x19", "x20", "x22", "x23", "memory");
    return carry;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double bench_path(const char *path, int iterations) {
    int64_t len = (int64_t)strlen(path);
    double best = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++)
            asm_lookup_embedded(path, len);
        uint64_t t1 = now_ns();
        double per_op = (double)(t1 - t0) / (double)iterations;
        if (per_op < best)
            best = per_op;
    }
    return best;
}

int main(void) {
    // Real asset paths, in table order (position 0..5), plus a realistic
    // miss (full scan, never matches).
    static const char *paths[] = {
        "www/assets/index-Q2Xld2VX.js",   // position 0
        "www/assets/index-pzx_VsSR.css",  // position 1
        "www/favicon.svg",                // position 2
        "www/index.html",                 // position 3
        "www/logo.png",                   // position 4
        "www/manifest.json",              // position 5
        "www/does-not-exist.html",        // miss: full scan
    };
    static const char *labels[] = {
        "hit_pos0", "hit_pos1", "hit_pos2", "hit_pos3", "hit_pos4",
        "hit_pos5", "miss",
    };
    const int n = (int)(sizeof(paths) / sizeof(paths[0]));
    const int iterations = 2000000;

    // Sanity: position-3 hit (index.html) must actually be found.
    if (asm_lookup_embedded(paths[3], (int64_t)strlen(paths[3])) != 0) {
        fprintf(stderr, "sanity lookup failed -- run embed_www.sh first\n");
        return 1;
    }

    double sum = 0.0;
    printf("{\"function\":\"lookup_embedded\",\"sizes\":{");
    for (int i = 0; i < n; i++) {
        double per = bench_path(paths[i], iterations);
        sum += per;
        if (i)
            printf(",");
        printf("\"%s\":%.3f", labels[i], per);
    }
    double runtime_ns = sum / (double)n;
    printf("},\"runtime_ns\":%.3f}\n", runtime_ns);
    printf("RESULT_NS=%.3f\n", runtime_ns);
    return 0;
}
