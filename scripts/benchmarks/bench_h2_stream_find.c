// Benchmark for src/h2/h2_stream_find.S -- docs/SCRIPTS.md.
//
// h2_stream_find is a linear scan of the 32-entry stream table, and on an
// h2c profile it was the single hottest function in the server. What makes
// it expensive is not the comparisons, it is the memory the comparisons
// walk: the ids it wants are one quadword each inside 32-byte entries, so
// scanning them in place strides over 16 cache lines. The packed u32 index
// beside the table (h2_stream_ids, see src/h2/data.S) holds the same 32 ids
// in 128 bytes -- two lines.
//
// So the number that matters here is the *miss*, which always walks the
// whole table, and a hit at the far end. A hit at slot 0 measures call
// overhead and nothing else; it is reported for contrast.
//
// The table is filled with odd ids the way a real connection fills it
// (client-initiated streams are odd, §5.1.1). Between timed rounds the
// caches are deliberately disturbed, otherwise 128 bytes and 1 KB both sit
// in L1 and the whole point of the change is invisible.
//
// Build and run:
//   make -C scripts/benchmarks bench_h2_stream_find
//   ./scripts/benchmarks/_bench_bin/bench_h2_stream_find

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "asm_sym.h"

#define H2_MAX_STREAMS 32
#define H2S_SIZE 32

// A plain C `extern` will not resolve against these on Mach-O, where C
// symbols are underscore-prefixed and these (defined in .S) are not.
// ASM_ADDR_ASM spells the address for whichever object format we are on.
static inline uint8_t *h2_streams_addr(void) {
    uint8_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "h2_streams") : "=r"(p));
    return p;
}

static inline uint32_t *h2_stream_ids_addr(void) {
    uint32_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "h2_stream_ids") : "=r"(p));
    return p;
}

// h2_stream_find(id=x0) -> entry pointer in x0, or 0
static inline uint64_t asm_stream_find(uint64_t id) {
    uint64_t out;
    asm volatile(
        "mov x0, %1\n"
        "bl h2_stream_find\n"
        "mov %0, x0\n"
        : "=r"(out)
        : "r"(id)
        : "x0", "x2", "x3", "x9", "x30", "cc",
          "v0","v1","v2","v3","v4","v5","v6","v7","v16", "memory");
    return out;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Something big enough to push the stream table out of L1 between rounds,
// so a scan's cache footprint actually shows up in the timing.
#define THRASH_BYTES (4u << 20)
static uint8_t thrash[THRASH_BYTES];

static void disturb_caches(void) {
    for (unsigned i = 0; i < THRASH_BYTES; i += 64)
        thrash[i] += 1;
}

// Fill the table exactly as h2_stream_create would: entry i gets id 2i+1,
// and the packed index mirrors it.
static void fill_table(void) {
    uint8_t *entries = h2_streams_addr();
    uint32_t *ids = h2_stream_ids_addr();
    memset(entries, 0, H2_MAX_STREAMS * H2S_SIZE);
    memset(ids, 0, H2_MAX_STREAMS * sizeof(uint32_t));
    for (int i = 0; i < H2_MAX_STREAMS; i++) {
        uint64_t id = (uint64_t)(2 * i + 1);
        *(uint64_t *)(entries + (size_t)i * H2S_SIZE) = id;
        ids[i] = (uint32_t)id;
    }
}

static double bench_id(uint64_t id, int iterations, int cold) {
    double best = 1e18;
    for (int r = 0; r < 7; r++) {
        if (cold)
            disturb_caches();
        uint64_t t0 = now_ns();
        uint64_t sink = 0;
        for (int i = 0; i < iterations; i++)
            sink += asm_stream_find(id);
        uint64_t t1 = now_ns();
        __asm__ volatile("" :: "r"(sink));
        double ns = (double)(t1 - t0) / (double)iterations;
        if (ns < best)
            best = ns;
    }
    return best;
}

// A lookup whose target rotates across all 32 slots. Under a client that
// keeps the table full, h2_stream_create recycles the oldest CLOSED slot,
// so a hit lands at a different depth every request rather than sitting
// at one — hit_first and hit_last are the two extremes of that, and this
// is the middle.
//
// RESULT_NS stays on `miss`, which is not laziness: of the two
// h2_stream_find calls a request still makes, the one inside
// h2_validate_stream_id is a miss every single time, because a brand-new
// stream id is by definition not in the table yet. A miss is a full
// 32-slot scan, so it is both the worst case and the common one, and the
// paired .noise.json was measured against it.
static double bench_rotating(int iterations) {
    double best = 1e18;
    for (int r = 0; r < 7; r++) {
        uint64_t t0 = now_ns();
        uint64_t sink = 0;
        for (int i = 0; i < iterations; i++)
            sink += asm_stream_find((uint64_t)(2 * (i & (H2_MAX_STREAMS - 1)) + 1));
        uint64_t t1 = now_ns();
        __asm__ volatile("" :: "r"(sink));
        double ns = (double)(t1 - t0) / (double)iterations;
        if (ns < best)
            best = ns;
    }
    return best;
}

int main(void) {
    fill_table();
    const int iters = 200000;

    double first = bench_id(1, iters, 0);                  // slot 0
    double last = bench_id(2 * H2_MAX_STREAMS - 1, iters, 0);  // slot 31
    double miss = bench_id(999999, iters, 0);              // full scan
    double miss_cold = bench_id(999999, iters / 20, 1);    // full scan, cold
    double rotating = bench_rotating(iters);               // the real shape

    printf("{\"function\":\"h2_stream_find\",\"cases\":{"
           "\"hit_first\":%.3f,\"hit_last\":%.3f,"
           "\"miss\":%.3f,\"miss_cold\":%.3f,\"rotating\":%.3f},"
           "\"runtime_ns\":%.3f}\n",
           first, last, miss, miss_cold, rotating, miss);
    printf("RESULT_NS=%.3f\n", miss);
    return 0;
}
