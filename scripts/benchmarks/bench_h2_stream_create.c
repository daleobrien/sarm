// Benchmark for src/h2/h2_stream_create.S -- docs/SCRIPTS.md.
//
// h2_stream_create runs once per HTTP/2 request, and on the Graviton
// profile of 2026-08-26 it was the hottest function in the whole server
// (5.93% of cycles on h2c, 4.21% on h2+TLS -- see
// perf-results/ec2-20260826-203401/profile_h2c.txt). Almost none of that
// was the id lookup. It was the two table walks around it: one over
// h2_stream_ids looking for a free slot, and -- once the table filled --
// a second over h2_streams itself, reading H2S_STATE and H2S_STREAM_ID at
// a 32-byte stride to pick the oldest CLOSED entry to recycle.
//
// THE FULL-TABLE CASE IS THE ONE THAT MATTERS, and it is easy to
// under-weight. A client that asks for our full MAX_CONCURRENT_STREAMS
// quota keeps all 32 slots occupied, so the table is full from the 33rd
// request onwards and the recycle path runs on EVERY request after that,
// for the life of the connection. The "free slot" case below is the first
// 32 requests of a connection and essentially nothing else.
//
// The three cases:
//   * free      -- a table with room. Measures the id scan plus the
//                  free-slot lookup.
// recycle_eight is the headline number (RESULT_NS), not `recycle`: the
// recycle pass now costs one iteration per CANDIDATE where it used to cost
// one per ENTRY, so an all-CLOSED table is the single shape where the two
// do the same amount of work, and quoting it would understate the change
// everywhere else while being the noisiest case to measure.
//
//   * recycle   -- a full table, every entry CLOSED. The steady state
//                  under a multiplexing client, and the case the slot
//                  bitmaps were added for: it used to touch all 16 cache
//                  lines of h2_streams, and now touches none of them.
//   * recycle_1 -- a full table with exactly ONE CLOSED entry, at the far
//                  end. The old code walked all 32 entries to find it
//                  either way; the bitmap path visits one candidate. This
//                  is the widest the gap gets.
//   * hit       -- an existing id, matched at the far end of the scan.
//                  Unchanged by the bitmaps; reported so a regression in
//                  the surviving loop is visible.
//
// Caches are deliberately disturbed between timed rounds: 1 KB of table
// and 128 bytes of index both sit in L1 otherwise, and the whole point of
// not walking the entries is invisible when walking them is free.
//
// Build and run:
//   make -C scripts/benchmarks bench_h2_stream_create
//   ./scripts/benchmarks/_bench_bin/bench_h2_stream_create

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "asm_sym.h"

#define H2_MAX_STREAMS 32
#define H2S_SIZE 32
#define H2S_STREAM_ID 0
#define H2S_STATE 8
#define H2_STREAM_IDLE 0
#define H2_STREAM_OPEN 1
#define H2_STREAM_CLOSED 4

// The connection struct h2_stream_create reads SETTINGS_INITIAL_WINDOW_SIZE
// out of and writes LAST_STREAM_ID back into. Only those two fields are
// touched, but the offsets have to match defs.S -- see H2C_* there.
#define H2C_SETTINGS_INITIAL_WINDOW_SIZE 40
#define H2C_LAST_STREAM_ID 72
#define H2C_BYTES 128

// A plain C `extern` will not resolve against these on Mach-O, where C
// symbols are underscore-prefixed and these (defined in .S) are not.
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

static inline uint64_t *h2_stream_used_addr(void) {
    uint64_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "h2_stream_used") : "=r"(p));
    return p;
}

static inline uint64_t *h2_stream_closed_addr(void) {
    uint64_t *p;
    asm volatile(ASM_ADDR_ASM("%0", "h2_stream_closed") : "=r"(p));
    return p;
}

// h2_stream_create(id=x0, conn=x1) -> entry pointer in x0
static inline uint64_t asm_stream_create(uint64_t id, void *conn) {
    uint64_t out;
    asm volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl h2_stream_create\n"
        "mov %0, x0\n"
        : "=r"(out)
        : "r"(id), "r"(conn)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x30", "cc",
          "v0","v1","v2","v3","v4","v5","v6","v7","v16", "memory");
    return out;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#define THRASH_BYTES (4u << 20)
static uint8_t thrash[THRASH_BYTES];

static void disturb_caches(void) {
    for (unsigned i = 0; i < THRASH_BYTES; i += 64)
        thrash[i] += 1;
}

static uint8_t conn[H2C_BYTES];

// Put the table into a known shape: `fill` entries occupied with ids
// 1, 3, 5, ..., of which the ones selected by `closed_mask` are CLOSED
// and the rest are OPEN. The bitmaps are written directly rather than
// through the server's writers -- this is the state those writers would
// have left, and building it by driving the real state machine would put
// h2_stream_event in the measurement.
static void shape_table(int fill, uint64_t closed_mask) {
    uint8_t *entries = h2_streams_addr();
    uint32_t *ids = h2_stream_ids_addr();
    memset(entries, 0, (size_t)H2_MAX_STREAMS * H2S_SIZE);
    memset(ids, 0, H2_MAX_STREAMS * sizeof(uint32_t));
    uint64_t used = 0, closed = 0;

    for (int i = 0; i < fill; i++) {
        uint64_t id = (uint64_t)(2 * i + 1);
        uint8_t *e = entries + (size_t)i * H2S_SIZE;
        *(uint64_t *)(e + H2S_STREAM_ID) = id;
        *(uint64_t *)(e + H2S_STATE) =
            (closed_mask >> i) & 1 ? H2_STREAM_CLOSED : H2_STREAM_OPEN;
        ids[i] = (uint32_t)id;
        used |= 1ULL << i;
        if ((closed_mask >> i) & 1)
            closed |= 1ULL << i;
    }
    *h2_stream_used_addr() = used;
    *h2_stream_closed_addr() = closed;
}

// THE MEASUREMENT PROBLEM, and how the loops below solve it. Creating a
// stream MUTATES the table, so a naive loop measures a different table
// every iteration and drifts off the case it meant to measure. Reshaping
// between calls fixes that but costs two memsets and a 32-entry loop --
// well over a hundred nanoseconds against the ~9-30 ns being measured.
//
// Instead each loop UNDOES exactly what its call did, in two or three
// stores, and that fixup is left INSIDE the timed region rather than
// subtracted as a control. Subtracting one was the first attempt and it
// was worse: it put a second timing's variance into every answer and the
// control could not walk the same slots in the same order as the real
// loop, which pushed the measured noise floor to 9% -- four times what
// bench_h2_stream_find gets out of the same table on the same machine.
// The fixup is a handful of stores, identical on both sides of any
// comparison, so carrying it is a constant offset rather than a bias.
// READ THE CASES AGAINST EACH OTHER, not as absolute costs.
//
// The fixups touch the bitmaps as well as the entries, so the state stays
// self-consistent for the bitmap build and is simply ignored by the
// pre-bitmap one -- the same source file measures both.
static inline int slot_of(uint64_t entry) {
    return (int)((entry - (uint64_t)(uintptr_t)h2_streams_addr()) / H2S_SIZE);
}

// Re-close the entry a recycling create just handed back, returning the
// table to "full, and every slot a candidate" for the next iteration.
static inline void reclose(uint64_t entry) {
    *(uint64_t *)(uintptr_t)(entry + H2S_STATE) = H2_STREAM_CLOSED;
    *h2_stream_closed_addr() |= 1ULL << slot_of(entry);
}

// Empty the slot a create just filled, returning the table to "one free
// slot at the end".
static inline void unfill(uint64_t entry) {
    int i = slot_of(entry);
    *(uint64_t *)(uintptr_t)(entry + H2S_STREAM_ID) = 0;
    *(uint64_t *)(uintptr_t)(entry + H2S_STATE) = H2_STREAM_IDLE;
    h2_stream_ids_addr()[i] = 0;
    *h2_stream_used_addr() &= ~(1ULL << i);
    *h2_stream_closed_addr() &= ~(1ULL << i);
}

#define ROUNDS 15

enum fixup { FIX_RECLOSE, FIX_UNFILL, FIX_NONE };

// `id_base` is incremented per call so recycling sees the monotonically
// increasing ids a real connection produces -- the CLOSED-LRU choice is a
// minimum over ids, so feeding it one repeated id would measure a
// degenerate case.
static double bench_case(int fill, uint64_t closed_mask, uint64_t id_base,
                         int fixed_id, enum fixup fx, int iterations,
                         int cold) {
    double best = 1e18;
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t sink = 0;
        shape_table(fill, closed_mask);
        if (cold)
            disturb_caches();

        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++) {
            uint64_t e = asm_stream_create(
                fixed_id ? id_base : id_base + (uint64_t)(2 * i), conn);
            if (fx == FIX_RECLOSE)
                reclose(e);
            else if (fx == FIX_UNFILL)
                unfill(e);
            sink += e;
        }
        uint64_t t1 = now_ns();
        __asm__ volatile("" ::"r"(sink));

        double ns = (double)(t1 - t0) / (double)iterations;
        if (ns > 0.0 && ns < best)
            best = ns;
    }
    return best;
}

// THE BRANCH-PATTERN PROBLEM the cases above have, and what this one
// fixes. bench_case replays ONE closed_mask for a whole round: the same
// candidates, in the same order, with the same ids, several hundred
// thousand times. The recycle pass is a loop whose trip count is the
// popcount of that mask and whose compare-and-branch follows the order of
// those ids, so after a handful of iterations the predictor has learned
// both exactly and neither costs anything again.
//
// That makes every number above a measurement of the WORK, with the
// mispredicts subtracted out -- and on the 2026-08-27 Graviton profile
// the mispredicts were the story: 20.5% of h2_stream_create sat on one
// branch in that loop and 7.0% on the other, because a real connection
// closes and reopens streams continuously and the mask changes shape from
// one request to the next. So the fixed-mask cases systematically
// understate what removing a branch is worth, and overstate what adding a
// data dependency (a csel, say) costs.
//
// This case rotates the shape instead: a ring of masks with differing
// popcounts, and the ids permuted so the running minimum arrives at a
// different point in the walk each time. Re-planting a whole table per
// iteration would swamp the ~7-25 ns being measured, so the ring is
// pre-built and each iteration installs one with two stores -- the same
// trick, and the same reasoning, as the fixups above: a constant offset
// carried identically by anything being compared. READ IT AGAINST
// ITSELF ACROSS BUILDS, never as an absolute cost.
#define RING 64
static uint64_t ring_closed[RING];
static uint32_t ring_ids[RING][H2_MAX_STREAMS];

static void build_ring(void) {
    uint64_t rng = 0x9e3779b97f4a7c15ULL;
    for (int r = 0; r < RING; r++) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        // Popcounts spread over the range a real connection produces,
        // never empty -- an empty mask is the refuse path, not this one.
        uint64_t m = (uint64_t)(uint32_t)(rng >> 32);
        int want = 1 + (r % 24);
        while (__builtin_popcountll(m) > want) m &= m - 1;
        if (!m) m = 1;
        ring_closed[r] = m;
        for (int i = 0; i < H2_MAX_STREAMS; i++)
            ring_ids[r][i] = (uint32_t)(2 * i + 1);
        for (int i = H2_MAX_STREAMS - 1; i > 0; i--) {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            int j = (int)((rng >> 32) % (unsigned)(i + 1));
            uint32_t t = ring_ids[r][i];
            ring_ids[r][i] = ring_ids[r][j];
            ring_ids[r][j] = t;
        }
    }
}

static double bench_varying(int iterations) {
    uint32_t *ids = h2_stream_ids_addr();
    double best = 1e18;
    for (int r = 0; r < ROUNDS; r++) {
        shape_table(H2_MAX_STREAMS, 0);
        uint64_t sink = 0;
        uint64_t t0 = now_ns();
        for (int i = 0; i < iterations; i++) {
            int k = i & (RING - 1);
            memcpy(ids, ring_ids[k], H2_MAX_STREAMS * sizeof(uint32_t));
            *h2_stream_closed_addr() = ring_closed[k];
            *h2_stream_used_addr() = (H2_MAX_STREAMS == 64)
                                         ? ~0ULL
                                         : ((1ULL << H2_MAX_STREAMS) - 1);
            sink += asm_stream_create(100001, conn);
        }
        uint64_t t1 = now_ns();
        __asm__ volatile("" ::"r"(sink));
        double ns = (double)(t1 - t0) / (double)iterations;
        if (ns > 0.0 && ns < best)
            best = ns;
    }
    return best;
}

int main(void) {
    memset(conn, 0, sizeof conn);
    *(uint64_t *)(conn + H2C_SETTINGS_INITIAL_WINDOW_SIZE) = 65535;

    const int iters = 500000;
    const uint64_t all = (H2_MAX_STREAMS == 64)
                             ? ~0ULL
                             : ((1ULL << H2_MAX_STREAMS) - 1);
    const uint64_t last_only = 1ULL << (H2_MAX_STREAMS - 1);
    // Comfortably above every id shape_table plants (2*32-1 = 63), so a
    // create is always a new stream and always the largest id so far.
    const uint64_t fresh = 100001;

    // one free slot at the end: the id scan plus the free-slot lookup
    double freeslot = bench_case(H2_MAX_STREAMS - 1, 0, fresh, 0,
                                 FIX_UNFILL, iters, 0);
    // full table, every entry CLOSED: recycle with 32 candidates
    double recycle = bench_case(H2_MAX_STREAMS, all, fresh, 0,
                                FIX_RECLOSE, iters, 0);
    // full table, one CLOSED entry at the far end: recycle with 1 candidate
    double recycle1 = bench_case(H2_MAX_STREAMS, last_only, fresh, 0,
                                 FIX_RECLOSE, iters, 0);
    // full table, a quarter of it CLOSED -- the density question. The
    // recycle pass costs one iteration per CANDIDATE now and one per
    // ENTRY before, so the two meet somewhere between here and `recycle`;
    // which side of that line a real connection sits on is what decides
    // whether this change is worth anything end to end.
    double recycle8 = bench_case(H2_MAX_STREAMS, 0xff000000ULL, fresh, 0,
                                 FIX_RECLOSE, iters, 0);
    // an existing id at the last slot: the surviving scan, no mutation
    double hit = bench_case(H2_MAX_STREAMS, 0,
                            (uint64_t)(2 * H2_MAX_STREAMS - 1), 1,
                            FIX_NONE, iters, 0);
    // the recycle case again, with the caches disturbed first
    double recycle_cold = bench_case(H2_MAX_STREAMS, all, fresh, 0,
                                     FIX_RECLOSE, iters / 20, 1);
    // the recycle pass with a shape the predictor cannot learn
    build_ring();
    double varying = bench_varying(iters);

    printf("{\"function\":\"h2_stream_create\",\"cases\":{"
           "\"free_slot\":%.3f,\"recycle\":%.3f,\"recycle_eight\":%.3f,"
           "\"recycle_one\":%.3f,\"hit_last\":%.3f,\"recycle_cold\":%.3f,"
           "\"recycle_varying\":%.3f},"
           "\"runtime_ns\":%.3f}\n",
           freeslot, recycle, recycle8, recycle1, hit, recycle_cold,
           varying, recycle8);
    printf("RESULT_NS=%.3f\n", recycle8);
    return 0;
}
