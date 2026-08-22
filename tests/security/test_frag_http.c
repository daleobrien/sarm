// sarm security tests — fragmentation of the plaintext read loop (Step 9)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_frag_http.c
//
// Description: The HTTP/1 side of the server has no socket routine of
//   its own to fragment. `src/sarm/child.S` reads with `read()`
//   straight into `buf`, appending to whatever is already there, and
//   after every read runs the same two scans over the whole buffer
//   again:
//
//       h2_probe(buf, n)          — is this an HTTP/2 preface?
//       parse_header_end(buf, n)  — is the request header complete?
//
//   So the fragmentation question for this path is not "does the
//   reader wait for the rest" — the loop is what waits. It is whether
//   *the answer depends on where the reads happened to land*, and that
//   makes it a property of the two scans over every prefix of the same
//   bytes:
//
//     header_end   the first "\r\n\r\n" must be found at exactly the
//                  same index no matter which prefix the scan sees, and
//                  never before the four bytes have all arrived. A
//                  terminator straddling a read boundary is the classic
//                  way this goes wrong: the scan sees "...\r\n\r" and
//                  either reports a header that has not ended or, on
//                  the next pass, fails to re-find one that has.
//     probe        every prefix of the HTTP/2 preface must still look
//                  like the preface — a connection whose first read is
//                  three bytes is not an HTTP/1 request — and anything
//                  that has already diverged must stay diverged.
//     pipeline     the loop itself, transcribed: accumulate, scan,
//                  serve, shift the leftover bytes to the front of
//                  `buf`, repeat. A pipelined stream must split into
//                  exactly the same requests however the reads landed
//                  — the arithmetic Step 8 carried forward
//                  (fuzzing.md §22 item 2, child.S's Lcheck_leftover).
//
//   The two scans are checked with the prefix placed *flush against a
//   guard page*, at every prefix length rather than one. That is the
//   other half of the question: a scan that peeks one byte past the
//   length it was given works fine on a full buffer, where the next
//   byte is the one that has not arrived yet, and reads whatever is
//   there exactly when a read boundary lands on it. Here it faults.
//
//   From frag_common.h this suite uses only the split-schedule
//   generator and the comparison helper: there is no socket to feed,
//   so there is no feeder thread either.
// ─────────────────────────────────────────────────────────────────────

#include "frag_common.h"

#include <string.h>

#define H2_PREFACE_LEN 24
static const char H2_PREFACE[H2_PREFACE_LEN + 1] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── the routines under test ─────────────────────────────────────────
// parse_header_end returns its answer in x1, not x0 — the one routine
// in the tree that does.
static uint64_t call_header_end(const uint8_t *b, uint64_t len)
{
    uint64_t out;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl parse_header_end\n"
        "mov %0, x1\n"
        : "=r"(out)
        : "r"(b), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x30", "cc", "memory");
    return out;
}

static uint64_t call_h2_probe(const uint8_t *b, uint64_t len)
{
    uint64_t out;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl h2_probe\n"
        "mov %0, x0\n"
        : "=r"(out)
        : "r"(b), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x9", "x30", "cc", "memory");
    return out;
}

// The server's own memcpy, which is not the one C calls: in Mach-O a
// `.global memcpy` in assembly is the symbol `memcpy`, while C's
// memcpy() is `_memcpy` in libc. The shift in child.S is `bl memcpy`,
// so reaching the routine actually under test means saying so.
static void sarm_memcpy(void *dst, const void *src, size_t n)
{
    __asm__ volatile(
        "mov x0, %0\n"
        "mov x1, %1\n"
        "mov x2, %2\n"
        "bl memcpy\n"
        :
        : "r"(dst), "r"(src), "r"(n)
        : "x0", "x1", "x2", "x3", "x4", "x30", "cc", "memory");
}

// ── the reference ───────────────────────────────────────────────────
// What the accumulating loop is entitled to assume: the index one past
// the first complete "\r\n\r\n", or 0 while there is not one yet.
static uint64_t ref_header_end(const uint8_t *b, size_t len)
{
    for (size_t i = 0; i + 4 <= len; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' &&
            b[i + 2] == '\r' && b[i + 3] == '\n')
            return i + 4;
    return 0;
}

static uint64_t ref_h2_probe(const uint8_t *b, size_t len)
{
    if (len == 0)
        return 0;
    size_t n = len < H2_PREFACE_LEN ? len : H2_PREFACE_LEN;
    return memcmp(b, H2_PREFACE, n) == 0 ? 1 : 0;
}

// ── corpus ──────────────────────────────────────────────────────────
// Terminators are the subject, so the generator spends its budget on
// them: requests that end properly, requests that end nearly, and
// bare CR/LF soup where every prefix boundary lands inside a partial
// match. A uniformly random buffer contains "\r\n\r\n" about once in
// four billion bytes and would make every case the same case.
#define REQ_MAX 480

struct gen { uint8_t *p; size_t len, cap; };

static void g_put(struct gen *g, const void *src, size_t n)
{
    if (g->len + n > g->cap) n = g->cap - g->len;
    memcpy(g->p + g->len, src, n);
    g->len += n;
}

static void g_str(struct gen *g, const char *s) { g_put(g, s, strlen(s)); }

// A run of CR and LF in some order: the bytes a partial-match scanner
// has to get right, and the ones a read boundary is most likely to
// split.
static void gen_eol_soup(struct gen *g, struct fuzz_rng *r)
{
    uint64_t n = fuzz_range(r, 1, 8);
    for (uint64_t i = 0; i < n; i++) {
        static const char *const bits[] = { "\r", "\n", "\r\n", "\r\r",
                                            "\n\n", "\r\n\r", "\n\r\n" };
        g_str(g, bits[fuzz_below(r, sizeof bits / sizeof bits[0])]);
    }
}

static void gen_header_line(struct gen *g, struct fuzz_rng *r)
{
    static const char *const names[] = {
        "Host: x", "Connection: keep-alive", "Range: bytes=0-1",
        "Accept: */*", "User-Agent: sarm", "Content-Length: 0",
    };
    g_str(g, names[fuzz_below(r, sizeof names / sizeof names[0])]);
    if (fuzz_chance(r, 6)) gen_eol_soup(g, r);
    else                   g_str(g, "\r\n");
}

static size_t gen_request(struct fuzz_rng *r, uint8_t *buf, size_t cap)
{
    struct gen g = { buf, 0, cap };

    switch (fuzz_below(r, 8)) {
    case 0:                                     // pure soup
        while (g.len < cap / 2 && !fuzz_chance(r, 4))
            gen_eol_soup(&g, r);
        break;
    case 1:                                     // the preface, whole or bent
        g_put(&g, H2_PREFACE, H2_PREFACE_LEN);
        if (fuzz_chance(r, 3) && g.len)
            buf[fuzz_below(r, g.len)] ^= (uint8_t)(1u << fuzz_below(r, 8));
        if (fuzz_chance(r, 2))
            g_str(&g, "\x00\x00\x00\x04\x00\x00\x00\x00\x00");
        break;
    default: {                                  // a request header
        static const char *const m[] = { "GET", "HEAD", "POST", "OPTIONS" };
        g_str(&g, m[fuzz_below(r, 4)]);
        g_str(&g, " /");
        uint64_t plen = fuzz_below(r, 12);
        for (uint64_t i = 0; i < plen; i++) {
            uint8_t c = (uint8_t)fuzz_range(r, 'a', 'z');
            g_put(&g, &c, 1);
        }
        g_str(&g, " HTTP/1.1\r\n");
        uint64_t nh = fuzz_below(r, 4);
        for (uint64_t i = 0; i < nh; i++)
            gen_header_line(&g, r);
        if (fuzz_chance(r, 4)) gen_eol_soup(&g, r);     // ends nearly
        else                   g_str(&g, "\r\n");       // ends properly
        if (fuzz_chance(r, 4)) {                        // pipelined leftovers
            g_str(&g, "GET /next HTTP/1.1\r\n\r\n");
        }
        break;
    }
    }

    // a light mutation pass, so the corpus is not only what was thought of
    if (fuzz_chance(r, 4) && g.len)
        fuzz_mutate(r, buf, g.len);
    return g.len;
}

// ── prefix sweep ────────────────────────────────────────────────────
// Every prefix, for the short inputs where that is affordable; for the
// longer ones a sample that always includes the lengths where the
// answer changes — the three around the terminator, and both ends.
#define SWEEP_FULL_MAX  192
#define SWEEP_SAMPLES   64

static size_t sweep_lengths(struct fuzz_rng *r, size_t n, uint64_t at,
                            uint32_t *out)
{
    if (n <= SWEEP_FULL_MAX) {
        for (size_t i = 0; i <= n; i++)
            out[i] = (uint32_t)i;
        return n + 1;
    }
    size_t k = 0;
    out[k++] = 0;
    out[k++] = (uint32_t)n;
    for (int64_t d = -2; d <= 2; d++) {         // around the terminator
        int64_t v = (int64_t)at + d;
        if (v >= 0 && v <= (int64_t)n)
            out[k++] = (uint32_t)v;
    }
    while (k < SWEEP_SAMPLES)
        out[k++] = (uint32_t)fuzz_below(r, n + 1);
    return k;
}

static struct {
    struct guarded_buffer probe;    // one prefix, flush against the guard
    uint8_t  req[REQ_MAX];
    uint32_t lens[SWEEP_FULL_MAX + 1 > SWEEP_SAMPLES
                  ? SWEEP_FULL_MAX + 1 : SWEEP_SAMPLES];
} g_sweep;

static int sweep_setup(struct fuzz_ctx *c)
{
    (void)c;
    return guard_alloc(&g_sweep.probe, REQ_MAX);
}

static void sweep_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_sweep.probe);
}

// Place buf[0, len) so that its last byte is the last byte before the
// guard page: reading buf[len] faults.
static uint8_t *place_flush(size_t len)
{
    uint8_t *at = g_sweep.probe.data + g_sweep.probe.size - len;
    memcpy(at, g_sweep.req, len);
    return at;
}

// Counted once per case, not once per prefix: the histogram is a
// statement about the corpus ("this many cases reached a complete
// header"), and a per-prefix tally would report percentages of cases
// in the thousands.
enum {
    B_FOUND = 0,        // some prefix at which the scan reports a header end
    B_PENDING,          // some prefix at which it does not, and should not
    B_STRADDLE,         // some prefix ending inside the terminator itself
};

#define HE_BUCKETS \
    { "!header end found", "!still incomplete", "!prefix inside the \\r\\n\\r\\n", \
      0 }

#define PROBE_BUCKETS \
    { "preface prefix", "diverged", "!empty and non-empty both seen", 0 }

// ── campaign 1: parse_header_end over every prefix ──────────────────
static void he_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_sweep.req, REQ_MAX);
    uint64_t at = ref_header_end(g_sweep.req, n);

    size_t k = sweep_lengths(r, n, at, g_sweep.lens);
    int saw_found = 0, saw_pending = 0, saw_straddle = 0;
    for (size_t i = 0; i < k; i++) {
        size_t len = g_sweep.lens[i];
        uint8_t *p = place_flush(len);
        uint64_t got = call_header_end(p, len);
        uint64_t want = ref_header_end(p, len);

        FUZZ_CHECK(c, got == want,
                   "parse_header_end: a prefix of the same bytes gives a "
                   "different answer than the byte string does");
        if (got) {
            FUZZ_CHECK(c, got == at,
                       "parse_header_end: the header end moves depending on "
                       "how much of the request has arrived");
            FUZZ_CHECK(c, got <= len,
                       "parse_header_end: reported a header end past the "
                       "bytes it was given");
            saw_found = 1;
        } else {
            FUZZ_CHECK(c, at == 0 || len < at,
                       "parse_header_end: lost a complete terminator that a "
                       "shorter prefix had already contained");
            saw_pending = 1;
            if (at && len >= at - 3)
                saw_straddle = 1;
        }
    }
    if (saw_found)    fuzz_tally(c, B_FOUND);
    if (saw_pending)  fuzz_tally(c, B_PENDING);
    if (saw_straddle) fuzz_tally(c, B_STRADDLE);
}

// ── campaign 2: h2_probe over every prefix ──────────────────────────
// child.S runs the probe once, on the first read, and never again —
// so a preface delivered in pieces is decided on whatever the first
// piece was. A probe that said "not HTTP/2" for a three-byte "PRI"
// would send that connection down the HTTP/1 path for good.
static void probe_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_sweep.req, REQ_MAX);
    if (n > H2_PREFACE_LEN + 16)
        n = H2_PREFACE_LEN + 16;                // only the decision window
    size_t k = sweep_lengths(r, n, 0, g_sweep.lens);

    int diverged_at = -1, saw_preface = 0, saw_other = 0;
    for (size_t i = 0; i < k; i++) {
        size_t len = g_sweep.lens[i];
        uint8_t *p = place_flush(len);
        uint64_t got = call_h2_probe(p, len);
        uint64_t want = ref_h2_probe(p, len);

        FUZZ_CHECK(c, got == want,
                   "h2_probe: a prefix of the same bytes gives a different "
                   "answer than the byte string does");
        if (got) saw_preface = 1;
        else     saw_other = 1;
        if (!got && len && (diverged_at < 0 || (int)len < diverged_at))
            diverged_at = (int)len;
    }

    // Monotone in the direction that matters: once the bytes are not
    // the preface, no longer prefix of them can be.
    if (diverged_at > 0) {
        for (size_t len = (size_t)diverged_at; len <= n; len++) {
            uint8_t *p = place_flush(len);
            FUZZ_CHECK(c, call_h2_probe(p, len) == 0,
                       "h2_probe: a stream that had already diverged from "
                       "the preface looks like the preface again once more "
                       "bytes arrive");
        }
        fuzz_tally(c, B_STRADDLE);
    }
    if (saw_preface) fuzz_tally(c, B_FOUND);
    if (saw_other)   fuzz_tally(c, B_PENDING);
}

// ── campaign 3: the read loop, pipelined ────────────────────────────
// A transcription of src/sarm/child.S, and only of the parts that move
// bytes: read into `buf` at the offset already filled, scan the whole
// of it with parse_header_end, and on a hit shift what follows the
// header down to the front with the server's own memcpy and go round
// again (Lcheck_leftover / Lhkc_shift). Everything else — the reply,
// the budget, the protocol probe — is left out, because the question
// is which bytes each request is made of.
//
// The stream is fed in the chunks the plan chose, so the boundaries
// land inside terminators, inside the leftover bytes, and inside the
// shift. Whatever the chunking, the sequence of requests taken out of
// the stream must be the one the byte string names.
#define PIPE_BUF_SIZE 16384          // BUF_SIZE, src/defs.S
#define PIPE_MAX_REQS 8

// A request is not just a length: the bytes the loop hands the parser
// have been shifted down the buffer, possibly several times, and the
// shift is the server's own memcpy. So each served request is recorded
// as its length *and* a hash of its bytes — a length-only record would
// call a corrupted shift identical.
struct pipe_out {
    uint32_t len[PIPE_MAX_REQS];     // header length of each request served
    uint64_t hash[PIPE_MAX_REQS];    // ... and its contents
    unsigned n;
    unsigned overflowed;             // the buffer filled with no terminator
};

static uint64_t pipe_hash(const uint8_t *p, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ULL;         // FNV-1a
    for (size_t i = 0; i < n; i++)
        h = (h ^ p[i]) * 0x100000001b3ULL;
    return h;
}

static struct {
    uint8_t stream[REQ_MAX * PIPE_MAX_REQS];
    uint8_t buf[PIPE_BUF_SIZE + 1];
} g_pipe;

// The reference: split the stream at each "\r\n\r\n" in turn, which is
// what the loop must do no matter where the reads fell.
static void pipe_reference(const uint8_t *s, size_t n, struct pipe_out *o)
{
    o->n = 0; o->overflowed = 0;
    size_t at = 0;
    while (at < n && o->n < PIPE_MAX_REQS) {
        uint64_t e = ref_header_end(s + at, n - at);
        if (!e)
            break;
        o->hash[o->n] = pipe_hash(s + at, (size_t)e);
        o->len[o->n++] = (uint32_t)e;
        at += e;
    }
}

// The loop, run against one chunking of the same stream.
static void pipe_run(const uint8_t *s, size_t n, const struct frag_plan *plan,
                     struct pipe_out *o)
{
    o->n = 0; o->overflowed = 0;
    size_t filled = 0;                       // x7 — bytes sitting in buf
    unsigned next_cut = 0;
    size_t delivered = 0;

    for (;;) {
        if (filled) {
            uint64_t e = call_header_end(g_pipe.buf, filled);
            if (e) {
                if (o->n >= PIPE_MAX_REQS)
                    return;
                o->hash[o->n] = pipe_hash(g_pipe.buf, (size_t)e);
                o->len[o->n++] = (uint32_t)e;
                size_t leftover = filled - (size_t)e;
                if (leftover)                // Lhkc_shift, the server's memcpy
                    sarm_memcpy(g_pipe.buf, g_pipe.buf + e, leftover);
                filled = leftover;
                continue;
            }
            if (filled >= PIPE_BUF_SIZE) {   // L431 — no terminator, no room
                o->overflowed = 1;
                return;
            }
        }
        if (delivered == n)                  // EOF: read_loop returns 0
            return;
        size_t end = (plan && next_cut < plan->n_cuts) ? plan->cut[next_cut++]
                                                       : n;
        if (end > n) end = n;
        size_t take = end - delivered;
        if (take > PIPE_BUF_SIZE - filled)
            take = PIPE_BUF_SIZE - filled;
        memcpy(g_pipe.buf + filled, s + delivered, take);
        filled    += take;
        delivered += take;
    }
}

static void pipe_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    // a pipeline: whole requests back to back, then sometimes a partial
    // one that no amount of reading will complete
    size_t n = 0;
    unsigned reqs = (unsigned)fuzz_range(r, 1, 4);
    for (unsigned i = 0; i < reqs; i++) {
        size_t len = gen_request(r, g_sweep.req, REQ_MAX);
        if (n + len > sizeof g_pipe.stream)
            break;
        memcpy(g_pipe.stream + n, g_sweep.req, len);
        n += len;
    }
    if (n == 0)
        return;

    // the ends of the requests the reference finds are where a read
    // boundary hurts most, so they are the hints
    struct pipe_out want;
    pipe_reference(g_pipe.stream, n, &want);
    uint32_t hints[8];
    unsigned n_hints = 0;
    uint32_t at = 0;
    for (unsigned i = 0; i < want.n && n_hints < 8; i++) {
        at += want.len[i];
        hints[n_hints++] = at;
    }

    struct frag_plan plan;
    frag_plan_gen(r, n, hints, n_hints, &plan);

    struct pipe_out whole, split;
    pipe_run(g_pipe.stream, n, NULL,  &whole);
    pipe_run(g_pipe.stream, n, &plan, &split);

    frag_check_equal(c, &whole, &split, sizeof whole,
                     "the read loop: a pipelined stream splits into different "
                     "requests depending on where the reads landed");
    FUZZ_CHECK(c, whole.n == want.n &&
                  memcmp(whole.len, want.len,
                         whole.n * sizeof whole.len[0]) == 0 &&
                  memcmp(whole.hash, want.hash,
                         whole.n * sizeof whole.hash[0]) == 0,
               "the read loop: the requests taken out of the stream are not, "
               "byte for byte, the ones its \r\n\r\n terminators name");

    if (whole.n) fuzz_tally(c, B_FOUND);
    else         fuzz_tally(c, B_PENDING);
    if (whole.n > 1) fuzz_tally(c, B_STRADDLE);
}

static const struct fuzz_target g_targets[] = {
    { "header_end", he_case,    sweep_setup, sweep_teardown, 40000, 0,
      HE_BUCKETS, 0 },
    { "probe",      probe_case, sweep_setup, sweep_teardown, 40000, 0,
      { "!looks like the preface", "!does not", "!diverged and stayed so", 0 },
      0 },
    { "pipeline",   pipe_case,  sweep_setup, sweep_teardown, 20000, 0,
      { "!a request was served", "!none was", "!more than one, pipelined", 0 },
      0 },
};

int main(int argc, char **argv)
{
    (void)argc;
    fuzz_disarm_harness_timeout();
    fuzz_suite("frag_http", argv[0]);

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  sarm — fragmentation of the read loop (Step 9)         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  seed 0x%llx, x%llu cases\n",
           (unsigned long long)fuzz_seed(), (unsigned long long)fuzz_mult());

    TEST_SUITE("the plaintext read loop — every prefix of the same bytes");
    fuzz_run_all(g_targets, sizeof g_targets / sizeof g_targets[0]);

    test_summary();
    return 0;
}
