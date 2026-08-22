// sarm security tests — the fuzzing harness (Step 6)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/fuzz_common.h — a standalone, deterministic,
//   guard-page-backed fuzzing harness (docs/SECURITY.md, Step 6)
//
// Description: Step 6 asks for a "standalone harness" run over
//   "millions of generated cases with no crash or hang". Three words
//   in that sentence set the design.
//
//   *Standalone*: the harness links the routines under test and
//   nothing else. A failure names `tls_record_parse`, not "the
//   server". No socket, no handshake, no libFuzzer, no sanitizer
//   runtime — none of which can instrument hand-written .S anyway
//   (guard_pages.h). What replaces them is the guard page: every
//   generated input is placed flush against PROT_NONE, so a read one
//   byte past the record faults on the instruction that did it.
//
//   *Millions*: fork-per-case, the shape Steps 3-5 use, costs about a
//   millisecond a case and caps out around a million cases an hour.
//   So the loop runs in-process and the *campaign* is forked: one
//   child runs a whole batch, publishing the index and seed of the
//   case it is about to try into a page shared with the parent. When
//   the child dies, the parent reads that page and knows exactly which
//   case killed it. The cost of a crash is one campaign; the cost of a
//   case is a few hundred nanoseconds.
//
//   *No crash or hang*: those are the two ways a child can fail to
//   come back, and they are distinguished here. A crash is a signal —
//   SIGSEGV from a guard page, SIGBUS, SIGILL, an abort. A hang is the
//   parent's deadline expiring with the child's heartbeat not moving.
//   Both are reported with the reproducer, and both are failures.
//
//   Everything is deterministic. A case is a pure function of
//   (campaign seed, case index): the same build, the same seed and the
//   same index generate the same bytes, on any machine, whether or not
//   the cases around it ran. So a crash report is a recipe:
//
//       SARM_FUZZ_SEED=<seed> SARM_FUZZ_CASE=<index> ./_obj/test_fuzz_tls_record
//
//   re-runs that one case in-process — no fork, no handler, straight
//   into the debugger.
//
// Environment:
//   SARM_FUZZ_SEED=<u64>   campaign seed (default FUZZ_DEFAULT_SEED, so
//                          the committed suite runs the same corpus
//                          every time and a regression is a regression,
//                          not a coincidence)
//   SARM_FUZZ_MULT=<n>     scale every campaign's case count by n. The
//                          default (1) is sized for `make test`; the
//                          long campaigns recorded in
//                          docs/security/fuzzing.md were run with
//                          larger values.
//   SARM_FUZZ_CASE=<index> run only this case, in-process, and exit.
//   SARM_FUZZ_SECS=<n>     per-campaign deadline (default
//                          FUZZ_DEADLINE_SECS).
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_FUZZ_COMMON_H
#define SARM_FUZZ_COMMON_H

// <unistd.h> before test_harness.h: the harness declares `write`
// itself (it deliberately avoids libc string/stdlib headers, see its
// own note), and a plain redeclaration after the SDK's asm-labelled one
// is fine while the reverse order is an error.
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#include "guard_pages.h"
#include "../unit/test_harness.h"

// ── determinism ─────────────────────────────────────────────────────
// splitmix64: one multiply-xorshift chain, no state beyond a u64, and
// good enough for input generation. Chosen over anything from libc
// because rand()/random() differ between platforms and this corpus
// must not.
#define FUZZ_DEFAULT_SEED  0x5a524d66757a7aULL   // "sarm" and a hint of fuzz

struct fuzz_rng { uint64_t s; };

static inline uint64_t fuzz_u64(struct fuzz_rng *r)
{
    uint64_t z = (r->s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline uint32_t fuzz_u32(struct fuzz_rng *r) { return (uint32_t)fuzz_u64(r); }
static inline uint8_t  fuzz_u8 (struct fuzz_rng *r) { return (uint8_t)fuzz_u64(r); }

// Uniform-enough in [0, n). n == 0 gives 0.
static inline uint64_t fuzz_below(struct fuzz_rng *r, uint64_t n)
{
    return n ? fuzz_u64(r) % n : 0;
}

// Inclusive range.
static inline uint64_t fuzz_range(struct fuzz_rng *r, uint64_t lo, uint64_t hi)
{
    return lo + fuzz_below(r, hi - lo + 1);
}

// True with probability 1/n.
static inline int fuzz_chance(struct fuzz_rng *r, uint64_t n)
{
    return fuzz_below(r, n) == 0;
}

// The seed for case `index` of a campaign. Derived rather than
// sequential so that running case 900123 alone gives byte-for-byte
// what running it inside the campaign gave.
static inline struct fuzz_rng fuzz_case_rng(uint64_t campaign_seed,
                                            uint64_t index)
{
    struct fuzz_rng mix = { campaign_seed ^ (index * 0xD6E8FEB86659FD93ULL) };
    struct fuzz_rng r = { fuzz_u64(&mix) };
    return r;
}

// ── generic byte mutators ───────────────────────────────────────────
// Values that historically sit on the wrong side of a comparison:
// signedness boundaries, powers of two, and the TLS length limits.
static const uint64_t fuzz_interesting[] = {
    0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 63, 64, 100, 127, 128,
    129, 255, 256, 257, 511, 512, 1023, 1024, 4095, 4096,
    16383, 16384, 16385,          // TLS_MAX_PLAINTEXT and its neighbours
    16400, 16401, 16402,          // TLS_MAX_AEAD
    16639, 16640, 16641,          // TLS_MAX_CIPHERTEXT
    32767, 32768, 65534, 65535,
};
#define FUZZ_INTERESTING_N (sizeof(fuzz_interesting) / sizeof(fuzz_interesting[0]))

static inline uint64_t fuzz_interesting_value(struct fuzz_rng *r)
{
    return fuzz_interesting[fuzz_below(r, FUZZ_INTERESTING_N)];
}

// Apply one random edit to buf[0, len). Bit flips find off-by-ones in
// flags and type checks; byte splices of interesting values find them
// in lengths.
static inline void fuzz_mutate_once(struct fuzz_rng *r, uint8_t *buf, size_t len)
{
    if (len == 0)
        return;
    size_t at = (size_t)fuzz_below(r, len);
    switch (fuzz_below(r, 6)) {
    case 0: buf[at] ^= (uint8_t)(1u << fuzz_below(r, 8)); break;
    case 1: buf[at] = fuzz_u8(r); break;
    case 2: buf[at] = 0x00; break;
    case 3: buf[at] = 0xFF; break;
    case 4: buf[at] = (uint8_t)fuzz_interesting_value(r); break;
    case 5: {                       // 16-bit big-endian splice
        uint64_t v = fuzz_interesting_value(r);
        buf[at] = (uint8_t)(v >> 8);
        if (at + 1 < len)
            buf[at + 1] = (uint8_t)v;
        break;
    }
    }
}

static inline void fuzz_mutate(struct fuzz_rng *r, uint8_t *buf, size_t len)
{
    uint64_t n = fuzz_range(r, 1, 8);
    for (uint64_t i = 0; i < n; i++)
        fuzz_mutate_once(r, buf, len);
}

static inline void fuzz_fill_random(struct fuzz_rng *r, uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = fuzz_u8(r);
}

// ── the shared report page ──────────────────────────────────────────
// MAP_SHARED, so the parent can still read what the child wrote after
// the child has been killed by a signal. Written before each case, not
// after, so it names the case in progress when the fault happens.
#define FUZZ_MSG_LEN 192

// Outcome buckets. A fuzzer that never reaches the accepting path is
// testing one branch a million times, and the only way to know which
// it is doing is to count. Targets tally the outcome of each case;
// SARM_FUZZ_STATS=1 prints the histogram, and fuzz_run fails a
// campaign outright if a bucket the target declared as required stayed
// empty — so a generator that drifts until it no longer produces valid
// records is a test failure, not a silently weaker suite.
#define FUZZ_BUCKETS 12

struct fuzz_report {
    volatile uint64_t index;        // case about to run
    volatile uint64_t seed;         // campaign seed
    volatile uint64_t heartbeat;    // cases completed; the liveness signal
    volatile int      invariant;    // non-zero: an invariant failed
    volatile uint64_t bucket[FUZZ_BUCKETS];
    volatile char     msg[FUZZ_MSG_LEN];
};

// Child exit codes. 77 is reserved by guard_pages.h; keep clear of it.
#define FUZZ_CHILD_OK         0
#define FUZZ_CHILD_INVARIANT  70

// Available inside a fuzz target through the ctx it is handed.
struct fuzz_ctx {
    struct fuzz_report *report;
    void               *user;
};

// Set while replaying a single case (SARM_FUZZ_CASE): there is no
// parent to relay the message, so fuzz_fail prints it itself.
static int fuzz_single_case = 0;

// Record an invariant violation and end the campaign. The message is
// copied into the shared page by hand: no libc string calls, so the
// harness stays usable from a child whose memory may be suspect.
static inline void fuzz_fail(struct fuzz_ctx *c, const char *msg)
{
    size_t i = 0;
    for (; msg[i] && i < FUZZ_MSG_LEN - 1; i++)
        c->report->msg[i] = msg[i];
    c->report->msg[i] = '\0';
    c->report->invariant = 1;
    if (fuzz_single_case) {
        printf("  ✗ case %llu: %s\n",
               (unsigned long long)c->report->index, msg);
        fflush(stdout);
    }
    _exit(FUZZ_CHILD_INVARIANT);
}

// The workhorse assertion inside a target: any violation is a finding,
// reported with the reproducer for the exact case that produced it.
#define FUZZ_CHECK(ctx, cond, msg) \
    do { if (!(cond)) fuzz_fail((ctx), (msg)); } while (0)

// Record which outcome this case produced.
static inline void fuzz_tally(struct fuzz_ctx *c, unsigned bucket)
{
    if (bucket < FUZZ_BUCKETS)
        c->report->bucket[bucket]++;
}

// ── a campaign ──────────────────────────────────────────────────────
#define FUZZ_DEADLINE_SECS 300

struct fuzz_target {
    const char *name;
    // Generate and run one case. Everything it needs is derived from
    // `rng`; `ctx` carries the report page and any per-target state.
    void      (*run)(struct fuzz_rng *rng, struct fuzz_ctx *ctx);
    // Per-target state set up once, before the fork, so the guarded
    // buffers a target reuses are mapped in the parent and inherited.
    int       (*setup)(struct fuzz_ctx *ctx);
    void      (*teardown)(struct fuzz_ctx *ctx);
    uint64_t    cases;              // before SARM_FUZZ_MULT is applied
    void       *user;
    // Bucket names, NULL-terminated, in fuzz_tally order. A name
    // prefixed with '!' marks an outcome the campaign must reach at
    // least once for its invariants to mean anything.
    const char *buckets[FUZZ_BUCKETS];
};

static uint64_t fuzz_env_u64(const char *name, uint64_t dflt, int *present)
{
    extern char **environ;
    size_t n = 0;
    while (name[n]) n++;
    for (char **e = environ; *e; e++) {
        size_t i = 0;
        for (; i < n && (*e)[i] == name[i]; i++) { }
        if (i != n || (*e)[i] != '=')
            continue;
        const char *v = *e + n + 1;
        if (!*v)
            break;
        uint64_t acc = 0;
        for (; *v >= '0' && *v <= '9'; v++)
            acc = acc * 10 + (uint64_t)(*v - '0');
        if (*v)
            break;                  // trailing junk: treat as unset
        if (present) *present = 1;
        return acc;
    }
    if (present) *present = 0;
    return dflt;
}

static uint64_t fuzz_seed(void)   { return fuzz_env_u64("SARM_FUZZ_SEED", FUZZ_DEFAULT_SEED, 0); }
static uint64_t fuzz_mult(void)   { uint64_t m = fuzz_env_u64("SARM_FUZZ_MULT", 1, 0); return m ? m : 1; }
static uint64_t fuzz_deadline(void) { return fuzz_env_u64("SARM_FUZZ_SECS", FUZZ_DEADLINE_SECS, 0); }

// test_harness.h arms alarm(TEST_TIMEOUT_SECS) at load time, which is
// sized for a unit test, not for a fuzzing campaign. A fuzz suite calls
// this from main() to stand it down; the campaign's own deadline
// (fuzz_run's heartbeat watch) is what catches a hang, and it is a
// better detector because it distinguishes "still making progress" from
// "stuck".
static void fuzz_disarm_harness_timeout(void) { alarm(0); }

// ── child-side fault handling ───────────────────────────────────────
// Left as the default disposition: an unhandled SIGSEGV is exactly the
// signal the parent wants to see, and letting it through means a
// developer running under a debugger stops on the faulting instruction
// rather than in an exit handler. The parent suppresses core files for
// the child (RLIMIT_CORE 0 is the caller's business; macOS does not
// write cores by default).

static const char *fuzz_signal_name(int sig)
{
    switch (sig) {
    case SIGSEGV: return "SIGSEGV (read or wrote outside a mapped page — a "
                         "guard page, or memory the routine had no business "
                         "touching)";
    case SIGBUS:  return "SIGBUS (the same, or an unaligned access — Apple "
                         "silicon reports guard-page hits either way)";
    case SIGILL:  return "SIGILL";
    case SIGABRT: return "SIGABRT";
    case SIGFPE:  return "SIGFPE";
    case SIGTRAP: return "SIGTRAP";
    case SIGKILL: return "SIGKILL (out of memory, or killed by the deadline)";
    default:      return "signal";
    }
}

// Run one campaign. Reports exactly one test result: the campaign
// either completed every case without a crash, a hang or an invariant
// violation, or it did not — and if it did not, the message carries the
// reproducer.
static void fuzz_run(const struct fuzz_target *t)
{
    const uint64_t seed  = fuzz_seed();
    const uint64_t cases = t->cases * fuzz_mult();
    const uint64_t secs  = fuzz_deadline();

    struct fuzz_report *rep = mmap(NULL, sizeof *rep, PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_ANON, -1, 0);
    if (rep == MAP_FAILED) {
        _FAIL("%s — could not map the report page", t->name);
        return;
    }
    rep->index = 0; rep->seed = seed; rep->heartbeat = 0;
    rep->invariant = 0; rep->msg[0] = '\0';
    for (unsigned b = 0; b < FUZZ_BUCKETS; b++)
        rep->bucket[b] = 0;

    struct fuzz_ctx ctx = { rep, t->user };
    if (t->setup && t->setup(&ctx) != 0) {
        _FAIL("%s — setup failed", t->name);
        munmap(rep, sizeof *rep);
        return;
    }

    // ── single-case mode: no fork, so a fault lands in the debugger ──
    int one_present = 0;
    uint64_t one = fuzz_env_u64("SARM_FUZZ_CASE", 0, &one_present);
    if (one_present) {
        printf("  [%s] replaying case %llu of seed 0x%llx\n",
               t->name, (unsigned long long)one, (unsigned long long)seed);
        fflush(stdout);
        fuzz_single_case = 1;
        rep->index = one;
        struct fuzz_rng r = fuzz_case_rng(seed, one);
        t->run(&r, &ctx);
        _PASS(t->name);
        if (t->teardown) t->teardown(&ctx);
        munmap(rep, sizeof *rep);
        return;
    }

    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        _FAIL("%s — fork failed", t->name);
        if (t->teardown) t->teardown(&ctx);
        munmap(rep, sizeof *rep);
        return;
    }
    if (pid == 0) {
        // The child inherits test_harness.h's alarm(TEST_TIMEOUT_SECS).
        // Disarm it: a campaign is meant to outlive it, and liveness is
        // the parent's job (the heartbeat below), not a fixed alarm.
        alarm(0);
        for (uint64_t i = 0; i < cases; i++) {
            rep->index = i;
            struct fuzz_rng r = fuzz_case_rng(seed, i);
            t->run(&r, &ctx);
            rep->heartbeat = i + 1;
        }
        _exit(FUZZ_CHILD_OK);
    }

    // ── parent: wait, watching the heartbeat ──
    // The deadline is against progress, not against wall time, so a
    // campaign that is merely long is not called a hang. It is a hang
    // only if the heartbeat has not moved for `secs`.
    int status = 0;
    uint64_t last_beat = 0;
    time_t last_move = time(NULL);
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            break;
        if (w < 0) {
            _FAIL("%s — waitpid failed", t->name);
            if (t->teardown) t->teardown(&ctx);
            munmap(rep, sizeof *rep);
            return;
        }
        uint64_t beat = rep->heartbeat;
        time_t now = time(NULL);
        if (beat != last_beat) { last_beat = beat; last_move = now; }
        else if (now - last_move >= (time_t)secs) {
            uint64_t idx = rep->index;
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            _FAIL("%s — HANG: no progress for %llus at case %llu "
                  "(reproduce: SARM_FUZZ_SEED=%llu SARM_FUZZ_CASE=%llu)",
                  t->name, (unsigned long long)secs,
                  (unsigned long long)idx, (unsigned long long)seed,
                  (unsigned long long)idx);
            if (t->teardown) t->teardown(&ctx);
            munmap(rep, sizeof *rep);
            return;
        }
        struct timespec ts = { 0, 20 * 1000 * 1000 };   // 20 ms
        nanosleep(&ts, NULL);
    }

    const uint64_t idx  = rep->index;
    const uint64_t done = rep->heartbeat;

    if (WIFSIGNALED(status)) {
        _FAIL("%s — CRASH: %s at case %llu of %llu "
              "(reproduce: SARM_FUZZ_SEED=%llu SARM_FUZZ_CASE=%llu)",
              t->name, fuzz_signal_name(WTERMSIG(status)),
              (unsigned long long)idx, (unsigned long long)cases,
              (unsigned long long)seed, (unsigned long long)idx);
    } else if (WEXITSTATUS(status) == FUZZ_CHILD_INVARIANT) {
        _FAIL("%s — %s (case %llu; reproduce: SARM_FUZZ_SEED=%llu "
              "SARM_FUZZ_CASE=%llu)",
              t->name, (const char *)rep->msg, (unsigned long long)idx,
              (unsigned long long)seed, (unsigned long long)idx);
    } else if (WEXITSTATUS(status) != FUZZ_CHILD_OK) {
        _FAIL("%s — child exited %d at case %llu", t->name,
              WEXITSTATUS(status), (unsigned long long)idx);
    } else if (done != cases) {
        _FAIL("%s — child finished having run %llu of %llu cases",
              t->name, (unsigned long long)done, (unsigned long long)cases);
    } else {
        // Non-vacuity: every outcome the target declared as required
        // must have happened. A generator that stops producing records
        // the parser accepts still passes every invariant it checks,
        // and is worth nothing.
        const char *empty = 0;
        for (unsigned b = 0; b < FUZZ_BUCKETS && t->buckets[b]; b++)
            if (t->buckets[b][0] == '!' && rep->bucket[b] == 0)
                empty = t->buckets[b] + 1;
        if (empty) {
            _FAIL("%s — VACUOUS: %llu cases and not one reached \"%s\"",
                  t->name, (unsigned long long)cases, empty);
        } else {
            printf("  ✓ %s — %llu cases\n", t->name,
                   (unsigned long long)cases);
            _tests_passed++;
        }
        if (fuzz_env_u64("SARM_FUZZ_STATS", 0, 0)) {
            for (unsigned b = 0; b < FUZZ_BUCKETS && t->buckets[b]; b++) {
                const char *nm = t->buckets[b];
                printf("      %-28s %10llu  (%5.2f%%)\n",
                       nm[0] == '!' ? nm + 1 : nm,
                       (unsigned long long)rep->bucket[b],
                       cases ? 100.0 * (double)rep->bucket[b] / (double)cases : 0.0);
            }
        }
    }

    if (t->teardown) t->teardown(&ctx);
    munmap(rep, sizeof *rep);
}

#endif // SARM_FUZZ_COMMON_H
