// sarm security tests — socket fragmentation (Step 9)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Header: tests/security/frag_common.h — delivering a byte string to a
//   real socket in pieces chosen by the test (docs/SECURITY.md, Step 9)
//
// Description: Step 9 asks one question of every reader in the tree:
//
//     Send every valid corpus item split at arbitrary byte positions.
//     Test: behaviour matches unsplit input.
//
//   The bug it hunts is the assumption Phase 4 names outright — that
//   `one recv() == one protocol message`. Nothing in TCP promises
//   that. A reader that believes it works perfectly against every
//   test client that writes a whole record with one `write()`, and
//   fails against the first peer whose ClientHello arrives as five
//   bytes and then the rest.
//
//   So the shape of a case here is not "one input, one invariant". It
//   is *the same input twice*: once written whole, once written in
//   pieces, with the two outcomes compared byte for byte. The
//   invariant is equality, which means the corpus does not have to be
//   valid for the check to mean something — a rejected record must be
//   rejected the same way, with the same error code, having left the
//   same bytes in the destination buffer, however it arrived.
//
// ── making a split a real split ─────────────────────────────────────
//   Writing the pieces back to back proves nothing: they land in the
//   socket buffer together and the reader's first `read()` returns the
//   lot, which is the unsplit case wearing a disguise. A split is only
//   real if the reader consumes piece k before piece k+1 arrives.
//
//   That needs two threads, and a way to know when to write the next
//   piece. The feeder thread asks the kernel: `FIONREAD` on the read
//   end is the number of bytes still waiting there, so the feeder
//   spins until it reads 0 — the reader has taken everything sent so
//   far and is (or is about to be) blocked in `read()` — and only then
//   writes the next piece. Every wait is bounded and the feeder writes
//   anyway when the bound expires, so a reader that stops reading
//   stalls nothing: the case still finishes and the campaign's own
//   deadline (fuzz_common.h) is what catches a genuine hang.
//
//   The feeder outlives its own last write, because saying EOF and
//   having it heard turned out to be two different things on this
//   kernel. The long comment above `frag_kick_until_done` below is the
//   whole story.
//
//   Whether each boundary was real is *counted*, not assumed:
//   `real_boundaries` and `missed_boundaries` are tallied per case and
//   the campaigns require the real ones to happen. A suite that
//   silently degraded into writing everything at once would fail as
//   VACUOUS rather than pass while testing nothing.
//
// ── for readers with no socket of their own ─────────────────────────
//   Not every reader in the tree takes a file descriptor. The HTTP/1
//   loop reads into a buffer and rescans the whole of it after every
//   read (src/sarm/child.S), so its fragmentation question is about
//   prefixes rather than packets. Those suites use this header's split
//   schedules and comparison helper without ever calling frag_open:
//   the cut offsets are where the reads landed, and there is nothing
//   to feed.
//
// ── determinism, and its one limit ──────────────────────────────────
//   The *schedule* is deterministic: the same seed and case index give
//   the same bytes cut at the same offsets, so every reproducer in
//   fuzz_common.h still works. The *interleaving* is not — it is two
//   threads and a scheduler. That asymmetry is the right way round:
//   the invariant under test is that the interleaving does not matter,
//   so a case that only fails on some interleavings is still a
//   finding, and re-running it is how you see it again.
// ─────────────────────────────────────────────────────────────────────

#ifndef SARM_FRAG_COMMON_H
#define SARM_FRAG_COMMON_H

#include "fuzz_common.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

// ── the split schedule ──────────────────────────────────────────────
// A plan is the set of offsets at which the byte string is cut. Cuts
// are strictly inside (0, n), strictly ascending, and de-duplicated:
// a zero-length write is not a fragmentation test, it is a no-op the
// kernel is entitled to discard.
#define FRAG_MAX_CUTS 32

struct frag_plan {
    uint32_t cut[FRAG_MAX_CUTS];
    unsigned n_cuts;
    unsigned shape;                 // FRAG_SHAPE_*, for the histogram
};

enum {
    FRAG_SHAPE_WHOLE = 0,   // no cuts — the reference delivery
    FRAG_SHAPE_ONE,         // a single cut, anywhere
    FRAG_SHAPE_BYTES,       // one byte at a time
    FRAG_SHAPE_RANDOM,      // k cuts at random offsets
    FRAG_SHAPE_HINTED       // cuts on the structure boundaries the
                            //   caller named (header/fragment, record
                            //   starts, the last byte)
};

static void frag_plan_sort(struct frag_plan *p)
{
    for (unsigned i = 1; i < p->n_cuts; i++) {      // insertion sort
        uint32_t v = p->cut[i];
        unsigned j = i;
        while (j && p->cut[j - 1] > v) { p->cut[j] = p->cut[j - 1]; j--; }
        p->cut[j] = v;
    }
    unsigned w = 0;                                  // drop duplicates
    for (unsigned i = 0; i < p->n_cuts; i++)
        if (w == 0 || p->cut[w - 1] != p->cut[i])
            p->cut[w++] = p->cut[i];
    p->n_cuts = w;
}

// Build a schedule for `n` bytes. `hints` are offsets the caller knows
// are structurally interesting — the header/fragment seam, the start
// of each record — which is where a reader that assumed one read per
// message goes wrong first. Random offsets alone reach them only by
// luck, so a shape is reserved for them and their neighbours.
static void frag_plan_gen(struct fuzz_rng *r, size_t n,
                          const uint32_t *hints, unsigned n_hints,
                          struct frag_plan *p)
{
    p->n_cuts = 0;
    p->shape  = FRAG_SHAPE_WHOLE;
    if (n < 2)
        return;

    unsigned shape = (unsigned)fuzz_below(r, 4) + 1;    // never WHOLE here
    if (shape == FRAG_SHAPE_HINTED && n_hints == 0)
        shape = FRAG_SHAPE_RANDOM;
    if (shape == FRAG_SHAPE_BYTES && n > FRAG_MAX_CUTS + 1)
        shape = FRAG_SHAPE_RANDOM;
    p->shape = shape;

    switch (shape) {
    case FRAG_SHAPE_ONE:
        p->cut[p->n_cuts++] = (uint32_t)fuzz_range(r, 1, n - 1);
        break;
    case FRAG_SHAPE_BYTES:
        for (size_t i = 1; i < n; i++)
            p->cut[p->n_cuts++] = (uint32_t)i;
        break;
    case FRAG_SHAPE_RANDOM: {
        unsigned k = (unsigned)fuzz_range(r, 1, FRAG_MAX_CUTS);
        if (k > n - 1) k = (unsigned)(n - 1);
        for (unsigned i = 0; i < k; i++)
            p->cut[p->n_cuts++] = (uint32_t)fuzz_range(r, 1, n - 1);
        break;
    }
    case FRAG_SHAPE_HINTED: {
        unsigned k = (unsigned)fuzz_range(r, 1, 8);
        for (unsigned i = 0; i < k && p->n_cuts < FRAG_MAX_CUTS; i++) {
            // the hint itself, or one byte to either side of it — the
            // three placements that tell a split header from a split
            // fragment
            int64_t at = (int64_t)hints[fuzz_below(r, n_hints)]
                       + (int64_t)fuzz_below(r, 3) - 1;
            if (at > 0 && at < (int64_t)n)
                p->cut[p->n_cuts++] = (uint32_t)at;
        }
        break;
    }
    }
    frag_plan_sort(p);
    if (p->n_cuts == 0)
        p->shape = FRAG_SHAPE_WHOLE;
}

// ── the feeder ──────────────────────────────────────────────────────
// How long to wait for the reader to drain a piece before giving up on
// that boundary and writing the next one anyway. A blocked reader
// drains in microseconds; the cap only matters when the reader has
// stopped reading altogether, which is exactly when the case must not
// deadlock.
#define FRAG_SPIN_YIELDS  20000
#define FRAG_SPIN_SLEEPS  40          // × 250 µs = 10 ms after the spin

// ── why the feeder outlives its last write ──────────────────────────
// `shutdown(wfd, SHUT_WR)` is how the reader is told there is nothing
// more coming, and on this kernel that message is *sometimes not
// delivered to a thread already asleep inside read()*. The state is
// set — a reader that re-enters read() gets 0 immediately — but the
// wakeup that should have ended the sleep in progress is lost. It is a
// race between the shutdown and the reader's descent into the sleep,
// so it needs both threads runnable at the same instant on a machine
// with something else to do: rare on an idle box, routine under
// `make test` beside a soak, where it hung the campaign until the
// 300-second no-progress deadline (docs/security/fuzzing.md §24, and
// docs/security/continuous-fuzzing.md §6 for how it was first seen).
//
// Measured on a 90-line model of this feeder: 61 lost wakeups in
// 320,000 deliveries across 16 concurrent processes, and in every one
// of the 61 the *next* read returned EOF at once.
//
// So the fix is not a better way to say EOF — the EOF is already said.
// It is to stop depending on a wakeup at all. After the shutdown the
// feeder stays alive until the reader tells it the delivery is over,
// and while it waits it prods the reading thread with a signal whose
// handler does nothing. The prod interrupts the sleep; the retry that
// every read path in the tree does on EINTR re-enters read(); read()
// re-reads the state and returns the EOF that was there all along. It
// repeats until the reader is done, so no interleaving can lose it —
// the reader always meets EOF or an error, never neither.
//
// SIGURG because nothing else in the tree uses it and its default
// disposition is to be ignored, so an unlucky stray delivery to some
// other thread costs nothing. The handler is installed without
// SA_RESTART: restarting the read is precisely what must not happen.
#define FRAG_KICK_SIG   SIGURG
#define FRAG_KICK_NS    (2 * 1000 * 1000)   // 2 ms between prods

struct frag_stream {
    int       rfd;                    // hand this to the code under test
    int       wfd;
    pthread_t th;
    int       threaded;

    const uint8_t   *bytes;
    size_t           n;
    struct frag_plan plan;

    volatile uint64_t real_boundaries;    // reader had drained: a true split
    volatile uint64_t missed_boundaries;  // wait expired: possibly coalesced
    volatile int      wr_error;

    // the reading thread, and the flag it raises when it has stopped
    // reading. Guarded by `lock`, so the feeder's wait for it is a
    // condition variable and not a poll: frag_close must not pay 2 ms
    // per fragmented case for a prod that is almost never needed.
    pthread_t       reader;
    pthread_mutex_t lock;
    pthread_cond_t  done_cv;
    int             reader_done;
    uint64_t        kicks;            // prods sent — a lost wakeup, counted
};

static void frag_kick_handler(int sig) { (void)sig; }

// Install the do-nothing handler once per process. Without SA_RESTART,
// so the signal ends the read() the reader is asleep in rather than
// resuming it underneath us.
static void frag_kick_arm(void)
{
    static int armed = 0;
    if (armed)
        return;
    armed = 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = frag_kick_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                  // deliberately not SA_RESTART
    sigaction(FRAG_KICK_SIG, &sa, NULL);
}

// Wait for the reader to finish, prodding it every FRAG_KICK_NS until
// it does. Normally the first wait is satisfied immediately — the EOF
// arrived, the reader returned, frag_close signalled — and not one
// signal is sent.
static void frag_kick_until_done(struct frag_stream *s)
{
    pthread_mutex_lock(&s->lock);
    while (!s->reader_done) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += FRAG_KICK_NS;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        int rc = pthread_cond_timedwait(&s->done_cv, &s->lock, &ts);
        if (rc == ETIMEDOUT && !s->reader_done) {
            pthread_kill(s->reader, FRAG_KICK_SIG);
            s->kicks++;
        }
    }
    pthread_mutex_unlock(&s->lock);
}

// Bytes still unread on `fd`. -1 if the kernel will not say.
static int frag_pending(int fd)
{
    int pend = 0;
    if (ioctl(fd, FIONREAD, &pend) != 0)
        return -1;
    return pend;
}

// Wait until the reader has taken everything sent so far. Returns 1 if
// it did (the next write is a real boundary), 0 if the wait expired.
static int frag_wait_drained(struct frag_stream *s)
{
    for (unsigned i = 0; i < FRAG_SPIN_YIELDS; i++) {
        int pend = frag_pending(s->rfd);
        if (pend == 0)
            return 1;
        if (pend < 0)
            return 0;
        sched_yield();
    }
    for (unsigned i = 0; i < FRAG_SPIN_SLEEPS; i++) {
        struct timespec ts = { 0, 250 * 1000 };
        nanosleep(&ts, NULL);
        if (frag_pending(s->rfd) == 0)
            return 1;
    }
    return 0;
}

static void frag_write_all(struct frag_stream *s, size_t off, size_t len)
{
    while (len) {
        ssize_t w = write(s->wfd, s->bytes + off, len);
        if (w <= 0) {                 // the reader closed, or the case is over
            s->wr_error = 1;
            return;
        }
        off += (size_t)w;
        len -= (size_t)w;
    }
}

static void *frag_feeder(void *arg)
{
    struct frag_stream *s = arg;
    size_t at = 0;
    for (unsigned i = 0; i <= s->plan.n_cuts; i++) {
        size_t end = (i == s->plan.n_cuts) ? s->n : s->plan.cut[i];
        if (i > 0) {
            if (frag_wait_drained(s)) s->real_boundaries++;
            else                      s->missed_boundaries++;
        }
        if (end > at)
            frag_write_all(s, at, end - at);
        at = end;
    }
    shutdown(s->wfd, SHUT_WR);        // EOF for anything the reader still wants
    frag_kick_until_done(s);          // ...and make sure it is heard
    return NULL;
}

// ── opening and closing a delivery ──────────────────────────────────
#define FRAG_SOCK_BUF (1 << 17)

// Deliver bytes[0, n) to a fresh socketpair according to `plan`, and
// return the read end. plan == NULL (or a plan with no cuts) writes the
// lot with one write() and needs no thread — that is the reference
// delivery every fragmented one is compared against. Either way the
// write end is shut down once the bytes are gone, so a reader asking
// for more than was sent meets EOF instead of blocking forever.
static int frag_open(struct frag_stream *s, const uint8_t *bytes, size_t n,
                     const struct frag_plan *plan)
{
    int sv[2];
    s->rfd = s->wfd = -1;
    s->threaded = 0;
    s->bytes = bytes;
    s->n = n;
    s->real_boundaries = s->missed_boundaries = 0;
    s->wr_error = 0;
    s->kicks = 0;
    s->reader = pthread_self();       // the thread about to do the reading
    s->reader_done = 0;
    pthread_mutex_init(&s->lock, NULL);
    pthread_cond_init(&s->done_cv, NULL);
    frag_kick_arm();
    if (plan) s->plan = *plan;
    else      { s->plan.n_cuts = 0; s->plan.shape = FRAG_SHAPE_WHOLE; }

    // Both failure paths below leave the mutex and condition variable
    // alive: every caller pairs a failed frag_open with a frag_close
    // anyway, and frag_close is where they are destroyed. Destroying
    // them here would leave that call locking freed state.
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    int sz = FRAG_SOCK_BUF;
    for (int i = 0; i < 2; i++) {
        setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
        setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    }
#ifdef SO_NOSIGPIPE
    int on = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif
    s->rfd = sv[0];
    s->wfd = sv[1];

    // The reference delivery is written and shut down before the reader
    // is handed the socket at all, so its EOF is already in the socket's
    // state when read() first looks: there is no wakeup to lose, and no
    // feeder to prod with.
    if (s->plan.n_cuts == 0) {
        frag_write_all(s, 0, n);
        shutdown(s->wfd, SHUT_WR);
        return 0;
    }
    if (pthread_create(&s->th, NULL, frag_feeder, s) != 0) {
        close(s->rfd); close(s->wfd);
        s->rfd = s->wfd = -1;
        return -1;
    }
    s->threaded = 1;
    return 0;
}

// The reader is done with the socket. Say so first — that is what ends
// the feeder's wait, whether it is still waiting to be told the EOF
// landed or has yet to reach that wait at all — then close the read end,
// which is what unblocks a feeder still writing to a reader that gave up
// early, then join. Every wait inside the feeder is bounded or ended
// here, so the join is too.
static void frag_close(struct frag_stream *s)
{
    pthread_mutex_lock(&s->lock);
    s->reader_done = 1;
    pthread_cond_signal(&s->done_cv);
    pthread_mutex_unlock(&s->lock);

    if (s->rfd >= 0) { close(s->rfd); s->rfd = -1; }
    if (s->threaded) { pthread_join(s->th, NULL); s->threaded = 0; }
    if (s->wfd >= 0) { close(s->wfd); s->wfd = -1; }

    pthread_cond_destroy(&s->done_cv);
    pthread_mutex_destroy(&s->lock);
}

// ── comparing two deliveries ────────────────────────────────────────
// The result of a delivery is whatever the campaign chose to record —
// return values, error codes, how many bytes came back — plus the
// destination buffer in full, poison and all. Both are compared with
// memcmp: "behaviour matches unsplit input" is not a summary, it is
// every byte the reader wrote and every value it returned.
//
// Reports the first differing byte, because "they differ" is not a bug
// report and the offset usually names the field.
static inline void frag_check_equal(struct fuzz_ctx *c,
                                    const void *whole, const void *split,
                                    size_t n, const char *what)
{
    const uint8_t *a = whole, *b = split;
    for (size_t i = 0; i < n; i++) {
        if (a[i] == b[i])
            continue;
        char msg[FUZZ_MSG_LEN];
        int k = snprintf(msg, sizeof msg,
                         "%s: fragmented delivery differs from whole at "
                         "byte %llu (0x%02x whole, 0x%02x split)",
                         what, (unsigned long long)i, a[i], b[i]);
        (void)k;
        fuzz_fail(c, msg);
        return;
    }
}

// The poison every destination buffer is filled with before a run, so
// that "wrote the same bytes" also covers bytes the reader had no
// business writing at all.
#define FRAG_POISON 0xA5

#endif // SARM_FRAG_COMMON_H
