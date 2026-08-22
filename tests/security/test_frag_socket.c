// sarm security tests — socket fragmentation of the read paths (Step 9)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_frag_socket.c
//
// Description: Steps 6-8 handed each parser a buffer that was already
//   full. That is the one thing the network never does. Step 9 puts
//   the bytes back on a socket and asks whether the answer depends on
//   how they arrived:
//
//     record       tls_read_record — the first read of the connection.
//                  Five header bytes decide how far the second read
//                  goes, and the split can land inside them.
//     prefilled    tls_read_record_prefilled — the same, for the
//                  ClientHello whose first bytes main.S already read.
//                  Two shortfall subtractions, both on wire-derived
//                  values, both fed a split that moves the boundary.
//     plain        transport_read in TRANSPORT_PLAIN mode — the
//                  staging buffer h2c reads frame headers and payloads
//                  out of. A span it serves must not depend on how the
//                  stream was chopped up underneath it.
//     tls          transport_read in TRANSPORT_TLS mode — the same
//                  question with a record layer in between: several
//                  records in one write, one record across several
//                  writes, and a header split down the middle.
//
//   Every case runs twice — the corpus item written whole, then the
//   same bytes written in pieces the case chose — and compares
//   everything observable: every return value, every error code, and
//   the whole destination buffer including the poison the reader was
//   supposed to leave alone. Equality is the invariant, so validity is
//   not required of the corpus: a record rejected for a bad version
//   must be rejected the same way, at the same point, however it
//   arrived.
//
//   What the two runs may legitimately differ in is internal staging
//   state — how much sits in plain_read_stage_buf when the last span
//   is served depends on the split, and is nobody's business but
//   transport_read's. So the comparison is of what a caller can see,
//   and the state each run starts from is reset to identical values
//   rather than compared at the end.
//
//   frag_common.h explains how a split is made real (the reader must
//   drain piece k before piece k+1 is written) and how the campaigns
//   prove it stayed real.
// ─────────────────────────────────────────────────────────────────────

#include "frag_common.h"

#include <string.h>

// ── the record layer's constants (src/tls/record/_constants.S) ──────
#define TLS_RECORD_HEADER_LEN   5
#define TLS_TAG_LEN             16

// The error codes a reader may report; the campaigns check the range
// rather than each value, since which one a malformed record earns is
// Step 6's subject, not this one's.
#define ERR_SHORT   1
#define ERR_BOUNDS  5

#define TRANSPORT_PLAIN 0
#define TRANSPORT_TLS   1

// ── reaching the assembly ───────────────────────────────────────────
// One convention, borrowed from test_fuzz_tls_handshake.c: arguments
// and results travel in a single uint64_t slot array addressed by one
// register operand. These callees clobber every register the allocator
// could otherwise hand out, and a per-argument operand exhausts it —
// the array costs exactly one, and it is the one register that must
// survive the call, so the compiler picks a callee-saved one.
#define SARM_CLOBBER \
    "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12", \
    "x13","x14","x15","x16","x17","x19","x20","x21","x22","x23","x24", \
    "x25","x26","x30", \
    "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11", \
    "v16","v17","v18","v19","v20","v21","cc","memory"

#define SARM_CALL(slots, body) \
    __asm__ volatile(body : : "r"(slots) : SARM_CLOBBER)

#define DEFINE_SYM(fn, name) \
    static inline void *fn(void) { void *p; \
        __asm__("adrp %0, " #name "@PAGE\n\tadd %0, %0, " #name "@PAGEOFF" \
                : "=r"(p)); return p; }

DEFINE_SYM(sym_transport_mode,   transport_mode)
DEFINE_SYM(sym_plain_stage_len,  plain_read_stage_len)
DEFINE_SYM(sym_plain_stage_pos,  plain_read_stage_pos)
DEFINE_SYM(sym_tls_stage_len,    tls_read_stage_len)
DEFINE_SYM(sym_tls_stage_pos,    tls_read_stage_pos)
DEFINE_SYM(sym_client_app_key,   tls_client_app_key)
DEFINE_SYM(sym_client_app_iv,    tls_client_app_iv)
DEFINE_SYM(sym_server_app_key,   tls_server_app_key)
DEFINE_SYM(sym_server_app_iv,    tls_server_app_iv)
DEFINE_SYM(sym_client_seq,       tls_client_seq)
DEFINE_SYM(sym_server_seq,       tls_server_seq)

// What one call to a record reader returns, in the order the doc
// comment lists it. Compared with memcmp, so it is deliberately a
// plain byte image with no padding to leave uninitialised.
struct rec_result {
    uint64_t carry, type, frag_off, frag_len, total;
};

static struct rec_result rec_read(int fd, uint8_t *buf, uint64_t cap)
{
    uint64_t a[8] = { (uint64_t)(unsigned)fd, (uint64_t)buf, cap, 0, 0, 0, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n"
        "ldr x2, [%0, #16]\n"
        "bl tls_read_record\n"
        "cset x9, cs\n"
        "stp x0, x1, [%0, #24]\n"
        "stp x2, x3, [%0, #40]\n"
        "str x9, [%0, #56]\n");
    struct rec_result o = { a[7], a[3], a[4] - (uint64_t)buf, a[5], a[6] };
    if (a[7])                       // failure: only the error code is defined
        o.type = a[3], o.frag_off = o.frag_len = o.total = 0;
    return o;
}

static struct rec_result rec_read_prefilled(int fd, uint8_t *buf, uint64_t cap,
                                            uint64_t have)
{
    uint64_t a[9] = { (uint64_t)(unsigned)fd, (uint64_t)buf, cap, have,
                      0, 0, 0, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n"
        "ldp x2, x3, [%0, #16]\n"
        "bl tls_read_record_prefilled\n"
        "cset x9, cs\n"
        "stp x0, x1, [%0, #32]\n"
        "stp x2, x3, [%0, #48]\n"
        "str x9, [%0, #64]\n");
    struct rec_result o = { a[8], a[4], a[5] - (uint64_t)buf, a[6], a[7] };
    if (a[8])
        o.type = a[4], o.frag_off = o.frag_len = o.total = 0;
    return o;
}

// transport_read: carry, plus x0 (0 on success, errno / TLS_RECORD_ERR_*
// on failure).
struct span_result { uint64_t carry, code; };

static struct span_result xport_read(int fd, uint8_t *buf, uint64_t len)
{
    uint64_t a[5] = { (uint64_t)(unsigned)fd, (uint64_t)buf, len, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n"
        "ldr x2, [%0, #16]\n"
        "bl transport_read\n"
        "cset x9, cs\n"
        "str x0, [%0, #24]\n"
        "str x9, [%0, #32]\n");
    struct span_result o = { a[4], a[3] };
    return o;
}

// tls_app_data_write — used only to build the corpus for the `tls`
// campaign: sealing under the server's application key at the server's
// sequence number, which the campaign then reads back as the client's
// by installing the same key material on both sides.
static uint64_t app_data_write(const uint8_t *pt, uint64_t len, uint8_t *out,
                               uint64_t *total)
{
    uint64_t a[5] = { (uint64_t)pt, len, (uint64_t)out, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n"
        "ldr x2, [%0, #16]\n"
        "bl tls_app_data_write\n"
        "cset x9, cs\n"
        "str x0, [%0, #24]\n"
        "str x9, [%0, #32]\n");
    *total = a[3];
    return a[4];
}

// ── outcome buckets ─────────────────────────────────────────────────
// Every campaign counts the same four things. The first two say the
// corpus still reaches both verdicts; the third says the splits were
// real splits and not writes the kernel coalesced behind our back — a
// suite that lost that property is testing nothing, so it is required.
enum {
    B_ACCEPT = 0,       // the reader accepted, identically both ways
    B_REJECT,           // the reader refused, identically both ways
    B_SPLIT,            // at least one boundary the reader really saw
    B_MISSED,           // a boundary whose drain-wait expired
    B_SHAPE_ONE,
    B_SHAPE_BYTES,
    B_SHAPE_RANDOM,
    B_SHAPE_HINTED
};

#define FRAG_BUCKETS \
    { "!accepted", "!rejected", "!real split boundaries", \
      "boundaries not confirmed", "shape: one cut", "shape: byte at a time", \
      "shape: random cuts", "shape: on the seams", 0 }

static void tally_delivery(struct fuzz_ctx *c, const struct frag_stream *s)
{
    if (s->real_boundaries)   fuzz_tally(c, B_SPLIT);
    if (s->missed_boundaries) fuzz_tally(c, B_MISSED);
    switch (s->plan.shape) {
    case FRAG_SHAPE_ONE:    fuzz_tally(c, B_SHAPE_ONE);    break;
    case FRAG_SHAPE_BYTES:  fuzz_tally(c, B_SHAPE_BYTES);  break;
    case FRAG_SHAPE_RANDOM: fuzz_tally(c, B_SHAPE_RANDOM); break;
    case FRAG_SHAPE_HINTED: fuzz_tally(c, B_SHAPE_HINTED); break;
    default: break;
    }
}

// ── corpus: one TLS record ──────────────────────────────────────────
// Structurally valid far more often than not: the question here is
// whether delivery changes the answer, and an input the parser throws
// out on its first byte does not exercise much of the reader. The
// lengths that do not match what was sent are kept because they are
// how a reader gets asked to wait for bytes that never come — and EOF
// mid-record must land the same way whether it follows one write or
// twenty.
#define REC_BODY_MAX 1200

static size_t gen_record(struct fuzz_rng *r, uint8_t *buf, size_t cap,
                         uint32_t *hints, unsigned *n_hints)
{
    uint64_t body = fuzz_chance(r, 8) ? fuzz_interesting_value(r)
                                      : fuzz_below(r, REC_BODY_MAX);
    if (body > REC_BODY_MAX) body = REC_BODY_MAX;
    if (body + TLS_RECORD_HEADER_LEN > cap)
        body = cap - TLS_RECORD_HEADER_LEN;

    buf[0] = fuzz_chance(r, 6) ? fuzz_u8(r) : (uint8_t)fuzz_range(r, 20, 23);
    if (fuzz_chance(r, 8)) { buf[1] = fuzz_u8(r); buf[2] = fuzz_u8(r); }
    else                   { buf[1] = 0x03; buf[2] = fuzz_chance(r, 4) ? 0x01 : 0x03; }

    // the length field: usually the truth, sometimes a claim about
    // bytes that are not there (EOF) or fewer than are (leftovers)
    uint64_t claim = body;
    if (fuzz_chance(r, 6)) {
        claim = fuzz_chance(r, 2) ? body + fuzz_range(r, 1, 64)
                                  : fuzz_below(r, body + 1);
    }
    buf[3] = (uint8_t)(claim >> 8);
    buf[4] = (uint8_t)claim;
    fuzz_fill_random(r, buf + TLS_RECORD_HEADER_LEN, body);

    unsigned nh = 0;
    for (unsigned i = 1; i <= TLS_RECORD_HEADER_LEN && nh < 8; i++)
        hints[nh++] = i;                        // inside and just past the header
    *n_hints = nh;
    return TLS_RECORD_HEADER_LEN + (size_t)body;
}

// ── campaign 1: tls_read_record ─────────────────────────────────────
#define REC_CAP_MAX (TLS_RECORD_HEADER_LEN + REC_BODY_MAX + 64)

static struct {
    struct guarded_buffer dst;
    uint8_t  wire[REC_CAP_MAX];
    uint8_t  snapshot[REC_CAP_MAX];
} g_rec;

static int rec_setup(struct fuzz_ctx *c)
{
    (void)c;
    return guard_alloc(&g_rec.dst, REC_CAP_MAX);
}

static void rec_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_rec.dst);
}

// One delivery: poison the destination, hand the reader a socket
// carrying `n` bytes cut according to `plan`, and record what came
// back. `cap` bytes of destination are used, placed flush against the
// guard page, so a reader that walks past what it was given faults
// here rather than in the server.
static struct rec_result rec_deliver(struct fuzz_ctx *c, size_t n,
                                     const struct frag_plan *plan,
                                     uint64_t cap, uint8_t *dst)
{
    memset(dst, FRAG_POISON, cap);
    struct frag_stream s;
    if (frag_open(&s, g_rec.wire, n, plan) != 0)
        fuzz_fail(c, "test bug: could not open the delivery socket");
    struct rec_result o = rec_read(s.rfd, dst, cap);
    frag_close(&s);
    tally_delivery(c, &s);
    return o;
}

static void rec_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    uint32_t hints[8];
    unsigned n_hints = 0;
    size_t n = gen_record(r, g_rec.wire, sizeof g_rec.wire, hints, &n_hints);

    uint64_t cap = fuzz_chance(r, 8)
                 ? fuzz_range(r, TLS_RECORD_HEADER_LEN, n + 1)  // sometimes too small
                 : REC_CAP_MAX;
    if (cap > REC_CAP_MAX) cap = REC_CAP_MAX;
    uint8_t *dst = g_rec.dst.data + g_rec.dst.size - cap;

    struct frag_plan plan;
    frag_plan_gen(r, n, hints, n_hints, &plan);

    struct rec_result whole = rec_deliver(c, n, NULL, cap, dst);
    memcpy(g_rec.snapshot, dst, cap);
    struct rec_result split = rec_deliver(c, n, &plan, cap, dst);

    frag_check_equal(c, &whole, &split, sizeof whole, "tls_read_record result");
    frag_check_equal(c, g_rec.snapshot, dst, cap, "tls_read_record buffer");

    if (whole.carry) {
        fuzz_tally(c, B_REJECT);
        FUZZ_CHECK(c, whole.type >= ERR_SHORT && whole.type <= ERR_BOUNDS,
                   "tls_read_record: failure with an error code outside "
                   "SHORT..BOUNDS");
    } else {
        fuzz_tally(c, B_ACCEPT);
    }
}

// ── campaign 2: tls_read_record_prefilled ───────────────────────────
// The prefill is the bytes main.S's accept-time read already took off
// the socket, so it is itself a fragmentation of the record: the split
// between "already in the buffer" and "still on the wire" is one cut,
// and the cuts the plan adds are the rest.
static void pre_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    uint32_t hints[8];
    unsigned n_hints = 0;
    size_t n = gen_record(r, g_rec.wire, sizeof g_rec.wire, hints, &n_hints);

    uint64_t cap = REC_CAP_MAX;
    uint8_t *dst = g_rec.dst.data + g_rec.dst.size - cap;

    uint64_t have = fuzz_chance(r, 3) ? 0 : fuzz_below(r, n + 1);
    if (have > cap) have = cap;
    size_t rest = n - (size_t)have;

    // cuts apply to what is left on the wire, so the hints move with it
    uint32_t rhints[8];
    unsigned n_rhints = 0;
    for (unsigned i = 0; i < n_hints; i++)
        if (hints[i] > have && hints[i] - have < rest)
            rhints[n_rhints++] = (uint32_t)(hints[i] - have);

    struct frag_plan plan;
    frag_plan_gen(r, rest, rhints, n_rhints, &plan);

    struct rec_result res[2];
    for (int pass = 0; pass < 2; pass++) {
        memset(dst, FRAG_POISON, cap);
        memcpy(dst, g_rec.wire, have);
        struct frag_stream s;
        if (frag_open(&s, g_rec.wire + have, rest, pass ? &plan : NULL) != 0)
            fuzz_fail(c, "test bug: could not open the delivery socket");
        res[pass] = rec_read_prefilled(s.rfd, dst, cap, have);
        frag_close(&s);
        tally_delivery(c, &s);
        if (pass == 0)
            memcpy(g_rec.snapshot, dst, cap);
    }

    frag_check_equal(c, &res[0], &res[1], sizeof res[0],
                     "tls_read_record_prefilled result");
    frag_check_equal(c, g_rec.snapshot, dst, cap,
                     "tls_read_record_prefilled buffer");

    if (res[0].carry) {
        fuzz_tally(c, B_REJECT);
        FUZZ_CHECK(c, res[0].type >= ERR_SHORT && res[0].type <= ERR_BOUNDS,
                   "tls_read_record_prefilled: failure with an error code "
                   "outside SHORT..BOUNDS");
    } else {
        fuzz_tally(c, B_ACCEPT);
        FUZZ_CHECK(c, res[0].frag_off == TLS_RECORD_HEADER_LEN,
                   "tls_read_record_prefilled: fragment pointer is not buf + 5");
    }
}

// ── campaigns 3 and 4: transport_read ───────────────────────────────
// The caller of transport_read asks for a span — 9 bytes of frame
// header, then however many bytes that header named — and neither the
// reads underneath nor, in TLS mode, the record boundaries have any
// reason to line up with it. What must never happen is that the answer
// changes when they line up differently.
#define STREAM_MAX   8192
#define WIRE_MAX     (STREAM_MAX + 64 * (TLS_RECORD_HEADER_LEN + TLS_TAG_LEN + 1))
#define SPANS_MAX    24

struct span_plan {
    uint32_t len[SPANS_MAX];
    unsigned n;
};

static void gen_spans(struct fuzz_rng *r, size_t stream_len,
                      struct span_plan *sp, uint32_t *hints, unsigned *n_hints)
{
    sp->n = (unsigned)fuzz_range(r, 1, SPANS_MAX);
    unsigned nh = 0;
    uint64_t at = 0;
    for (unsigned i = 0; i < sp->n; i++) {
        uint64_t len;
        switch (fuzz_below(r, 4)) {
        case 0:  len = fuzz_range(r, 1, 9); break;            // a frame header
        case 1:  len = fuzz_interesting_value(r) % 4096 + 1; break;
        default: len = fuzz_range(r, 1, 2048); break;
        }
        sp->len[i] = (uint32_t)len;
        at += len;
        if (at < stream_len && nh < 8)
            hints[nh++] = (uint32_t)at;      // the seam between two spans
    }
    *n_hints = nh;
}

// Sum of the spans, which is how much destination the case needs.
static size_t span_total(const struct span_plan *sp)
{
    size_t t = 0;
    for (unsigned i = 0; i < sp->n; i++)
        t += sp->len[i];
    return t;
}

static struct {
    struct guarded_buffer dst;
    uint8_t  wire[WIRE_MAX];
    uint8_t  plain[STREAM_MAX];
    uint8_t  snapshot[SPANS_MAX * 4096];
    struct span_result res[2][SPANS_MAX];
} g_tr;

#define TR_DST_MAX (SPANS_MAX * 4096)

static int tr_setup(struct fuzz_ctx *c)
{
    (void)c;
    return guard_alloc(&g_tr.dst, TR_DST_MAX);
}

static void tr_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_tr.dst);
}

// Run one delivery of `n` wire bytes through `sp->n` transport_read
// calls, filling res[] and the destination. `mode` selects which side
// of transport_read's dispatch is under test; both stage buffers are
// reset first, so the two runs of a case start from the same state.
static void tr_deliver(struct fuzz_ctx *c, uint64_t mode, size_t n,
                       const struct frag_plan *plan,
                       const struct span_plan *sp, uint8_t *dst,
                       struct span_result *res)
{
    memset(dst, FRAG_POISON, TR_DST_MAX);
    *(uint64_t *)sym_transport_mode()  = mode;
    *(uint64_t *)sym_plain_stage_len() = 0;
    *(uint64_t *)sym_plain_stage_pos() = 0;
    *(uint64_t *)sym_tls_stage_len()   = 0;
    *(uint64_t *)sym_tls_stage_pos()   = 0;
    *(uint64_t *)sym_client_seq()      = 0;

    struct frag_stream s;
    if (frag_open(&s, g_tr.wire, n, plan) != 0)
        fuzz_fail(c, "test bug: could not open the delivery socket");

    uint8_t *at = dst;
    for (unsigned i = 0; i < sp->n; i++) {
        res[i] = xport_read(s.rfd, at, sp->len[i]);
        at += sp->len[i];
        if (res[i].carry) {                 // the stream is over; the rest of
            for (unsigned j = i + 1; j < sp->n; j++)   // the spans are not run
                res[j].carry = res[j].code = UINT64_MAX;
            break;
        }
    }
    frag_close(&s);
    tally_delivery(c, &s);
}

static void tr_compare(struct fuzz_ctx *c, const struct span_plan *sp,
                       const uint8_t *dst, const char *what)
{
    frag_check_equal(c, g_tr.res[0], g_tr.res[1],
                     sp->n * sizeof g_tr.res[0][0], what);
    frag_check_equal(c, g_tr.snapshot, dst, TR_DST_MAX, what);
    if (g_tr.res[0][0].carry) fuzz_tally(c, B_REJECT);
    else                      fuzz_tally(c, B_ACCEPT);
}

// ── campaign 3: TRANSPORT_PLAIN ─────────────────────────────────────
static void plain_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = (size_t)fuzz_range(r, 1, STREAM_MAX);
    fuzz_fill_random(r, g_tr.wire, n);

    struct span_plan sp;
    uint32_t hints[8];
    unsigned n_hints = 0;
    gen_spans(r, n, &sp, hints, &n_hints);
    while (span_total(&sp) > TR_DST_MAX)
        sp.n--;

    struct frag_plan plan;
    frag_plan_gen(r, n, hints, n_hints, &plan);

    uint8_t *dst = g_tr.dst.data + g_tr.dst.size - TR_DST_MAX;

    tr_deliver(c, TRANSPORT_PLAIN, n, NULL, &sp, dst, g_tr.res[0]);
    memcpy(g_tr.snapshot, dst, TR_DST_MAX);
    tr_deliver(c, TRANSPORT_PLAIN, n, &plan, &sp, dst, g_tr.res[1]);

    tr_compare(c, &sp, dst, "transport_read (plain)");

    // Whatever it delivered must be the stream, in order: staging is
    // an optimisation, not a licence to reorder or duplicate bytes.
    size_t served = 0;
    for (unsigned i = 0; i < sp.n && !g_tr.res[0][i].carry; i++)
        served += sp.len[i];
    if (served > n)
        served = n;
    FUZZ_CHECK(c, memcmp(dst, g_tr.wire, served) == 0,
               "transport_read (plain): delivered bytes are not the stream");
}

// ── campaign 4: TRANSPORT_TLS ───────────────────────────────────────
// The corpus is a plaintext stream sealed into a sequence of
// application_data records. Reading it back needs the client's
// application key to be the one it was sealed under, so the case
// installs the same key and IV on both sides and resets the client
// sequence number before each run — the server's own key schedule
// (Phase 19) is Step 7's subject, not this one's.
static void tls_install_keys(struct fuzz_rng *r)
{
    uint8_t key[16], iv[12];
    fuzz_fill_random(r, key, sizeof key);
    fuzz_fill_random(r, iv, sizeof iv);
    memcpy(sym_client_app_key(), key, sizeof key);
    memcpy(sym_server_app_key(), key, sizeof key);
    memcpy(sym_client_app_iv(),  iv,  sizeof iv);
    memcpy(sym_server_app_iv(),  iv,  sizeof iv);
    *(uint64_t *)sym_client_seq() = 0;
    *(uint64_t *)sym_server_seq() = 0;
}

static void tls_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    tls_install_keys(r);

    size_t plain_len = (size_t)fuzz_range(r, 1, STREAM_MAX);
    fuzz_fill_random(r, g_tr.plain, plain_len);

    // seal the stream into 1..k records of independently chosen sizes
    uint32_t hints[8];
    unsigned n_hints = 0;
    size_t wire = 0, at = 0;
    while (at < plain_len && wire + TLS_RECORD_HEADER_LEN + TLS_TAG_LEN + 1
                             + 2048 <= WIRE_MAX) {
        uint64_t take = fuzz_chance(r, 16) ? 0 : fuzz_range(r, 1, 2048);
        if (take > plain_len - at) take = plain_len - at;
        uint64_t total = 0;
        if (app_data_write(g_tr.plain + at, take, g_tr.wire + wire, &total))
            fuzz_fail(c, "test bug: tls_app_data_write refused a fragment");
        if (n_hints < 8) hints[n_hints++] = (uint32_t)wire;          // record start
        if (n_hints < 8) hints[n_hints++] = (uint32_t)(wire + TLS_RECORD_HEADER_LEN);
        wire += (size_t)total;
        at   += (size_t)take;
    }
    plain_len = at;

    struct span_plan sp;
    uint32_t shints[8];
    unsigned n_shints = 0;
    gen_spans(r, plain_len, &sp, shints, &n_shints);
    while (span_total(&sp) > TR_DST_MAX)
        sp.n--;
    for (unsigned i = 0; i < n_shints && n_hints < 8; i++)
        hints[n_hints++] = shints[i];

    struct frag_plan plan;
    frag_plan_gen(r, wire, hints, n_hints, &plan);

    uint8_t *dst = g_tr.dst.data + g_tr.dst.size - TR_DST_MAX;

    tr_deliver(c, TRANSPORT_TLS, wire, NULL, &sp, dst, g_tr.res[0]);
    memcpy(g_tr.snapshot, dst, TR_DST_MAX);
    tr_deliver(c, TRANSPORT_TLS, wire, &plan, &sp, dst, g_tr.res[1]);

    tr_compare(c, &sp, dst, "transport_read (tls)");

    size_t served = 0;
    for (unsigned i = 0; i < sp.n && !g_tr.res[0][i].carry; i++)
        served += sp.len[i];
    if (served > plain_len)
        served = plain_len;
    FUZZ_CHECK(c, memcmp(dst, g_tr.plain, served) == 0,
               "transport_read (tls): delivered bytes are not the plaintext");
}

// ── campaigns ───────────────────────────────────────────────────────
// Case counts an order of magnitude below the Step 6-8 campaigns, and
// deliberately so: a case here is two full deliveries, a thread, and
// as many context switches as it has cuts — hundreds of microseconds,
// not hundreds of nanoseconds. The corpus does not need millions of
// cases either, because it is not searching for a rare input: the
// property under test fails for *every* input the moment a reader
// assumes one read per message.
static const struct fuzz_target g_targets[] = {
    { "record",    rec_case,   rec_setup, rec_teardown, 3000, 0, FRAG_BUCKETS },
    { "prefilled", pre_case,   rec_setup, rec_teardown, 3000, 0, FRAG_BUCKETS },
    { "plain",     plain_case, tr_setup,  tr_teardown,   800, 0, FRAG_BUCKETS },
    { "tls",       tls_case,   tr_setup,  tr_teardown,   400, 0, FRAG_BUCKETS },
};

int main(void)
{
    fuzz_disarm_harness_timeout();
    // A feeder whose reader gave up early gets EPIPE, not a signal:
    // "the reader stopped reading" is one of the outcomes under test.
    signal(SIGPIPE, SIG_IGN);

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  sarm — socket fragmentation (SECURITY.md Step 9)       ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  seed 0x%llx, x%llu cases\n",
           (unsigned long long)fuzz_seed(), (unsigned long long)fuzz_mult());

    TEST_SUITE("the read paths — whole delivery vs split delivery");
    for (size_t i = 0; i < sizeof g_targets / sizeof g_targets[0]; i++)
        fuzz_run(&g_targets[i]);

    test_summary();
    return 0;
}
