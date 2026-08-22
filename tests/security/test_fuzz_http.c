// sarm security tests — HTTP/1 request parsing fuzzing (Step 8)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_fuzz_http.c
//
// Description: Steps 6 and 7 fuzzed everything an attacker says before
//   the server knows who they are. This one fuzzes what they say
//   afterwards, which on a plaintext port is the first thing they say:
//   the HTTP/1 request header (threat-model.md §3.4). It is a
//   line-oriented text grammar parsed by hand in assembly, with six
//   routines walking the same attacker-supplied bytes with their own
//   cursors, and three fixed-size .bss buffers on the other side of it.
//
//   Six campaigns, each a generator plus the invariants that must hold
//   for every input it can produce:
//
//     header_end     parse_header_end against a reference: the index it
//                    returns must be the first "\r\n\r\n" and nothing
//                    else
//     header_field   get_header_field against a reference — the line
//                    walk, the ':' rule and the whitespace skip
//     request        the whole front door as child.S drives it:
//                    parse_header_end -> verify_http_version ->
//                    parse_request, checked against the output contract
//                    and the three buffers behind it
//     path           parse_path against a reference, over request lines
//                    built to hit slash collapsing, the query split and
//                    the 4096-byte cap
//     filters        decode_url -> check_path_safety ->
//                    check_path_traversal, the four filters that stand
//                    between a URL and a filename, each against a
//                    reference
//     range          parse_range over Range header values
//     keepalive      http1_should_keep_alive, where the smuggling
//                    question lives: a request carrying a body header
//                    must never keep the connection open
//
//   Two things make this target shaped differently from the TLS ones.
//
//   *The parsers do not all return.* parse_path, get_header_field and
//   verify_http_version answer some malformed inputs by tail-branching
//   to reply_status, which in the server writes a response and ends the
//   connection. A standalone harness has no connection, so it links its
//   own reply_status (below): it records the status and longjmps back
//   to the case loop. That turns "which inputs escape, with which
//   code" into an observable outcome instead of a process exit — the
//   escapes are tallied and the campaign fails if one stops happening.
//
//   *The output buffers are .bss, not the harness's to place.* A guard
//   page can sit after the input, and does: every request ends flush
//   against PROT_NONE, with exactly one accessible byte of slack for
//   the NUL child.S writes at buf[total_len]. But filename_buf,
//   query_buf and authority_buf are the server's own globals, so what
//   stands in for a guard there is a poison canary in the padding each
//   one carries past its documented bound, checked after every case.
// ─────────────────────────────────────────────────────────────────────

#include "fuzz_common.h"

#include <setjmp.h>
#include <string.h>

// ── the server's own constants (src/defs.S, src/config.S) ───────────
#define BUF_SIZE            16384
#define FILENAME_BUF_SIZE   4096
#define QUERY_BUF_SIZE      4096
#define AUTHORITY_BUF_SIZE  256

// The .bss allocations behind them, padded to 16-byte multiples exactly
// as src/parse/data.S computes them. The bytes between the documented
// bound and the end of the allocation are the canary.
#define FILENAME_ALLOC      4112    // (4096 + 1 + 15) & ~15
#define QUERY_ALLOC         4096
#define AUTHORITY_ALLOC     272     // (256 + 1 + 15) & ~15
#define RANGE_ALLOC         32      // (19 + 15) & ~15

#define DOCROOT             "www/"
#define DOCROOT_LEN         4
#define DEFAULT_FILE        "index.html"
#define DEFAULT_FILE_LEN    10

#define GET_ID      0
#define HEAD_ID     1
#define OPTIONS_ID  2
#define BREW_ID     3
#define UNKNOWN_ID  4

// src/defs.S REQ_* offsets into the `request` struct.
#define REQ_METHOD        0
#define REQ_PATH          8
#define REQ_PATH_LENGTH   16
#define REQ_QUERY         24
#define REQ_QUERY_LENGTH  32
#define REQ_AUTHORITY     40
#define REQ_STREAM_ID     48
#define REQUEST_SIZE      80

// ── the server's globals ────────────────────────────────────────────
extern uint8_t  request[REQUEST_SIZE]          __asm__("request");
extern uint8_t  filename_buf[FILENAME_ALLOC]   __asm__("filename_buf");
extern uint8_t  query_buf[QUERY_ALLOC]         __asm__("query_buf");
extern uint8_t  authority_buf[AUTHORITY_ALLOC] __asm__("authority_buf");
extern uint8_t  range_buf[RANGE_ALLOC]         __asm__("range_buf");

static uint64_t req_field(unsigned off)
{
    uint64_t v;
    memcpy(&v, request + off, sizeof v);
    return v;
}

// ── the escape hatch ────────────────────────────────────────────────
// Four of the routines under test do not return on every input: they
// `b reply_status` with a status code, which in the server writes the
// error page and then either returns to the handler or continues the
// keep-alive loop. Neither exists here, and neither is what is being
// tested. This reply_status — the only one in the link — records the
// code and unwinds back to the case loop, so the campaign sees an
// outcome rather than losing the process.
//
// The `flag` argument is the server's "return or continue" selector.
// Every escape from the parse module passes 0 (continue), which is
// precisely the path that never comes back, so it is recorded and
// otherwise ignored.
static jmp_buf   g_escape;
static int       g_escape_armed;
static uint64_t  g_escape_status;
static uint64_t  g_escape_flag;

void fuzz_reply_status(uint64_t status, uint64_t flag) __asm__("reply_status");
void fuzz_reply_status(uint64_t status, uint64_t flag)
{
    g_escape_status = status;
    g_escape_flag   = flag;
    if (!g_escape_armed)
        _exit(FUZZ_CHILD_INVARIANT);    // an escape from nowhere: a test bug
    g_escape_armed = 0;
    _longjmp(g_escape, 1);
}

// Every wrapper below runs its call under this hatch and reports
// `escaped` plus the status, so a routine that answers by branching to
// reply_status is an outcome the campaign can check rather than the end
// of the process. Results come back through a caller-supplied struct —
// memory, not registers — because that is what survives a longjmp.
#define ESCAPE_ARM()   (g_escape_status = 0, g_escape_flag = 0, \
                        g_escape_armed = 1, _setjmp(g_escape))
#define ESCAPE_DONE()  (g_escape_armed = 0)

// ── the routines under test ─────────────────────────────────────────
// Reached through inline asm, like the TLS suites, because the carry
// flag is how this tree reports "not found" and C cannot see it. The
// clobber lists are the union of each routine's documented clobbers and
// everything it calls: get_header_field reaches streqn_i, which uses
// NEON on names of 16 bytes and up.
#define HTTP_CLOBBER \
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x9", "x10", \
    "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24", "x25", \
    "x26", "x27", "x28", "x30", \
    "v0", "v1", "v2", "v3", "v4", "v5", "v16", "v17", "v18", \
    "cc", "memory"

// parse_header_end returns its answer in x1 alone.
struct hdrend_out { uint64_t idx; int escaped; uint64_t status; };

static void call_header_end(const uint8_t *b, uint64_t len,
                            struct hdrend_out *o)
{
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    uint64_t r1;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl parse_header_end\n"
        "mov %0, x1\n"
        : "=r"(r1)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    o->idx = r1;
}

struct field_out {
    uint64_t ptr, rem, carry;
    int escaped; uint64_t status;
};

static void call_header_field(const uint8_t *b, uint64_t len,
                              const char *name, uint64_t name_len,
                              struct field_out *o)
{
    memset(o, 0, sizeof *o);
    uint64_t a[4];
    a[0] = (uint64_t)b; a[1] = len; a[2] = (uint64_t)name; a[3] = name_len;
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    uint64_t r0, r1, c;
    __asm__ volatile(
        "ldp x0, x1, [%3]\n"
        "ldp x2, x3, [%3, #16]\n"
        "bl get_header_field\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "cset %2, cs\n"
        : "=r"(r0), "=r"(r1), "=r"(c)
        : "r"(a)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    o->ptr = r0; o->rem = r1; o->carry = c;
}

struct path_out {
    uint64_t path, path_len, query, query_len, carry;
    int escaped; uint64_t status;
};

static void call_parse_path(const uint8_t *b, uint64_t len, uint64_t dflt,
                            struct path_out *o)
{
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    uint64_t r0, r1, r2, r3, c;
    __asm__ volatile(
        "mov x0, %5\n"
        "mov x1, %6\n"
        "mov x2, %7\n"
        "bl parse_path\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "mov %2, x2\n"
        "mov %3, x3\n"
        "cset %4, cs\n"
        : "=r"(r0), "=r"(r1), "=r"(r2), "=r"(r3), "=r"(c)
        : "r"(b), "r"(len), "r"(dflt)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    o->path = r0; o->path_len = r1; o->query = r2; o->query_len = r3;
    o->carry = c;
}

struct req_out { uint64_t carry; int escaped; uint64_t status; };

static void call_verify_version(const uint8_t *b, uint64_t len,
                                struct req_out *o)
{
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    __asm__ volatile(
        "mov x0, %0\n"
        "mov x1, %1\n"
        "bl verify_http_version\n"
        :
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
}

static void call_parse_request(const uint8_t *b, uint64_t len,
                               struct req_out *o)
{
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    uint64_t c;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl parse_request\n"
        "cset %0, cs\n"
        : "=r"(c)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    o->carry = c;
}

struct range_out { uint64_t start, end, carry; int escaped; uint64_t status; };

static void call_parse_range(const uint8_t *b, uint64_t len,
                             struct range_out *o)
{
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return; }
    uint64_t r0, r1, c;
    __asm__ volatile(
        "mov x0, %3\n"
        "mov x1, %4\n"
        "bl parse_range\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "cset %2, cs\n"
        : "=r"(r0), "=r"(r1), "=r"(c)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    o->start = r0; o->end = r1; o->carry = c;
}

// decode_url decodes in place and returns (ptr, len) or (0, 0).
struct decode_out { uint64_t ptr, len; };

static void call_decode_url(uint8_t *b, uint64_t len, struct decode_out *o)
{
    uint64_t r0, r1;
    __asm__ volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl decode_url\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        : "=r"(r0), "=r"(r1)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    o->ptr = r0; o->len = r1;
}

static uint64_t call_path_safety(const uint8_t *b, uint64_t len)
{
    uint64_t r0;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl check_path_safety\n"
        "mov %0, x0\n"
        : "=r"(r0)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    return r0;
}

static uint64_t call_path_traversal(const uint8_t *b, uint64_t len)
{
    uint64_t r0;
    __asm__ volatile(
        "mov x0, %1\n"
        "mov x1, %2\n"
        "bl check_path_traversal\n"
        "mov %0, x0\n"
        : "=r"(r0)
        : "r"(b), "r"(len)
        : HTTP_CLOBBER);
    return r0;
}

static uint64_t call_keep_alive(const uint8_t *b, uint64_t len,
                                uint64_t method, uint64_t status,
                                struct req_out *o)
{
    uint64_t a[4];
    a[0] = (uint64_t)b; a[1] = len; a[2] = method; a[3] = status;
    memset(o, 0, sizeof *o);
    if (ESCAPE_ARM()) { o->escaped = 1; o->status = g_escape_status; return 0; }
    uint64_t r0;
    __asm__ volatile(
        "ldp x0, x1, [%1]\n"
        "ldp x2, x3, [%1, #16]\n"
        "bl http1_should_keep_alive\n"
        "mov %0, x0\n"
        : "=r"(r0)
        : "r"(a)
        : HTTP_CLOBBER);
    ESCAPE_DONE();
    return r0;
}

// ── the second implementation ───────────────────────────────────────
// Written from the assembly's control flow, not from RFC 9112: the
// question a differential can answer here is "does the parser do what
// its own module README says", and a reference written from the RFC
// would only re-report the places sarm deliberately accepts less than
// HTTP does. Each reference below names the file it mirrors.

// src/util/streqn_i.S: case-insensitive over n bytes, with a NUL in one
// input and not the other counting as a mismatch, and a NUL in both
// counting as the end of a match.
static int ref_streqn_i(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t x = a[i], y = b[i];
        if (x == 0 && y == 0) return 1;
        if (x == 0 || y == 0) return 0;
        if (x >= 'A' && x <= 'Z') x += 0x20;
        if (y >= 'A' && y <= 'Z') y += 0x20;
        if (x != y) return 0;
    }
    return 1;
}

// src/parse/parse_header_end.S. The assembly is a hand-rolled scan with
// a one-character restart on '\r', which is the correct KMP failure
// transition for this pattern — so the answer must be the first
// occurrence, and that is what this checks.
static uint64_t ref_header_end(const uint8_t *b, size_t len)
{
    for (size_t i = 0; i + 4 <= len; i++)
        if (b[i] == '\r' && b[i + 1] == '\n' &&
            b[i + 2] == '\r' && b[i + 3] == '\n')
            return (uint64_t)i + 4;
    return 0;
}

// src/parse/get_header_field.S. Three outcomes, and the third one is
// the interesting one: several malformed shapes are answered with 400
// rather than "not found".
enum { REF_ABSENT = 0, REF_FOUND = 1, REF_ESCAPE = 2 };

static int ref_header_field(const uint8_t *b, size_t len,
                            const char *name, size_t name_len,
                            size_t *value_off)
{
    size_t i = 0;
    for (;;) {
        if (i >= len) return REF_ABSENT;
        if (b[i] != '\r') { i++; continue; }
        i++;
        if (i >= len) return REF_ABSENT;
        if (b[i] != '\n') continue;         // lone '\r': rescan from here
        i++;                                 // start of the next line
        if (i >= len) return REF_ABSENT;
        if (b[i] == ' ' || b[i] == '\t') return REF_ESCAPE;  // obs-fold
        if (len - i < name_len) return REF_ABSENT;
        if (!ref_streqn_i(b + i, (const uint8_t *)name, name_len)) {
            i++;
            continue;
        }
        i += name_len;
        if (i >= len) return REF_ESCAPE;
        if (b[i] != ':') return REF_ESCAPE;  // a longer name with our prefix
        do {
            i++;
            if (i >= len) return REF_ESCAPE;
        } while (b[i] == ' ' || b[i] == '\t');
        *value_off = i;
        return REF_FOUND;
    }
}

// src/file/check_path_safety.S: printable ASCII only.
static int ref_path_safety(const uint8_t *b, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (b[i] <= 0x1F || b[i] >= 0x7F)
            return 0;
    return 1;
}

// src/file/check_path_traversal.S: a segment that is exactly ".." is
// rejected. Segments end at '/' or at a NUL, and the final segment is
// checked too.
static int ref_path_traversal(const uint8_t *b, size_t len)
{
    size_t dots = 0, chars = 0;
    for (size_t i = 0; i <= len; i++) {
        int at_end = (i == len);
        uint8_t c = at_end ? 0 : b[i];
        if (at_end || c == '/' || c == 0) {
            if (dots == chars && dots == 2) return 0;
            dots = chars = 0;
            continue;
        }
        chars++;
        if (c == '.') dots++;
    }
    return 1;
}

// src/file/decode_url.S. Two details the RFC does not have: the hex
// test folds with `orr w4, #0x20` before classifying, so 0x10 and 0x11
// pass as '0' and '1'; and a decoded NUL is a rejection rather than a
// byte.
static int ref_hex_val(uint8_t c, int *val)
{
    uint8_t f = (uint8_t)(c | 0x20);
    if (f < '0') return 0;
    if (f <= '9') { *val = f - '0'; return 1; }
    if (f < 'a') return 0;
    if (f > 'f') return 0;
    *val = f - 'a' + 10;
    return 1;
}

// Returns the decoded length, or -1 for a rejection. `out` may alias
// `in`, exactly as the real one decodes in place.
static long ref_decode_url(const uint8_t *in, size_t len, uint8_t *out)
{
    size_t i = 0, n = 0;
    size_t remaining = len;
    for (;;) {
        uint8_t c = in[i];
        if (c == 0) break;
        if (c != '%') {
            out[n++] = c;
            if (--remaining == 0) break;
            i++;
            continue;
        }
        if (remaining < 3) return -1;
        int hi, lo;
        if (!ref_hex_val(in[i + 1], &hi)) return -1;
        if (!ref_hex_val(in[i + 2], &lo)) return -1;
        int v = (hi << 4) | lo;
        if (v == 0) return -1;
        out[n++] = (uint8_t)v;
        if (remaining <= 3) break;
        remaining -= 3;
        i += 3;
    }
    return (long)n;
}

// src/parse/parse_path.S. The longest reference here, because it is the
// routine with the most state: a 17-byte window to find " /" or " *",
// a copy loop that collapses runs of '/', a query split that happens
// after the fact by rewriting what was already copied, and two escapes
// (400 for a malformed asterisk-form, 414 for either buffer filling).
enum {
    REF_PP_FAIL = 0,        // carry set, (0, 0, 0, 0)
    REF_PP_OK   = 1,
    REF_PP_400  = 2,
    REF_PP_414  = 3,
};

struct ref_path {
    uint8_t  name[FILENAME_ALLOC];
    size_t   name_len;
    uint8_t  query[QUERY_ALLOC];
    size_t   query_len;
    int      has_query;
};

static int ref_parse_path(const uint8_t *h, size_t len, int dflt,
                          struct ref_path *o)
{
    o->name_len = o->query_len = 0;
    o->has_query = 0;

    if (len < 17) return REF_PP_400;

    // Find the first '/' or '*' in h[0..16], and require the byte
    // before it to be a space — which is why "HTTP/1.1" does not match.
    size_t i = 0;
    uint8_t prev = 1;           // a non-space sentinel, as the asm has
    uint8_t c;
    for (;;) {
        c = h[i];
        if (c == '/' || c == '*') break;
        if (i == 16) return REF_PP_FAIL;
        if (c == 0) return REF_PP_FAIL;
        prev = c;
        i++;
    }
    if (prev != ' ') return REF_PP_FAIL;
    if (i + 1 >= len) return REF_PP_FAIL;

    if (c == '*') {
        if (i + 2 > len) return REF_PP_400;
        if (h[i + 1] != ' ') return REF_PP_400;
        o->name[0] = '*';
        o->name[1] = 0;
        o->name_len = 1;
        return REF_PP_OK;
    }

    memcpy(o->name, DOCROOT, DOCROOT_LEN);
    size_t src = 0;             // index into h, from just past the '/'
    size_t dst = DOCROOT_LEN;   // index into the filename
    size_t total = i + 1;       // bytes of h consumed, the length bound
    size_t qmark = 0;           // filename index just past the '?', or 0
    int    last_slash = 1;
    const uint8_t *p = h + i + 1;

    for (;;) {
        if (dst >= FILENAME_BUF_SIZE) return REF_PP_414;
        uint8_t b = p[src];
        if (b == 0) return REF_PP_FAIL;
        if (b == ' ') break;
        if (b == '\r' || b == '\n') return REF_PP_FAIL;

        int skip = 0;
        if (!qmark) {
            if (b == '/') {
                if (last_slash) skip = 1;
                last_slash = 1;
            } else {
                last_slash = 0;
            }
        }
        if (!skip) {
            if (b == '?' && !qmark)
                qmark = dst + 1;
            o->name[dst++] = b;
        }
        src++;
        total++;
        if (total >= len) return REF_PP_FAIL;
    }

    if (dst == DOCROOT_LEN) {
        // No filename at all: "GET / HTTP/1.1" and friends.
        if (dflt) {
            memcpy(o->name + DOCROOT_LEN, DEFAULT_FILE, DEFAULT_FILE_LEN);
            o->name[DOCROOT_LEN + DEFAULT_FILE_LEN] = 0;
            o->name_len = DOCROOT_LEN + DEFAULT_FILE_LEN;
        } else {
            o->name_len = DOCROOT_LEN;
        }
        return REF_PP_OK;       // qmark cannot be set here: '?' is copied
    }

    o->name[dst] = 0;
    o->name_len = dst;

    if (qmark) {
        size_t q = qmark, n = 0;
        while (q < o->name_len) {
            if (n >= QUERY_BUF_SIZE) return REF_PP_414;
            o->query[n++] = o->name[q];
            o->name[q] = 0;
            q++;
        }
        o->name[qmark - 1] = 0;
        o->name_len = qmark - 1;
        o->query_len = n;
        o->has_query = 1;
    }
    return REF_PP_OK;
}

// ── generation ──────────────────────────────────────────────────────
// Uniformly random bytes are almost never an HTTP request, and a corpus
// of them would test the first byte comparison a billion times. So most
// of what follows is a *structurally* plausible request, wrong only
// where the interesting decisions are: the token that selects the
// method, the 17-byte window the path scanner searches, the byte after
// the last '/', the eight bytes before the first CRLF, the header that
// decides whether a body follows, and the terminator that decides where
// the request ends. A mutation pass then puts some of the chaos back.

struct gen { uint8_t *buf; size_t cap; size_t len; };

static void g_put(struct gen *g, const void *p, size_t n)
{
    if (g->len + n > g->cap)
        n = g->cap - g->len;
    memcpy(g->buf + g->len, p, n);
    g->len += n;
}

static void g_str(struct gen *g, const char *s) { g_put(g, s, strlen(s)); }
static void g_byte(struct gen *g, uint8_t b)    { g_put(g, &b, 1); }

static void g_rand(struct gen *g, struct fuzz_rng *r, size_t n)
{
    for (size_t i = 0; i < n && g->len < g->cap; i++)
        g_byte(g, fuzz_u8(r));
}

// Bytes chosen to land on the comparisons the parsers actually make.
static uint8_t gen_token_byte(struct fuzz_rng *r)
{
    static const uint8_t interesting[] = {
        '/', '.', '?', '%', ' ', '\t', '\r', '\n', 0x00, ':', '*', '=',
        'a', 'A', 'z', '0', '9', '-', '_', 0x1F, 0x7F, 0x80, 0xFF,
    };
    if (fuzz_chance(r, 3))
        return interesting[fuzz_below(r, sizeof interesting)];
    return fuzz_u8(r);
}

static void gen_method(struct gen *g, struct fuzz_rng *r, int sane)
{
    if (sane) {
        static const char *ok[] = { "GET", "HEAD", "OPTIONS" };
        g_str(g, ok[fuzz_below(r, 3)]);
        return;
    }
    static const char *known[] = {
        "GET", "HEAD", "OPTIONS", "BREW", "POST", "PUT", "DELETE",
        "TRACE", "CONNECT", "PRI", "get", "Get", "GETX", "G", "",
        "GE", "HEA", "OPTION", "OPTIONSX", "BRE",
    };
    switch (fuzz_below(r, 16)) {
    case 0:
        g_rand(g, r, (size_t)fuzz_range(r, 0, 10));
        return;
    case 1: {                       // a long method token
        size_t n = (size_t)fuzz_range(r, 1, 40);
        for (size_t i = 0; i < n; i++)
            g_byte(g, 'A' + (uint8_t)fuzz_below(r, 26));
        return;
    }
    default:
        g_str(g, known[fuzz_below(r, sizeof known / sizeof known[0])]);
        return;
    }
}

// A path, in the shape the scanner cares about: what precedes the first
// '/', how many slashes run together, whether a '?' appears and where,
// and how long the whole thing is.
static void gen_path(struct gen *g, struct fuzz_rng *r, int sane)
{
    static const char *segs[] = {
        "index.html", "..", ".", "...", "foo..txt", "a", "%2e%2e%2f",
        "%2E%2E", "%00", "%", "%4", "%zz", "%20", "..%2f", "....//",
        "foo", "bar.css", "err", "www", "a%2fb", "%ff", "%7f",
    };

    if (fuzz_chance(r, sane ? 6 : 12)) {   // an over-long path: 4096 is a cliff
        size_t n = (size_t)fuzz_range(r, FILENAME_BUF_SIZE - 8,
                                      FILENAME_BUF_SIZE + 64);
        for (size_t i = 0; i < n; i++)
            g_byte(g, (uint8_t)(fuzz_chance(r, 8) ? '/' : 'a'));
        return;
    }

    uint64_t nseg = fuzz_range(r, 0, 5);
    for (uint64_t s = 0; s < nseg; s++) {
        uint64_t slashes = fuzz_chance(r, 4) ? fuzz_range(r, 2, 5) : 1;
        for (uint64_t k = 0; k < slashes; k++)
            g_byte(g, '/');
        if (fuzz_chance(r, 6)) {
            size_t n = (size_t)fuzz_range(r, 1, 8);
            for (size_t i = 0; i < n; i++)
                g_byte(g, gen_token_byte(r));
        } else {
            g_str(g, segs[fuzz_below(r, sizeof segs / sizeof segs[0])]);
        }
    }

    if (fuzz_chance(r, 4)) {            // a query string
        g_byte(g, '?');
        uint64_t n = fuzz_chance(r, 16)
                   ? fuzz_range(r, QUERY_BUF_SIZE - 4, QUERY_BUF_SIZE + 4)
                   : fuzz_range(r, 0, 24);
        for (uint64_t i = 0; i < n; i++)
            g_byte(g, fuzz_chance(r, 8) ? gen_token_byte(r)
                                        : (uint8_t)('a' + fuzz_below(r, 26)));
    }
}

static void gen_version(struct gen *g, struct fuzz_rng *r, int sane)
{
    if (sane) {
        g_str(g, fuzz_chance(r, 4) ? "HTTP/1.0" : "HTTP/1.1");
        return;
    }
    static const char *versions[] = {
        "HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.2", "HTTP/", "HTTP",
        "http/1.1", "HTTP/1.1 ", "HTTP/1.10", "HTTPS/1.1", "", "HTT",
        "HTTP/1.1\r", "hTtP/1.0",
    };
    if (fuzz_chance(r, 12)) {
        g_rand(g, r, (size_t)fuzz_range(r, 0, 12));
        return;
    }
    g_str(g, versions[fuzz_below(r, sizeof versions / sizeof versions[0])]);
}

// One header line, without its terminator. The menu is weighted towards
// the fields the server actually looks for, because those are the ones
// whose absence or presence changes what it does.
static void gen_header_line(struct gen *g, struct fuzz_rng *r)
{
    static const char *lines[] = {
        "Host: example.com",
        "host: example.com:8080",
        "HOST:example.com",
        "Host:",
        "Host:  \t  example.com",
        "Content-Length: 0",
        "Content-Length: 12",
        "content-length: 12",
        "Content-Length: 12\r\nContent-Length: 34",
        "Content-Lengths: 12",
        "Transfer-Encoding: chunked",
        "transfer-encoding: identity, chunked",
        "Connection: close",
        "Connection: keep-alive",
        "connection: Keep-Alive, TE",
        "Connection: closed",
        "Connection: keep-alives",
        "Connection: close, keep-alive",
        "Connection:",
        "Range: bytes=0-99",
        "Range: bytes=-100",
        "Range: bytes=100-",
        "range: bytes=99-0",
        "Range: bytes=",
        "Range: bytes=99999999999999999999-1",
        "Range: chars=0-1",
        "Accept: */*",
        "User-Agent: sarm-fuzz",
        "If-None-Match: \"abc\"",
        "Accept-Encoding: gzip",
        " obs-fold-continuation",
        "\tfolded",
        "NoColonHere",
        ":emptyname",
        "X: ",
    };

    switch (fuzz_below(r, 12)) {
    case 0: {                           // a random name and value
        size_t n = (size_t)fuzz_range(r, 1, 12);
        for (size_t i = 0; i < n; i++)
            g_byte(g, gen_token_byte(r));
        g_byte(g, ':');
        n = (size_t)fuzz_range(r, 0, 16);
        for (size_t i = 0; i < n; i++)
            g_byte(g, gen_token_byte(r));
        return;
    }
    case 1: {                           // a Host value around the
        // authority_buf bound: 256 bytes is where parse_request starts
        // truncating, and nothing else in the menu comes close to it.
        g_str(g, fuzz_chance(r, 2) ? "Host: " : "host:");
        size_t n = (size_t)fuzz_range(r, AUTHORITY_BUF_SIZE - 8,
                                      AUTHORITY_BUF_SIZE + 32);
        for (size_t i = 0; i < n; i++)
            g_byte(g, (uint8_t)('a' + fuzz_below(r, 26)));
        return;
    }
    case 3: {                           // a very long line
        size_t n = (size_t)fuzz_range(r, 200, 2000);
        g_str(g, "X-Long: ");
        for (size_t i = 0; i < n; i++)
            g_byte(g, (uint8_t)('a' + fuzz_below(r, 26)));
        return;
    }
    case 2: {                           // a known line with one byte edited
        const char *s = lines[fuzz_below(r, sizeof lines / sizeof lines[0])];
        size_t n = strlen(s);
        size_t at = g->len;
        g_str(g, s);
        if (n && g->len > at)
            fuzz_mutate_once(r, g->buf + at, g->len - at);
        return;
    }
    default:
        g_str(g, lines[fuzz_below(r, sizeof lines / sizeof lines[0])]);
        return;
    }
}

// The terminator, and what follows it. A request that never ends is as
// interesting as one that ends twice.
static void gen_terminator(struct gen *g, struct fuzz_rng *r)
{
    switch (fuzz_below(r, 16)) {
    case 0:  g_str(g, "\n\n");        break;    // no CRs at all
    case 1:  g_str(g, "\r\n");        break;    // half a terminator
    case 2:  g_str(g, "\r\r\n\r\n");  break;    // the restart case
    case 3:  g_str(g, "\r\n\r");      break;
    case 4:  break;                             // none: an unfinished header
    case 5:  g_str(g, "\r\n\r\n\r\n"); break;   // two in a row
    default: g_str(g, "\r\n\r\n");    break;
    }
    if (fuzz_chance(r, 8)) {                    // pipelined leftovers
        g_str(g, "GET /next HTTP/1.1\r\nHost: x\r\n\r\n");
    }
}

// A whole request. `cap` is what the caller can place; the generator
// never exceeds it, so a request built at the 16 KiB limit is truncated
// exactly the way the server's read loop truncates one.
static size_t gen_request(struct fuzz_rng *r, uint8_t *buf, size_t cap)
{
    struct gen g = { buf, cap, 0 };

    if (fuzz_chance(r, 12)) {                   // pure chaos
        g_rand(&g, r, (size_t)fuzz_below(r, 129));
        return g.len;
    }

    // Half the corpus is built on a skeleton the server will actually
    // accept — a known method, a version it recognises, a Host header
    // and a real terminator — and is hostile only in the path, the
    // query and the header block. Without that bias almost every case
    // dies at the version check, and the campaign would be a very
    // thorough test of one `b.ne`.
    const int sane = fuzz_chance(r, 2);

    gen_method(&g, r, sane);
    if (sane || !fuzz_chance(r, 24)) g_byte(&g, ' ');
    gen_path(&g, r, sane);
    if (sane || !fuzz_chance(r, 24)) g_byte(&g, ' ');
    gen_version(&g, r, sane);

    if (sane) {
        g_str(&g, "\r\n");
        g_str(&g, fuzz_chance(r, 8) ? "host:example.com"
                                    : "Host: example.com");
    }

    uint64_t nhdr = fuzz_chance(r, 8) ? fuzz_range(r, 6, 24)
                                      : fuzz_range(r, 0, 4);
    for (uint64_t i = 0; i < nhdr && g.len < g.cap; i++) {
        g_str(&g, "\r\n");
        gen_header_line(&g, r);
    }

    if (sane && !fuzz_chance(r, 8))
        g_str(&g, "\r\n\r\n");
    else
        gen_terminator(&g, r);

    if (fuzz_chance(r, sane ? 8 : 3))
        fuzz_mutate(r, g.buf, g.len);
    return g.len;
}

// ── placement ───────────────────────────────────────────────────────
// One mapping per campaign, reused: at a million cases a second an mmap
// per case would cost more than the parsers do.
#define REQ_MAX (BUF_SIZE + 1)

// The input ends flush against the guard: buf[len] traps. This is the
// placement for every routine whose contract is "read at most `len`
// bytes", which is all of them.
static uint8_t *place_flush(struct guarded_buffer *gb, const uint8_t *src,
                            size_t n)
{
    uint8_t *p = gb->data + gb->size - n;
    memcpy(p, src, n);
    return p;
}

// As above, but with the one accessible byte child.S puts there: the
// server NUL-terminates `buf` at the total number of bytes read, so
// buf[len] is a real byte and buf[len + 1] is not. Used by the campaign
// that drives the front door the way the server drives it.
static uint8_t *place_nul(struct guarded_buffer *gb, const uint8_t *src,
                          size_t n)
{
    uint8_t *p = gb->data + gb->size - n - 1;
    memcpy(p, src, n);
    p[n] = 0;
    return p;
}

// ── the .bss canaries ───────────────────────────────────────────────
// filename_buf, query_buf and authority_buf belong to the server, not
// to the harness, so they cannot be given a guard page. Each is
// allocated larger than the bound its writer enforces; the slack is
// filled with poison before every case and checked after, which catches
// a write past the documented bound the way the guard catches a read.
#define POISON 0xA5

static void canaries_arm(void)
{
    memset(filename_buf + FILENAME_BUF_SIZE + 1, POISON,
           FILENAME_ALLOC - FILENAME_BUF_SIZE - 1);
    memset(authority_buf + AUTHORITY_BUF_SIZE + 1, POISON,
           AUTHORITY_ALLOC - AUTHORITY_BUF_SIZE - 1);
    memset(range_buf + 19, POISON, RANGE_ALLOC - 19);
}

static int canaries_intact(void)
{
    for (size_t i = FILENAME_BUF_SIZE + 1; i < FILENAME_ALLOC; i++)
        if (filename_buf[i] != POISON) return 0;
    for (size_t i = AUTHORITY_BUF_SIZE + 1; i < AUTHORITY_ALLOC; i++)
        if (authority_buf[i] != POISON) return 0;
    for (size_t i = 19; i < RANGE_ALLOC; i++)
        if (range_buf[i] != POISON) return 0;
    return 1;
}

// ── campaign 1: parse_header_end ────────────────────────────────────
// Everything downstream is handed the index this routine returns, so an
// answer that is not the first "\r\n\r\n" is a request boundary in the
// wrong place — which is the shape a smuggling bug takes here.
enum { HE_FOUND = 0, HE_NONE };

static struct { struct guarded_buffer in; uint8_t *scratch; } g_he;

static int he_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_he.in, REQ_MAX) != 0)
        return -1;
    static uint8_t scratch[REQ_MAX];
    g_he.scratch = scratch;
    return 0;
}

static void he_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_he.in);
}

// The body from the request bytes on, so a preserved input runs the
// same invariants as a generated one (Step 14).
static void he_check(uint8_t *p, size_t n, struct fuzz_ctx *c)
{
    struct hdrend_out o;
    call_header_end(p, n, &o);

    FUZZ_CHECK(c, !o.escaped, "parse_header_end: escaped to reply_status");
    FUZZ_CHECK(c, o.idx == ref_header_end(p, n),
               "parse_header_end: index is not the first \\r\\n\\r\\n");
    if (o.idx) {
        FUZZ_CHECK(c, o.idx >= 4 && o.idx <= n,
                   "parse_header_end: index outside the buffer");
        FUZZ_CHECK(c, memcmp(p + o.idx - 4, "\r\n\r\n", 4) == 0,
                   "parse_header_end: index does not follow a terminator");
        fuzz_tally(c, HE_FOUND);
    } else {
        fuzz_tally(c, HE_NONE);
    }
}

static void he_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_he.scratch, REQ_MAX);
    fuzz_input(c, g_he.scratch, n);
    he_check(place_flush(&g_he.in, g_he.scratch, n), n, c);
}

static void he_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REQ_MAX) len = REQ_MAX;
    he_check(place_flush(&g_he.in, in, len), len, c);
}

// ── campaign 2: get_header_field ────────────────────────────────────
// Four callers depend on this one walk: the Host lookup in
// verify_http_version and parse_request, the two body-header lookups in
// http1_should_keep_alive, and the Range lookup. A field found where
// there is none — or missed where there is one — is a different request
// than the one on the wire.
enum { HF_FOUND = 0, HF_ABSENT, HF_ESCAPE };

static const char *const g_field_names[] = {
    "Host", "Content-Length", "Transfer-Encoding", "Connection", "range",
    "X", "Accept", "content-length", "CONNECTION", "If-None-Match",
};

static void hf_check(uint8_t *p, size_t n, const char *name, size_t name_len,
                     struct fuzz_ctx *c)
{
    size_t ref_off = 0;
    int expect = ref_header_field(p, n, name, name_len, &ref_off);

    struct field_out o;
    call_header_field(p, n, name, name_len, &o);

    if (o.escaped) {
        FUZZ_CHECK(c, expect == REF_ESCAPE,
                   "get_header_field: replied 400 where the reference did not");
        FUZZ_CHECK(c, o.status == 400,
                   "get_header_field: escaped with a status other than 400");
        fuzz_tally(c, HF_ESCAPE);
        return;
    }
    FUZZ_CHECK(c, expect != REF_ESCAPE,
               "get_header_field: returned where the reference replied 400");

    if (o.carry) {
        FUZZ_CHECK(c, expect == REF_ABSENT,
                   "get_header_field: missed a field the reference found");
        FUZZ_CHECK(c, o.ptr == 0 && o.rem == 0,
                   "get_header_field: not-found did not return (0, 0)");
        fuzz_tally(c, HF_ABSENT);
        return;
    }

    FUZZ_CHECK(c, expect == REF_FOUND,
               "get_header_field: found a field the reference did not");
    FUZZ_CHECK(c, o.ptr == (uint64_t)(p + ref_off),
               "get_header_field: value pointer is not where the reference "
               "puts it");
    FUZZ_CHECK(c, o.rem == n - ref_off,
               "get_header_field: remaining length is not (length - offset)");
    FUZZ_CHECK(c, o.ptr >= (uint64_t)p && o.ptr + o.rem == (uint64_t)(p + n),
               "get_header_field: value pointer outside the buffer");
    fuzz_tally(c, HF_FOUND);
}

static void hf_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_he.scratch, REQ_MAX);
    fuzz_input(c, g_he.scratch, n);
    const char *name = g_field_names[
        fuzz_below(r, sizeof g_field_names / sizeof g_field_names[0])];
    hf_check(place_flush(&g_he.in, g_he.scratch, n), n, name, strlen(name), c);
}

// A preserved input carries bytes, not the field that was being looked
// for; "Host" is the lookup every request reaches (verify_http_version
// and parse_request both make it) and is the one worth regressing.
static void hf_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REQ_MAX) len = REQ_MAX;
    hf_check(place_flush(&g_he.in, in, len), len, "Host", 4, c);
}

// ── campaign 3: the front door ──────────────────────────────────────
// child.S's sequence, exactly: find the header terminator, NUL-
// terminate the buffer at the total bytes read, verify the version,
// parse the request. The invariants are the ones the rest of the server
// then assumes without re-checking — that REQ_PATH points into
// filename_buf, is NUL-terminated inside it, starts with the docroot,
// survives all four path filters, and that REQ_AUTHORITY is a
// NUL-terminated copy of the Host value and not a pointer into the
// request.
enum {
    FD_SERVED = 0, FD_UNKNOWN, FD_PARSE_FAIL, FD_400, FD_414, FD_505,
    FD_NO_HEADER,
};

static struct { struct guarded_buffer in; uint8_t *scratch; } g_fd;

static int fd_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_fd.in, REQ_MAX + 1) != 0)
        return -1;
    static uint8_t scratch[REQ_MAX];
    g_fd.scratch = scratch;
    return 0;
}

static void fd_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_fd.in);
}

// The path the parser produced must survive the filters it claims to
// have applied. Re-run them here rather than trusting that they ran:
// the three of them are the whole of sarm's path policy.
static void check_path_contract(struct fuzz_ctx *c, const uint8_t *path,
                                uint64_t len)
{
    FUZZ_CHECK(c, (uint64_t)path == (uint64_t)filename_buf,
               "parse_request: REQ_PATH does not point at filename_buf");
    FUZZ_CHECK(c, len > 0 && len <= FILENAME_BUF_SIZE,
               "parse_request: REQ_PATH_LENGTH outside 1..4096");
    FUZZ_CHECK(c, filename_buf[len] == 0,
               "parse_request: REQ_PATH is not NUL-terminated at its length");
    FUZZ_CHECK(c, ref_path_safety(path, len),
               "parse_request: accepted a path with a byte outside 0x20-0x7E");
    FUZZ_CHECK(c, ref_path_traversal(path, len),
               "parse_request: accepted a path with a \"..\" segment");
    FUZZ_CHECK(c, len == 1
                  ? path[0] == '*'
                  : memcmp(path, DOCROOT, DOCROOT_LEN) == 0,
               "parse_request: accepted a path that is neither \"*\" nor "
               "docroot-prefixed");
}

static void fd_check(uint8_t *p, size_t n, struct fuzz_ctx *ctx)
{
    struct hdrend_out he;
    call_header_end(p, n, &he);
    if (he.idx == 0) {                  // child.S reads more, or replies 431
        fuzz_tally(ctx, FD_NO_HEADER);
        return;
    }
    const uint64_t hdr_len = he.idx;

    canaries_arm();
    memset(request, 0, REQUEST_SIZE);

    struct req_out v;
    call_verify_version(p, hdr_len, &v);
    if (v.escaped) {
        FUZZ_CHECK(ctx, v.status == 400 || v.status == 505,
                   "verify_http_version: escaped with a status other than "
                   "400 or 505");
        FUZZ_CHECK(ctx, canaries_intact(),
                   "verify_http_version: wrote past a request buffer");
        fuzz_tally(ctx, v.status == 505 ? FD_505 : FD_400);
        return;
    }

    struct req_out o;
    call_parse_request(p, hdr_len, &o);

    FUZZ_CHECK(ctx, canaries_intact(),
               "parse_request: wrote past filename_buf, authority_buf or "
               "range_buf");

    if (o.escaped) {
        FUZZ_CHECK(ctx, o.status == 400 || o.status == 414,
                   "parse_request: escaped with a status other than 400 "
                   "or 414");
        fuzz_tally(ctx, o.status == 414 ? FD_414 : FD_400);
        return;
    }
    if (o.carry) {
        fuzz_tally(ctx, FD_PARSE_FAIL);
        return;
    }

    const uint64_t method = req_field(REQ_METHOD);
    FUZZ_CHECK(ctx, method <= UNKNOWN_ID,
               "parse_request: method id outside GET..UNKNOWN");
    FUZZ_CHECK(ctx, req_field(REQ_STREAM_ID) == 0,
               "parse_request: HTTP/1 request left a nonzero stream id");

    if (method == BREW_ID || method == UNKNOWN_ID) {
        // These two are answered 418/501 without any path handling, so
        // the only claim is that nothing was parsed into the buffers.
        fuzz_tally(ctx, FD_UNKNOWN);
        return;
    }

    const uint8_t *path = (const uint8_t *)req_field(REQ_PATH);
    const uint64_t path_len = req_field(REQ_PATH_LENGTH);
    check_path_contract(ctx, path, path_len);

    const uint64_t query = req_field(REQ_QUERY);
    const uint64_t query_len = req_field(REQ_QUERY_LENGTH);
    if (query) {
        FUZZ_CHECK(ctx, query == (uint64_t)query_buf,
                   "parse_request: REQ_QUERY does not point at query_buf");
        FUZZ_CHECK(ctx, query_len <= QUERY_BUF_SIZE,
                   "parse_request: REQ_QUERY_LENGTH above query_buf_size");
    } else {
        FUZZ_CHECK(ctx, query_len == 0,
                   "parse_request: no query pointer but a nonzero length");
    }

    const uint64_t auth = req_field(REQ_AUTHORITY);
    if (auth) {
        FUZZ_CHECK(ctx, auth == (uint64_t)authority_buf,
                   "parse_request: REQ_AUTHORITY does not point at "
                   "authority_buf");
        // The copy is byte-for-byte, not a C string copy: a Host value
        // may contain NULs, and the loop stops only at '\r', at the end
        // of the header, or at the bound. So the expected length is
        // computed the same way rather than with strlen.
        size_t off = 0;
        int found = ref_header_field(p, hdr_len, "Host", 4, &off);
        FUZZ_CHECK(ctx, found == REF_FOUND,
                   "parse_request: an authority with no Host header");
        size_t want = 0;
        while (off + want < hdr_len && p[off + want] != '\r' &&
               want < AUTHORITY_BUF_SIZE)
            want++;
        FUZZ_CHECK(ctx, want <= AUTHORITY_BUF_SIZE,
                   "parse_request: authority longer than its bound");
        FUZZ_CHECK(ctx, authority_buf[want] == 0,
                   "parse_request: authority_buf is not NUL-terminated at "
                   "the end of the copy");
        FUZZ_CHECK(ctx, memcmp(authority_buf, p + off, want) == 0,
                   "parse_request: authority is not a copy of the Host value");
    }
    fuzz_tally(ctx, FD_SERVED);
}

static void fd_case(struct fuzz_rng *r, struct fuzz_ctx *ctx)
{
    size_t n = gen_request(r, g_fd.scratch, REQ_MAX - 1);
    fuzz_input(ctx, g_fd.scratch, n);
    fd_check(place_nul(&g_fd.in, g_fd.scratch, n), n, ctx);
}

static void fd_replay(const uint8_t *in, size_t len, struct fuzz_ctx *ctx)
{
    if (len > REQ_MAX - 1) len = REQ_MAX - 1;
    fd_check(place_nul(&g_fd.in, in, len), len, ctx);
}

// ── campaign 4: parse_path ──────────────────────────────────────────
// The routine with the most state in the module: a 17-byte window to
// find " /" or " *", a copy loop that collapses runs of '/' and stops
// at the first space, a query split that rewrites what it already
// copied, and two escapes. It is checked against a reference written
// from the same control flow, on request lines whose length is *not*
// tied to a header terminator — so the length argument itself is under
// test, not just the bytes.
//
// One byte of accessible slack sits between the input and the guard,
// and it is there deliberately. parse_path reads h[16] when it has
// found no '/' in the first sixteen bytes, and reads h[len] when the
// path runs to the end of the buffer without a space, a CR or a NUL —
// both one past the length argument, both unreachable from the server
// (child.S NUL-terminates buf, and a header always ends "\r\n\r\n" so
// the copy loop stops before the terminator). The slack models that
// NUL byte; the poison in it is a value none of the parser's
// comparisons treat specially, so a read that lands there changes the
// answer and the reference catches it.
enum { PP_OK = 0, PP_FAIL, PP_400, PP_414 };

static struct {
    struct guarded_buffer in;
    uint8_t             *scratch;
    struct ref_path     *ref;
} g_pp;

static int pp_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_pp.in, REQ_MAX + 1) != 0)
        return -1;
    static uint8_t scratch[REQ_MAX];
    static struct ref_path ref;
    g_pp.scratch = scratch;
    g_pp.ref = &ref;
    return 0;
}

static void pp_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_pp.in);
}

// The body from the request-line bytes on. This is the campaign that
// found the three reads past the length argument of §16, and a
// byte-level replay is what keeps that input a regression test after
// gen_request changes (Step 14).
static void pp_check(uint8_t *p, size_t n, uint64_t dflt, struct fuzz_ctx *c)
{
    canaries_arm();

    int expect = ref_parse_path(p, n, (int)dflt, g_pp.ref);

    struct path_out o;
    call_parse_path(p, n, dflt, &o);

    FUZZ_CHECK(c, canaries_intact(),
               "parse_path: wrote past filename_buf or query_buf");

    if (o.escaped) {
        FUZZ_CHECK(c, o.status == 400 || o.status == 414,
                   "parse_path: escaped with a status other than 400 or 414");
        FUZZ_CHECK(c, expect == (o.status == 400 ? REF_PP_400 : REF_PP_414),
                   "parse_path: escaped where the reference did not, or with "
                   "a different status");
        fuzz_tally(c, o.status == 400 ? PP_400 : PP_414);
        return;
    }
    FUZZ_CHECK(c, expect != REF_PP_400 && expect != REF_PP_414,
               "parse_path: returned where the reference escaped");

    if (o.carry) {
        FUZZ_CHECK(c, expect == REF_PP_FAIL,
                   "parse_path: rejected a request line the reference "
                   "accepted");
        FUZZ_CHECK(c, o.path == 0 && o.path_len == 0 &&
                      o.query == 0 && o.query_len == 0,
                   "parse_path: failure did not return (0, 0, 0, 0)");
        fuzz_tally(c, PP_FAIL);
        return;
    }

    FUZZ_CHECK(c, expect == REF_PP_OK,
               "parse_path: accepted a request line the reference rejected");
    FUZZ_CHECK(c, o.path == (uint64_t)filename_buf,
               "parse_path: filename does not point at filename_buf");
    FUZZ_CHECK(c, o.path_len == g_pp.ref->name_len,
               "parse_path: filename length differs from the reference");
    FUZZ_CHECK(c, o.path_len <= FILENAME_BUF_SIZE,
               "parse_path: filename length above filename_buf_size");
    FUZZ_CHECK(c, memcmp(filename_buf, g_pp.ref->name, o.path_len) == 0,
               "parse_path: filename bytes differ from the reference");
    FUZZ_CHECK(c, filename_buf[o.path_len] == 0 ||
                  (o.path_len == DOCROOT_LEN && !dflt),
               "parse_path: filename is not NUL-terminated at its length");

    if (g_pp.ref->has_query) {
        FUZZ_CHECK(c, o.query == (uint64_t)query_buf,
                   "parse_path: query does not point at query_buf where the "
                   "reference found one");
        FUZZ_CHECK(c, o.query_len == g_pp.ref->query_len,
                   "parse_path: query length differs from the reference");
        FUZZ_CHECK(c, o.query_len <= QUERY_BUF_SIZE,
                   "parse_path: query length above query_buf_size");
        FUZZ_CHECK(c, memcmp(query_buf, g_pp.ref->query, o.query_len) == 0,
                   "parse_path: query bytes differ from the reference");
    } else {
        FUZZ_CHECK(c, o.query == 0 && o.query_len == 0,
                   "parse_path: returned a query where the reference found "
                   "none");
    }
    fuzz_tally(c, PP_OK);
}

static void pp_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_pp.scratch, REQ_MAX - 1);

    // Most of the time the length is the whole generated request; the
    // rest of the time it is cut short, including at exactly 16, the
    // boundary the routine's first comparison tests.
    if (fuzz_chance(r, 4)) {
        uint64_t cut = fuzz_chance(r, 3) ? fuzz_range(r, 14, 20)
                                         : fuzz_below(r, n + 1);
        if (cut < n) n = (size_t)cut;
    }

    fuzz_input(c, g_pp.scratch, n);
    const uint64_t dflt = fuzz_chance(r, 2) ? 1 : 0;
    pp_check(place_flush(&g_pp.in, g_pp.scratch, n), n, dflt, c);
}

// The truncation the generator applies is already baked into a
// preserved input — its length is the length that failed. The
// "default file" knob is not, and it replays both ways, because a
// finding that only shows up under one of them is still a finding.
static void pp_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REQ_MAX - 1) len = REQ_MAX - 1;
    pp_check(place_flush(&g_pp.in, in, len), len, 0, c);
    pp_check(place_flush(&g_pp.in, in, len), len, 1, c);
}

// ── campaign 5: the path filters ────────────────────────────────────
// decode_url -> check_path_safety -> check_path_traversal, in that
// order, is the whole of sarm's path policy (threat-model.md §3.4), and
// the order is load-bearing: decoding first is what makes %2e%2e%2f a
// traversal rather than a filename. Each is checked against a
// reference, and then the composition is checked for the property the
// policy exists to provide.
enum { PF_DECODED = 0, PF_REJECTED, PF_UNSAFE, PF_TRAVERSAL };

static struct {
    struct guarded_buffer in;
    uint8_t              *scratch;
    uint8_t              *before;
    uint8_t              *refout;
} g_pf;

static int pf_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_pf.in, REQ_MAX + 1) != 0)
        return -1;
    static uint8_t scratch[REQ_MAX], before[REQ_MAX], refout[REQ_MAX];
    g_pf.scratch = scratch;
    g_pf.before  = before;
    g_pf.refout  = refout;
    return 0;
}

static void pf_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_pf.in);
}

// A URL-shaped string: escapes that decode, escapes that do not, dots,
// slashes and raw bytes. Never zero-length — decode_url's loop reads
// its first byte before consulting the length, so a caller passing 0
// walks memory until it meets a NUL, and every caller in the tree
// passes a length of at least four (see docs/security/fuzzing.md).
static size_t gen_url(struct fuzz_rng *r, uint8_t *buf, size_t cap)
{
    struct gen g = { buf, cap, 0 };
    if (fuzz_chance(r, 8)) {
        g_rand(&g, r, (size_t)fuzz_range(r, 1, 64));
        return g.len ? g.len : (g_byte(&g, 'a'), g.len);
    }
    g_str(&g, DOCROOT);
    gen_path(&g, r, 0);
    if (fuzz_chance(r, 3))
        fuzz_mutate(r, g.buf, g.len);
    if (g.len == 0)
        g_byte(&g, 'a');
    return g.len;
}

// Placing the URL is part of the case: decode_url rewrites its input in
// place, so the reference needs a copy of the bytes taken before the
// call, and p[n] is the one accessible byte past the length that the
// server really does put there.
static uint8_t *pf_place(const uint8_t *src, size_t n)
{
    uint8_t *p = g_pf.in.data + g_pf.in.size - n - 1;
    memcpy(p, src, n);
    p[n] = POISON;              // decode_url NUL-terminates at out[len]
    memcpy(g_pf.before, p, n);
    return p;
}

static void pf_check(uint8_t *p, size_t n, struct fuzz_ctx *c)
{
    long want = ref_decode_url(g_pf.before, n, g_pf.refout);

    struct decode_out d;
    call_decode_url(p, n, &d);

    if (want < 0) {
        FUZZ_CHECK(c, d.ptr == 0 && d.len == 0,
                   "decode_url: accepted an escape the reference rejected");
        fuzz_tally(c, PF_REJECTED);
        return;
    }
    FUZZ_CHECK(c, d.ptr == (uint64_t)p,
               "decode_url: rejected input the reference decoded, or moved "
               "the pointer");
    FUZZ_CHECK(c, d.len == (uint64_t)want,
               "decode_url: decoded length differs from the reference");
    FUZZ_CHECK(c, d.len <= n,
               "decode_url: decoded more bytes than it was given");
    FUZZ_CHECK(c, memcmp(p, g_pf.refout, d.len) == 0,
               "decode_url: decoded bytes differ from the reference");
    FUZZ_CHECK(c, p[d.len] == 0,
               "decode_url: did not NUL-terminate at the decoded length");
    for (uint64_t i = 0; i < d.len; i++)
        FUZZ_CHECK(c, p[i] != 0,
                   "decode_url: a NUL byte survived into the decoded path");

    const uint64_t safe = call_path_safety(p, d.len);
    FUZZ_CHECK(c, safe == (uint64_t)ref_path_safety(p, d.len),
               "check_path_safety: verdict differs from the reference");
    if (!safe) {
        fuzz_tally(c, PF_UNSAFE);
        return;
    }

    const uint64_t clean = call_path_traversal(p, d.len);
    FUZZ_CHECK(c, clean == (uint64_t)ref_path_traversal(p, d.len),
               "check_path_traversal: verdict differs from the reference");
    if (!clean) {
        fuzz_tally(c, PF_TRAVERSAL);
        return;
    }

    // What the three of them together are for: whatever survives has no
    // segment that is exactly "..", however it was spelled on the wire.
    size_t seg = 0, dots = 0;
    for (uint64_t i = 0; i <= d.len; i++) {
        if (i == d.len || p[i] == '/') {
            FUZZ_CHECK(c, !(seg == 2 && dots == 2),
                       "the path filters: a \"..\" segment survived all "
                       "three of them");
            seg = dots = 0;
            continue;
        }
        seg++;
        if (p[i] == '.') dots++;
    }
    fuzz_tally(c, PF_DECODED);
}

static void pf_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_url(r, g_pf.scratch, 512);
    fuzz_input(c, g_pf.scratch, n);
    pf_check(pf_place(g_pf.scratch, n), n, c);
}

static void pf_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > 512) len = 512;
    pf_check(pf_place(in, len), len, c);
}

// ── campaign 6: parse_range ─────────────────────────────────────────
// The one place an HTTP/1 header value becomes an integer. Two numbers
// are copied into a 19-byte buffer and handed to atoi_n, and the result
// later indexes into an embedded file, so "which values does it accept"
// is a memory-safety question one layer down.
enum { RG_OK = 0, RG_NONE, RG_ESCAPE };

// Mirrors src/parse/parse_range.S over the value get_header_field
// returns. -1 in a bound is the open-ended form ("bytes=-100").
struct ref_range { int64_t start, end; };

static int ref_range(const uint8_t *b, size_t len, struct ref_range *o,
                     int *escaped)
{
    *escaped = 0;
    size_t off = 0;
    int found = ref_header_field(b, len, "range", 5, &off);
    if (found == REF_ESCAPE) { *escaped = 1; return 0; }
    if (found != REF_FOUND) return 0;

    const uint8_t *v = b + off;
    size_t rem = len - off;
    if (5 >= rem) return 0;
    if (!ref_streqn_i(v, (const uint8_t *)"bytes", 5)) return 0;
    if (v[5] != '=') return 0;

    size_t i = 6;
    if (i >= rem) return 0;

    char digits[20];
    size_t n = 0;
    for (;;) {                          // the start of the range
        uint8_t c = v[i];
        if (c == '-') break;
        if (c < '0' || c > '9') return 0;
        digits[n++] = (char)c;
        if (n >= 19) return 0;
        i++;
        if (i >= rem) return 0;
    }
    int64_t start = -1;
    if (n) {
        start = 0;
        for (size_t k = 0; k < n; k++)
            start = start * 10 + (digits[k] - '0');
    }

    n = 0;
    for (;;) {                          // the end of the range
        i++;
        if (i >= rem) return 0;
        uint8_t c = v[i];
        if (c == '\r') break;
        if (c < '0' || c > '9') return 0;
        digits[n++] = (char)c;
        if (n >= 19) return 0;
    }
    int64_t end = -1;
    if (n) {
        end = 0;
        for (size_t k = 0; k < n; k++)
            end = end * 10 + (digits[k] - '0');
    }

    if (start == -1 && end == -1) return 0;
    if (start != -1 && end != -1 && start > end) return 0;
    o->start = start;
    o->end = end;
    return 1;
}

static void rg_check(uint8_t *p, size_t n, struct fuzz_ctx *c)
{
    canaries_arm();
    struct ref_range want = { 0, 0 };
    int want_escape = 0;
    int want_ok = ref_range(p, n, &want, &want_escape);

    struct range_out o;
    call_parse_range(p, n, &o);

    FUZZ_CHECK(c, canaries_intact(), "parse_range: wrote past range_buf");

    if (o.escaped) {
        FUZZ_CHECK(c, want_escape,
                   "parse_range: replied 400 where the reference did not");
        FUZZ_CHECK(c, o.status == 400,
                   "parse_range: escaped with a status other than 400");
        fuzz_tally(c, RG_ESCAPE);
        return;
    }
    FUZZ_CHECK(c, !want_escape,
               "parse_range: returned where the reference replied 400");

    if (o.carry) {
        FUZZ_CHECK(c, !want_ok,
                   "parse_range: rejected a range the reference accepted");
        FUZZ_CHECK(c, o.start == 0 && o.end == 0,
                   "parse_range: failure did not return (0, 0)");
        fuzz_tally(c, RG_NONE);
        return;
    }

    FUZZ_CHECK(c, want_ok,
               "parse_range: accepted a range the reference rejected");
    FUZZ_CHECK(c, (int64_t)o.start == want.start,
               "parse_range: start differs from the reference");
    FUZZ_CHECK(c, (int64_t)o.end == want.end,
               "parse_range: end differs from the reference");
    FUZZ_CHECK(c, (int64_t)o.start == -1 || (int64_t)o.end == -1 ||
                  (int64_t)o.start <= (int64_t)o.end,
               "parse_range: accepted a range whose start is past its end");
    fuzz_tally(c, RG_OK);
}

static void rg_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_he.scratch, REQ_MAX);
    fuzz_input(c, g_he.scratch, n);
    rg_check(place_flush(&g_he.in, g_he.scratch, n), n, c);
}

static void rg_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REQ_MAX) len = REQ_MAX;
    rg_check(place_flush(&g_he.in, in, len), len, c);
}

// ── campaign 7: keep-alive, and the smuggling question ──────────────
// threat-model.md §7.3 argues that request smuggling is out of scope
// structurally rather than by careful parsing: sarm never reads a body,
// so it closes the connection rather than guess where the next request
// starts. That argument is only as good as one predicate, and §7.3 says
// Step 8 should confirm it rather than assume it. This campaign is that
// confirmation — the whole rule from src/http1/README.md, as an iff.
enum { KA_KEEP = 0, KA_CLOSE_BODY, KA_CLOSE_CONN, KA_CLOSE_VERSION,
       KA_CLOSE_OTHER, KA_ESCAPE };

enum { CONN_ABSENT = 0, CONN_KEEPALIVE = 1, CONN_CLOSE = 2 };

// The Connection header's value, classified the way keep_alive.S
// classifies it: a token match followed by end-of-value or one of the
// five delimiters it accepts.
static int ref_conn_token(const uint8_t *v, size_t rem)
{
    static const struct { const char *tok; size_t len; int verdict; } toks[] = {
        { "close",      5,  CONN_CLOSE },
        { "keep-alive", 10, CONN_KEEPALIVE },
    };
    for (unsigned t = 0; t < 2; t++) {
        size_t l = toks[t].len;
        if (rem < l) continue;
        if (!ref_streqn_i(v, (const uint8_t *)toks[t].tok, l)) continue;
        if (rem == l) return toks[t].verdict;
        uint8_t d = v[l];
        if (d == '\r' || d == ' ' || d == '\t' || d == ';' || d == ',')
            return toks[t].verdict;
    }
    return CONN_ABSENT;
}

static int ref_keep_alive(const uint8_t *b, size_t len, uint64_t method,
                          uint64_t status, int *escaped, unsigned *why)
{
    *escaped = 0;
    *why = KA_CLOSE_OTHER;
    if (len == 0) return 0;
    if (method != GET_ID && method != HEAD_ID && method != OPTIONS_ID)
        return 0;
    if (status == 400 || status == 408 || status == 413 ||
        status == 431 || status == 500)
        return 0;

    size_t off = 0;
    int f = ref_header_field(b, len, "Content-Length", 14, &off);
    if (f == REF_ESCAPE) { *escaped = 1; return 0; }
    if (f == REF_FOUND) { *why = KA_CLOSE_BODY; return 0; }
    f = ref_header_field(b, len, "Transfer-Encoding", 17, &off);
    if (f == REF_ESCAPE) { *escaped = 1; return 0; }
    if (f == REF_FOUND) { *why = KA_CLOSE_BODY; return 0; }

    // HTTP/1.0 is decided by the eight bytes before the first '\r'
    // anywhere in the header — not by parsing the request line.
    int is_10 = 0;
    size_t cr = 0;
    while (cr < len && b[cr] != '\r')
        cr++;
    if (cr < len && cr >= 8)
        is_10 = ref_streqn_i(b + cr - 8, (const uint8_t *)"HTTP/1.0", 8);

    int conn = CONN_ABSENT;
    f = ref_header_field(b, len, "Connection", 10, &off);
    if (f == REF_ESCAPE) { *escaped = 1; return 0; }
    if (f == REF_FOUND)
        conn = ref_conn_token(b + off, len - off);

    if (conn == CONN_CLOSE) { *why = KA_CLOSE_CONN; return 0; }
    if (!is_10) { *why = KA_KEEP; return 1; }
    if (conn == CONN_KEEPALIVE) { *why = KA_KEEP; return 1; }
    *why = KA_CLOSE_VERSION;
    return 0;
}

static void ka_check(uint8_t *p, uint64_t hdr, uint64_t method,
                     uint64_t status, struct fuzz_ctx *c)
{
    int want_escape = 0;
    unsigned why = 0;
    int want = ref_keep_alive(p, (size_t)hdr, method, status,
                              &want_escape, &why);

    struct req_out esc;
    uint64_t got = call_keep_alive(p, hdr, method, status, &esc);

    if (esc.escaped) {
        FUZZ_CHECK(c, want_escape,
                   "http1_should_keep_alive: replied 400 where the reference "
                   "did not");
        fuzz_tally(c, KA_ESCAPE);
        return;
    }
    FUZZ_CHECK(c, !want_escape,
               "http1_should_keep_alive: returned where the reference "
               "replied 400");
    FUZZ_CHECK(c, got == 0 || got == 1,
               "http1_should_keep_alive: returned something other than 0 or 1");
    FUZZ_CHECK(c, got == (uint64_t)want,
               "http1_should_keep_alive: verdict differs from the rule in "
               "src/http1/README.md");

    if (got) {
        // The claim §7.3 rests on, stated on its own so a failure names
        // it: nothing that carries a body header may stay open.
        size_t off = 0;
        FUZZ_CHECK(c, ref_header_field(p, hdr, "Content-Length", 14, &off)
                      != REF_FOUND,
                   "http1_should_keep_alive: kept a connection carrying "
                   "Content-Length");
        FUZZ_CHECK(c, ref_header_field(p, hdr, "Transfer-Encoding", 17, &off)
                      != REF_FOUND,
                   "http1_should_keep_alive: kept a connection carrying "
                   "Transfer-Encoding");
        FUZZ_CHECK(c, method == GET_ID || method == HEAD_ID ||
                      method == OPTIONS_ID,
                   "http1_should_keep_alive: kept a connection for a method "
                   "with no defined body framing");
        FUZZ_CHECK(c, hdr != 0,
                   "http1_should_keep_alive: kept a connection on which no "
                   "request was observed");
    }
    fuzz_tally(c, got ? KA_KEEP : why);
}

static void ka_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_request(r, g_he.scratch, REQ_MAX);

    // The predicate is handed the header length, so give it one: the
    // terminator's index when there is one, and an arbitrary cut
    // otherwise — including 0, which is the "no request observed" case
    // the rule names first.
    uint64_t hdr = ref_header_end(g_he.scratch, n);
    if (!hdr || fuzz_chance(r, 8))
        hdr = fuzz_chance(r, 16) ? 0 : fuzz_below(r, n + 1);
    fuzz_input(c, g_he.scratch, (size_t)hdr);

    static const uint64_t statuses[] = {
        200, 206, 304, 400, 403, 404, 408, 413, 416, 431, 500, 501, 505,
    };
    const uint64_t method = fuzz_below(r, 5);
    const uint64_t status = fuzz_chance(r, 8)
        ? fuzz_below(r, 600)
        : statuses[fuzz_below(r, sizeof statuses / sizeof statuses[0])];

    ka_check(place_flush(&g_he.in, g_he.scratch, (size_t)hdr), hdr,
             method, status, c);
}

// A preserved input is the header the predicate was handed; the method
// and the status are the server's own, and replay at the pair that
// keeps a connection open — GET and 200 — which is the answer the rule
// has to get right for a request to be pipelined at all.
static void ka_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REQ_MAX) len = REQ_MAX;
    ka_check(place_flush(&g_he.in, in, len), len, 0, 200, c);
}

// The last field is the byte-level replay entry (Step 14). Every
// campaign here has one: an HTTP request is a byte string, which is
// exactly the shape a preserved finding keeps.
static const struct fuzz_target g_targets[] = {
    { "header_end", he_case, he_setup, he_teardown, 400000, 0,
      { "!terminator found", "!no terminator", 0 }, he_replay },
    { "header_field", hf_case, he_setup, he_teardown, 400000, 0,
      { "!found", "!absent", "!400 escape", 0 }, hf_replay },
    { "front_door", fd_case, fd_setup, fd_teardown, 200000, 0,
      { "!served", "!brew/unknown", "!parse rejected", "!400 escape",
        "!414 escape", "!505 escape", "!no terminator", 0 }, fd_replay },
    { "path", pp_case, pp_setup, pp_teardown, 200000, 0,
      { "!parsed", "!rejected", "!400 escape", "!414 escape", 0 },
      pp_replay },
    { "filters", pf_case, pf_setup, pf_teardown, 200000, 0,
      { "!decoded and clean", "!escape rejected", "!unsafe byte",
        "!traversal", 0 }, pf_replay },
    { "range", rg_case, he_setup, he_teardown, 200000, 0,
      { "!range accepted", "!no range", "!400 escape", 0 }, rg_replay },
    { "keepalive", ka_case, he_setup, he_teardown, 200000, 0,
      { "!kept alive", "!closed: body header", "!closed: Connection",
        "!closed: HTTP/1.0", "!closed: method or status", "!400 escape",
        0 }, ka_replay },
};

int main(int argc, char **argv)
{
    (void)argc;
    fuzz_disarm_harness_timeout();
    fuzz_suite("http", argv[0]);

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  sarm — HTTP/1 request parsing fuzzing (Step 8)         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  seed 0x%llx, x%llu cases\n",
           (unsigned long long)fuzz_seed(), (unsigned long long)fuzz_mult());

    TEST_SUITE("HTTP/1 request parsing — generated inputs");
    fuzz_run_all(g_targets, sizeof g_targets / sizeof g_targets[0]);

    test_summary();
    return 0;
}
