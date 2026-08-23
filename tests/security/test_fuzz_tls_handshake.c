// sarm security tests — TLS handshake fuzzing (Step 7)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_fuzz_tls_handshake.c
//
// Description: Step 6 fuzzed the record layer — five header bytes and
//   the length arithmetic behind them. Everything it found the record
//   layer doing correctly, it does *before* the handshake begins. Step
//   7 asks the next question: given that a record arrived intact, does
//   the handshake accept it only in the states where it is legal?
//
//   That is two different subjects, and this suite keeps them apart:
//
//     client_hello   the parser. tls_parse_client_hello is the largest
//                    piece of pre-authentication attack surface in the
//                    tree (docs/SECURITY.md §3.1) — nested length
//                    prefixes five deep, walked before a single byte
//                    has been authenticated. Structured generation
//                    plus mutation, ending flush against a guard page.
//
//     flight         the driver's early states. tls_server_handshake
//                    against a socket carrying a generated flight:
//                    mutated ClientHellos, records out of order,
//                    records of the wrong type, records that stop in
//                    the middle. No such flight can complete a
//                    handshake, so every case must end at
//                    TLS_HS_FAILED with the transport still plaintext
//                    and no application traffic keys installed.
//
//     finished       the transition that matters. A real client is
//                    driven all the way through the server's flight —
//                    X25519, the key schedule, decrypting
//                    EncryptedExtensions..Finished under the server
//                    handshake key — and then sends a client Finished
//                    that is either exactly right or wrong in one
//                    generated way. The invariant is an iff: the
//                    server connects if and only if the Finished was
//                    correct, encrypted under the client handshake key
//                    at sequence 0, carrying inner type `handshake`,
//                    with nothing illegal ahead of it.
//
//   The iff is the point. A handshake that rejects everything passes
//   "invalid transitions are rejected" trivially and is worth nothing,
//   so the same campaign that generates the invalid transitions also
//   generates the valid one, and fails if either verdict is wrong.
//   The harness's vacuity check (fuzz_common.h) enforces that both
//   sides actually happened.
// ─────────────────────────────────────────────────────────────────────

#include "fuzz_common.h"

#include <sys/socket.h>
#include <string.h>

// ── constants from src/defs.S ───────────────────────────────────────
#define TLS_HS_CONNECTED   7
#define TLS_HS_FAILED      8

#define TRANSPORT_PLAIN    0
#define TRANSPORT_TLS      1

#define REC_HANDSHAKE           22
#define REC_APPLICATION_DATA    23
#define REC_CHANGE_CIPHER_SPEC  20
#define REC_ALERT               21

#define HS_CLIENT_HELLO    1
#define HS_FINISHED        20

#define ALERT_HANDSHAKE_FAILURE         40
#define ALERT_ILLEGAL_PARAMETER         47
#define ALERT_DECODE_ERROR              50
#define ALERT_PROTOCOL_VERSION          70
#define ALERT_UNRECOGNIZED_NAME         112
#define ALERT_NO_APPLICATION_PROTOCOL   120

// ── reaching the assembly ───────────────────────────────────────────
// Every routine below is a raw assembly label (no leading underscore)
// reporting failure in the carry flag, so each is reached through
// inline asm. One convention throughout: arguments and results travel
// in a single `uint64_t a[]`, addressed by one register operand.
// Between them these callees clobber every register the allocator
// could otherwise use, and a per-argument operand exhausts it — the
// array costs exactly one.
#define SARM_CLOBBER \
    "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12", \
    "x13","x14","x15","x16","x17","x19","x20","x21","x22","x23","x24", \
    "x25","x26","x30", \
    "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11", \
    "v16","v17","v18","v19","v20","v21","cc","memory"

#define SARM_CALL(slots, body) \
    __asm__ volatile(body : : "r"(slots) : SARM_CLOBBER)

// The globals under test are assembly labels too, so their addresses
// come from the same place the code does.
#define DEFINE_SYM(fn, name) \
    static inline void *fn(void) { void *p; \
        __asm__("adrp %0, " #name "@PAGE\n\tadd %0, %0, " #name "@PAGEOFF" \
                : "=r"(p)); return p; }

DEFINE_SYM(sym_hs_state,          tls_hs_state)
DEFINE_SYM(sym_shared_secret,     tls_shared_secret)
DEFINE_SYM(sym_client_hs_key,     tls_client_hs_key)
DEFINE_SYM(sym_client_hs_iv,      tls_client_hs_iv)
DEFINE_SYM(sym_server_hs_key,     tls_server_hs_key)
DEFINE_SYM(sym_server_hs_iv,      tls_server_hs_iv)
DEFINE_SYM(sym_client_hs_secret,  tls_client_hs_traffic_secret)
DEFINE_SYM(sym_client_app_key,    tls_client_app_key)
DEFINE_SYM(sym_client_app_iv,     tls_client_app_iv)
DEFINE_SYM(sym_server_app_key,    tls_server_app_key)
DEFINE_SYM(sym_server_app_iv,     tls_server_app_iv)
DEFINE_SYM(sym_alpn_len,          tls_alpn_len)
DEFINE_SYM(sym_alpn,              tls_alpn)
DEFINE_SYM(sym_session_id_len,    tls_session_id_len)
DEFINE_SYM(sym_transport_mode,    transport_mode)
DEFINE_SYM(sym_basepoint9,        x25519_basepoint9)

static uint64_t sarm_hs_run(int fd)
{
    uint64_t a[2] = { (uint64_t)(unsigned)fd, 0 };
    SARM_CALL(a,
        "ldr x0, [%0]\n mov x1, #0\n mov x2, #0\n"
        "bl tls_server_handshake\n cset x3, cs\n str x3, [%0, #8]\n");
    return a[1];
}

struct ch_out { uint64_t alert, carry; };

static struct ch_out sarm_ch_parse(const uint8_t *body, uint64_t len)
{
    uint64_t a[4] = { (uint64_t)body, len, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n bl tls_parse_client_hello\n"
        "cset x2, cs\n stp x0, x2, [%0, #16]\n");
    struct ch_out o = { a[2], a[3] };
    return o;
}

static void sarm_x25519(uint8_t *out, const uint8_t *scalar,
                        const uint8_t *point)
{
    uint64_t a[4] = { (uint64_t)out, (uint64_t)scalar, (uint64_t)point, 0 };
    SARM_CALL(a, "ldp x0, x1, [%0]\n ldr x2, [%0, #16]\n bl x25519\n");
}

static void sarm_transcript_init(void)
{
    uint64_t a[1] = { 0 };
    SARM_CALL(a, "bl tls_transcript_init\n");
}

static void sarm_transcript_add(uint64_t type, const uint8_t *msg, uint64_t len)
{
    uint64_t a[4] = { type, (uint64_t)msg, len, 0 };
    SARM_CALL(a, "ldp x0, x1, [%0]\n ldr x2, [%0, #16]\n"
                 "bl tls_transcript_add\n");
}

static void sarm_transcript_hash(uint8_t *out)
{
    uint64_t a[1] = { (uint64_t)out };
    SARM_CALL(a, "ldr x0, [%0]\n bl tls_transcript_hash\n");
}

static void sarm_derive_hs_secrets(const uint8_t *hash)
{
    uint64_t a[1] = { (uint64_t)hash };
    SARM_CALL(a, "ldr x0, [%0]\n bl tls_derive_handshake_secrets\n");
}

static void sarm_finished_key(const uint8_t *base, uint8_t *out)
{
    uint64_t a[2] = { (uint64_t)base, (uint64_t)out };
    SARM_CALL(a, "ldp x0, x1, [%0]\n bl tls_finished_key\n");
}

static void sarm_verify_data(const uint8_t *fk, const uint8_t *hash,
                             uint8_t *out)
{
    uint64_t a[4] = { (uint64_t)fk, (uint64_t)hash, (uint64_t)out, 0 };
    SARM_CALL(a, "ldp x0, x1, [%0]\n ldr x2, [%0, #16]\n"
                 "bl tls_finished_verify_data\n");
}

// tls_record_encrypt/decrypt take an AES-128-GCM key *context* (round
// keys + GHASH subkey, built once per epoch by aes_gcm_ctx_init), not a
// bare key. This harness drives the record layer as a client would, off
// the server's own key fields, so it expands them here.
#define GCM_CTX_SIZE 304

extern void aes_gcm_ctx_init(const void *key, void *ctx)
    __asm__("aes_gcm_ctx_init");

struct dec_out { uint64_t len, inner, carry; };

static struct dec_out sarm_decrypt(const uint8_t *rec, uint64_t rlen,
                                   const uint8_t *key, const uint8_t *iv,
                                   uint64_t seq, uint8_t *out)
{
    uint8_t ctx[GCM_CTX_SIZE] __attribute__((aligned(16)));
    aes_gcm_ctx_init(key, ctx);
    uint64_t a[10] = { (uint64_t)rec, rlen, (uint64_t)ctx, (uint64_t)iv,
                       seq, (uint64_t)out, 0, 0, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n ldp x2, x3, [%0, #16]\n ldp x4, x5, [%0, #32]\n"
        "bl tls_record_decrypt\n"
        "cset x2, cs\n stp x0, x1, [%0, #48]\n str x2, [%0, #64]\n");
    struct dec_out o = { a[6], a[7], a[8] };
    return o;
}

struct enc_out { uint64_t len, carry; };

static struct enc_out sarm_encrypt(uint64_t type, const uint8_t *pt,
                                   uint64_t ptlen, const uint8_t *key,
                                   const uint8_t *iv, uint64_t seq,
                                   uint8_t *out)
{
    uint8_t ctx[GCM_CTX_SIZE] __attribute__((aligned(16)));
    aes_gcm_ctx_init(key, ctx);
    uint64_t a[10] = { type, (uint64_t)pt, ptlen, (uint64_t)ctx,
                       (uint64_t)iv, seq, (uint64_t)out, 0, 0, 0 };
    SARM_CALL(a,
        "ldp x0, x1, [%0]\n ldp x2, x3, [%0, #16]\n"
        "ldp x4, x5, [%0, #32]\n ldr x6, [%0, #48]\n"
        "bl tls_record_encrypt\n"
        "cset x1, cs\n stp x0, x1, [%0, #56]\n");
    struct enc_out o = { a[7], a[8] };
    return o;
}

// ── wire helpers ────────────────────────────────────────────────────

static uint8_t *put_u8(uint8_t *p, uint8_t v)   { *p = v; return p + 1; }
static uint8_t *put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; return p + 2;
}
static uint8_t *put_bytes(uint8_t *p, const void *src, size_t n)
{
    memcpy(p, src, n); return p + n;
}

// Wraps a handshake message body in its 4-byte header and a plaintext
// record header. Returns the total record length.
static size_t wrap_handshake(uint8_t *out, uint8_t hs_type,
                             const uint8_t *body, size_t len)
{
    out[0] = REC_HANDSHAKE;
    out[1] = 3; out[2] = 1;
    out[3] = (uint8_t)((len + 4) >> 8);
    out[4] = (uint8_t)(len + 4);
    out[5] = hs_type;
    out[6] = 0;
    out[7] = (uint8_t)(len >> 8);
    out[8] = (uint8_t)len;
    memcpy(out + 9, body, len);
    return len + 9;
}

// ─────────────────────────────────────────────────────────────────────
// Campaign 1 — client_hello
// ─────────────────────────────────────────────────────────────────────
// A ClientHello is five levels of nested length prefix: the body's own
// bounds, then cipher_suites, then the extensions block, then each
// extension, then the lists inside key_share / supported_groups /
// ALPN / server_name. tls_parse_client_hello walks all of it before
// anything is authenticated. The generator builds structurally
// plausible ones and then damages them, because a purely random buffer
// is rejected at the first length check and never reaches the fifth.

#define CH_CAP 1024

// Each field is 0 (absent), 1 (what the server wants) or 2 (present
// but offering something else) — the three shapes the parser has to
// tell apart.
struct ch_opts {
    unsigned version, cipher, group, keyshare, alpn, sni;
    unsigned sid_len;
    int      ext_len_delta;
};

static size_t build_ch(const struct ch_opts *o, const uint8_t *key_share,
                       uint8_t *out)
{
    uint8_t *p = out;
    p = put_u16(p, 0x0303);                     // legacy_version
    for (int i = 0; i < 32; i++)
        p = put_u8(p, (uint8_t)(i + 1));        // client_random
    p = put_u8(p, (uint8_t)o->sid_len);         // legacy_session_id
    for (unsigned i = 0; i < o->sid_len; i++)
        p = put_u8(p, (uint8_t)(0x80 + i));

    p = put_u16(p, 2);                          // cipher_suites
    p = put_u16(p, o->cipher == 1 ? 0x1301 : 0x1302);
    p = put_u8(p, 1);                           // compression_methods
    p = put_u8(p, 0);

    uint8_t ext[512];
    uint8_t *e = ext;
    if (o->version) {
        e = put_u16(e, 43); e = put_u16(e, 3);
        e = put_u8(e, 2);
        e = put_u16(e, o->version == 1 ? 0x0304 : 0x0303);
    }
    if (o->group) {
        e = put_u16(e, 10); e = put_u16(e, 4);
        e = put_u16(e, 2);
        e = put_u16(e, o->group == 1 ? 0x001d : 0x0017);
    }
    if (o->keyshare) {
        e = put_u16(e, 51); e = put_u16(e, 2 + 2 + 2 + 32);
        e = put_u16(e, 2 + 2 + 32);
        e = put_u16(e, o->keyshare == 1 ? 0x001d : 0x0017);
        e = put_u16(e, 32);
        e = put_bytes(e, key_share, 32);
    }
    if (o->alpn) {
        const char *name = o->alpn == 1 ? "h2" : "h3";
        e = put_u16(e, 16); e = put_u16(e, 2 + 1 + 2);
        e = put_u16(e, 1 + 2);
        e = put_u8(e, 2);
        e = put_bytes(e, name, 2);
    }
    if (o->sni) {
        const char *host = o->sni == 1 ? "localhost" : "example.com";
        size_t hl = o->sni == 1 ? 9 : 11;
        e = put_u16(e, 0); e = put_u16(e, (uint16_t)(2 + 3 + hl));
        e = put_u16(e, (uint16_t)(3 + hl));
        e = put_u8(e, 0);
        e = put_u16(e, (uint16_t)hl);
        e = put_bytes(e, host, hl);
    }

    size_t el = (size_t)(e - ext);
    p = put_u16(p, (uint16_t)((int)el + o->ext_len_delta));
    p = put_bytes(p, ext, el);
    return (size_t)(p - out);
}

// The ClientHello every deeper campaign starts from: everything the
// server requires, nothing it does not.
static const struct ch_opts CH_VALID = { 1, 1, 1, 1, 1, 1, 0, 0 };

static void gen_ch_opts(struct fuzz_rng *r, struct ch_opts *o)
{
    // 7/8 present, and when present 7/8 offering what the server
    // wants: most cases should get far enough to test a *later*
    // requirement than the first one.
    unsigned *f[5] = { &o->version, &o->cipher, &o->group, &o->keyshare,
                       &o->alpn };
    for (int i = 0; i < 5; i++)
        *f[i] = fuzz_chance(r, 8) ? 0 : (fuzz_chance(r, 8) ? 2 : 1);
    o->sni = fuzz_chance(r, 3) ? 0 : (fuzz_chance(r, 8) ? 2 : 1);

    uint64_t k = fuzz_below(r, 4);
    o->sid_len = k == 0 ? 0 : (k == 1 ? 32 : (unsigned)fuzz_below(r, 41));
    o->ext_len_delta = fuzz_chance(r, 8)
                     ? (int)fuzz_range(r, 0, 6) - 3 : 0;
}

static size_t gen_ch(struct fuzz_rng *r, uint8_t *out)
{
    if (fuzz_chance(r, 8)) {                    // pure chaos
        size_t n = (size_t)fuzz_below(r, 641);
        fuzz_fill_random(r, out, n);
        return n;
    }
    struct ch_opts o;
    gen_ch_opts(r, &o);
    uint8_t ks[32];
    fuzz_fill_random(r, ks, sizeof ks);
    size_t n = build_ch(&o, ks, out);
    if (fuzz_chance(r, 16) && n > 1)            // stop mid-field
        n = (size_t)fuzz_below(r, n);
    if (fuzz_chance(r, 3))
        fuzz_mutate(r, out, n);
    return n;
}

// The six alerts src/tls/handshake/client_hello.S's header declares.
// The module README's API reference lists only five — it omits
// illegal_parameter, which is what a non-null compression method
// gets. The file header is the contract, so this follows it.
enum {
    CB_OK = 0, CB_DECODE, CB_VERSION, CB_HANDSHAKE, CB_ALPN, CB_SNI,
    CB_ILLEGAL, CB_OTHER
};

static unsigned alert_bucket(uint64_t alert)
{
    switch (alert) {
    case ALERT_DECODE_ERROR:            return CB_DECODE;
    case ALERT_PROTOCOL_VERSION:        return CB_VERSION;
    case ALERT_HANDSHAKE_FAILURE:       return CB_HANDSHAKE;
    case ALERT_NO_APPLICATION_PROTOCOL: return CB_ALPN;
    case ALERT_UNRECOGNIZED_NAME:       return CB_SNI;
    case ALERT_ILLEGAL_PARAMETER:       return CB_ILLEGAL;
    default:                            return CB_OTHER;
    }
}

static struct {
    struct guarded_buffer body;
    uint8_t scratch[CH_CAP];
} g_ch;

static int ch_setup(struct fuzz_ctx *c)
{
    (void)c;
    return guard_alloc(&g_ch.body, CH_CAP);
}

static void ch_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_ch.body);
}

// The body from the ClientHello bytes on, so that a preserved input
// runs the same invariants as a generated one (Step 14).
static void ch_check(const uint8_t *bytes, size_t n, struct fuzz_ctx *c)
{
    // Flush against the guard page: the parser's own bounds checks are
    // the only thing standing between it and a fault.
    uint8_t *body = g_ch.body.data + g_ch.body.size - n;
    memcpy(body, bytes, n);

    // Poison the two length fields the parser owns. They are read
    // later by tls_server_hello_write and tls_encrypted_extensions_
    // write, which trust them — so they must be inside their buffers
    // whatever the parser decides, not only when it succeeds.
    uint64_t *sid_len = sym_session_id_len();
    uint64_t *alpn_len = sym_alpn_len();
    *sid_len  = 0xDEAD;
    *alpn_len = 0xDEAD;

    struct ch_out o = sarm_ch_parse(body, n);

    FUZZ_CHECK(c, *sid_len == 0xDEAD || *sid_len <= 32,
               "tls_parse_client_hello: left tls_session_id_len above 32");
    FUZZ_CHECK(c, *alpn_len == 0xDEAD || *alpn_len <= 16,
               "tls_parse_client_hello: left tls_alpn_len past the ALPN buffer");

    if (o.carry) {
        unsigned b = alert_bucket(o.alert);
        FUZZ_CHECK(c, b != CB_OTHER,
                   "tls_parse_client_hello: failure with an alert its "
                   "header does not document");
        fuzz_tally(c, b);
        return;
    }

    fuzz_tally(c, CB_OK);
    FUZZ_CHECK(c, o.alert == 0,
               "tls_parse_client_hello: success with a non-zero x0");
    FUZZ_CHECK(c, *sid_len <= 32,
               "tls_parse_client_hello: accepted a session id longer than 32");
    FUZZ_CHECK(c, *alpn_len == 2 &&
                  memcmp(sym_alpn(), "h2", 2) == 0,
               "tls_parse_client_hello: accepted without negotiating \"h2\"");
}

static void ch_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_ch(r, g_ch.scratch);
    fuzz_input(c, g_ch.scratch, n);
    ch_check(g_ch.scratch, n, c);
}

static void ch_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > g_ch.body.size)
        len = g_ch.body.size;
    ch_check(in, len, c);
}

// ─────────────────────────────────────────────────────────────────────
// Shared socket plumbing for the two driver campaigns
// ─────────────────────────────────────────────────────────────────────
// A socketpair, not a real network: fragmentation at arbitrary byte
// positions is Step 9's subject. What matters here is that
// tls_server_handshake talks to a real file descriptor with a real
// EOF, so raw_read_exact's short-read loop and the driver's failure
// paths are the ones the server actually runs.

#define SOCK_BUF (1 << 17)

static int make_pair(int sv[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        return -1;
    int sz = SOCK_BUF;
    for (int i = 0; i < 2; i++) {
        setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
        setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        long r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

// Reads one record off the wire. Returns 5 + fragment length, or -1.
static int read_record(int fd, uint8_t *buf)
{
    if (read_full(fd, buf, 5) < 0) return -1;
    unsigned len = ((unsigned)buf[3] << 8) | buf[4];
    if (len > 16640) return -1;
    if (len && read_full(fd, buf + 5, len) < 0) return -1;
    return (int)(5 + len);
}

// ─────────────────────────────────────────────────────────────────────
// Campaign 2 — flight
// ─────────────────────────────────────────────────────────────────────
// The driver's early states, driven from a flight written into the
// socket in one go with the write end then closed. No flight this
// generator can produce completes a handshake — the client's Finished
// depends on a ServerHello that has not been sent when the bytes are
// written — so every case must end the same way: carry set,
// TLS_HS_FAILED, the transport still plaintext, and no application
// traffic keys installed. That last one is the invariant worth having:
// a handshake that fails after deriving application secrets would
// leave a key schedule live that no peer ever authenticated.

#define FLIGHT_CAP 8192
#define APP_POISON 0x5A

enum { FB_NO_REPLY = 0, FB_SH_ONLY, FB_FULL_FLIGHT, FB_CONNECTED };

static struct {
    uint8_t flight[FLIGHT_CAP];
    uint8_t ch[CH_CAP];
    uint8_t back[SOCK_BUF];
} g_flight;

static uint8_t *app_key_fields(void) { return (uint8_t *)sym_client_app_key(); }

// The four application traffic key/IV fields are adjacent in tls_state
// (src/tls/data.S): client key, client IV, server key, server IV, all
// TLS_KEY_LEN/TLS_IV_STRIDE = 16 bytes apart.
#define APP_FIELDS_LEN 64

static void poison_app_keys(void)
{
    memset(app_key_fields(), APP_POISON, APP_FIELDS_LEN);
}

static int app_keys_untouched(void)
{
    const uint8_t *p = app_key_fields();
    for (size_t i = 0; i < APP_FIELDS_LEN; i++)
        if (p[i] != APP_POISON) return 0;
    return 1;
}

// One record of generated garbage, appended at `p`.
static uint8_t *gen_junk_record(struct fuzz_rng *r, uint8_t *p, uint8_t *end)
{
    static const uint8_t types[] = { 20, 21, 22, 23 };
    uint8_t t = fuzz_chance(r, 4) ? fuzz_u8(r)
                                  : types[fuzz_below(r, sizeof types)];
    uint16_t v = fuzz_chance(r, 4) ? (uint16_t)fuzz_u64(r) : 0x0303;
    size_t n = (size_t)fuzz_below(r, 65);
    if (p + 5 + n > end) return p;
    p = put_u8(p, t);
    p = put_u16(p, v);
    p = put_u16(p, (uint16_t)n);
    fuzz_fill_random(r, p, n);
    return p + n;
}

static size_t gen_flight(struct fuzz_rng *r)
{
    uint8_t *p = g_flight.flight;
    uint8_t *end = p + FLIGHT_CAP;

    if (fuzz_chance(r, 8))                      // nothing legal can follow
        p = gen_junk_record(r, p, end);

    size_t chlen;
    if (fuzz_chance(r, 4)) {                    // the real thing, verbatim
        uint8_t ks[32];
        fuzz_fill_random(r, ks, sizeof ks);
        chlen = build_ch(&CH_VALID, ks, g_flight.ch);
    } else {
        chlen = gen_ch(r, g_flight.ch);
    }
    if (p + 9 + chlen <= end) {
        size_t rl = wrap_handshake(p, HS_CLIENT_HELLO, g_flight.ch, chlen);
        if (fuzz_chance(r, 4))                  // damage the framing too
            fuzz_mutate(r, p, rl);
        p += rl;
    }

    uint64_t extra = fuzz_below(r, 4);
    for (uint64_t i = 0; i < extra; i++)
        p = gen_junk_record(r, p, end);

    return (size_t)(p - g_flight.flight);
}

// Counts the well-formed records the server wrote back, which is how
// far through its own flight it got before giving up.
static unsigned count_records(const uint8_t *p, size_t n)
{
    unsigned k = 0;
    size_t i = 0;
    while (i + 5 <= n) {
        size_t len = ((size_t)p[i + 3] << 8) | p[i + 4];
        if (i + 5 + len > n) break;
        i += 5 + len;
        k++;
    }
    return k;
}

static int flight_setup(struct fuzz_ctx *c)
{
    (void)c;
    signal(SIGPIPE, SIG_IGN);
    // The poison check above only means anything if the four fields
    // really are adjacent; assert the layout rather than trusting the
    // comment.
    const uint8_t *base = (const uint8_t *)sym_client_app_key();
    if ((const uint8_t *)sym_client_app_iv()  != base + 16 ||
        (const uint8_t *)sym_server_app_key() != base + 32 ||
        (const uint8_t *)sym_server_app_iv()  != base + 48)
        return -1;
    return 0;
}

// The body from the peer's bytes on. This is the campaign that found
// the five-byte pre-authentication crash of §9, and a byte-level replay
// is what turns that input into a regression test that survives every
// later change to gen_flight.
static void flight_check(const uint8_t *bytes, size_t n, struct fuzz_ctx *c)
{
    int sv[2];
    if (make_pair(sv) < 0) {
        fuzz_fail(c, "socketpair failed");
        return;
    }

    if (n) {
        long w = write(sv[0], bytes, n);
        (void)w;                                 // a short write is one
    }                                            // more truncated flight
    shutdown(sv[0], SHUT_WR);

    poison_app_keys();
    *(uint64_t *)sym_transport_mode() = TRANSPORT_PLAIN;
    *(uint64_t *)sym_hs_state() = 0xEE;

    uint64_t carry = sarm_hs_run(sv[1]);

    // Drain whatever the server managed to send before giving up.
    size_t back = 0;
    for (;;) {
        long got = recv(sv[0], g_flight.back + back,
                        sizeof g_flight.back - back, MSG_DONTWAIT);
        if (got <= 0) break;
        back += (size_t)got;
        if (back == sizeof g_flight.back) break;
    }
    close(sv[0]);
    close(sv[1]);

    if (!carry) {
        fuzz_tally(c, FB_CONNECTED);
        fuzz_fail(c, "tls_server_handshake: connected without a client "
                     "Finished");
        return;
    }

    FUZZ_CHECK(c, *(uint64_t *)sym_hs_state() == TLS_HS_FAILED,
               "tls_server_handshake: failed without leaving "
               "tls_hs_state at TLS_HS_FAILED");
    FUZZ_CHECK(c, *(uint64_t *)sym_transport_mode() == TRANSPORT_PLAIN,
               "tls_server_handshake: failed with transport_mode switched "
               "to TLS");
    FUZZ_CHECK(c, app_keys_untouched(),
               "tls_server_handshake: failed after installing application "
               "traffic keys");

    unsigned recs = count_records(g_flight.back, back);
    fuzz_tally(c, recs == 0 ? FB_NO_REPLY
                            : (recs >= 5 ? FB_FULL_FLIGHT : FB_SH_ONLY));
}

static void flight_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_flight(r);
    fuzz_input(c, g_flight.flight, n);
    flight_check(g_flight.flight, n, c);
}

static void flight_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > sizeof g_flight.flight)
        len = sizeof g_flight.flight;
    flight_check(in, len, c);
}

// ─────────────────────────────────────────────────────────────────────
// Campaign 3 — finished
// ─────────────────────────────────────────────────────────────────────
// Everything above tests states the handshake rejects. This one tests
// the state it accepts, and then every neighbouring state it must not.
//
// The server runs in a forked child so it has its own copy of
// tls_state; the case itself plays the client with the same assembly
// the server uses — x25519, tls_derive_handshake_secrets,
// tls_record_decrypt, tls_finished_key, tls_finished_verify_data — and
// gets far enough to hold the one secret that authenticates the
// client: verify_data over the CH..server-Finished transcript, keyed
// off client_handshake_traffic_secret. That is what makes the
// invariant an iff rather than "it said no".

enum {
    FK_VALID = 0,      // exactly right
    FK_CCS,            // change_cipher_spec first (RFC 8446 D.4)
    FK_CCS_FLOOD,      // ... a great many of them
    FK_BAD_VD,         // one bit of verify_data
    FK_BAD_TYPE,       // HandshakeType other than 20
    FK_BAD_BODY_LEN,   // a body that is not 32 bytes
    FK_BAD_DECL_LEN,   // 32 correct bytes, and a uint24 that lies
    FK_BAD_INNER,      // sealed with an inner type other than handshake
    FK_WRONG_KEY,      // sealed under the server's handshake key
    FK_WRONG_SEQ,      // sealed at a sequence number other than 0
    FK_GARBAGE,        // random bytes in an application_data record
    FK_PLAINTEXT,      // a correct Finished, but not encrypted at all
    FK_OTHER_MSG,      // a different handshake message, correctly sealed
    FK_NOTHING,        // EOF where the Finished should be
    FK_COUNT
};

enum {
    NB_OK = 0, NB_OK_CCS, NB_VD, NB_FRAMING, NB_KEY, NB_PLAIN, NB_EOF,
    NB_FINDING
};

static unsigned kind_bucket(unsigned k)
{
    switch (k) {
    case FK_VALID:                          return NB_OK;
    case FK_CCS: case FK_CCS_FLOOD:         return NB_OK_CCS;
    case FK_BAD_VD:                         return NB_VD;
    case FK_BAD_TYPE: case FK_BAD_BODY_LEN:
    case FK_BAD_DECL_LEN:
    case FK_BAD_INNER: case FK_OTHER_MSG:   return NB_FRAMING;
    case FK_WRONG_KEY: case FK_WRONG_SEQ:
    case FK_GARBAGE:                        return NB_KEY;
    case FK_PLAINTEXT:                      return NB_PLAIN;
    default:                                return NB_EOF;
    }
}

static int kind_should_connect(unsigned k)
{
    return k == FK_VALID || k == FK_CCS || k == FK_CCS_FLOOD;
}

// Child exit codes, distinct from the harness's own.
#define SRV_CONNECTED    0
#define SRV_REJECTED     1
#define SRV_INCONSISTENT 2

static struct {
    uint8_t ch[CH_CAP];
    uint8_t rec[17408];
    uint8_t pt[17408];
    uint8_t out[17408];
} g_fin;

static int fin_setup(struct fuzz_ctx *c)
{
    (void)c;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

// Pulls the X25519 share out of a ServerHello body. Written by hand
// rather than reusing the server's own writer so a change to
// tls_server_hello_write that broke the wire format would show up here
// as a client that cannot continue, not as two matching bugs.
static const uint8_t *sh_key_share(const uint8_t *b, size_t n)
{
    if (n < 35) return 0;
    size_t i = 2 + 32;
    size_t sid = b[i];
    i += 1 + sid;
    i += 2 + 1;                                  // cipher suite, compression
    if (i + 2 > n) return 0;
    size_t el = ((size_t)b[i] << 8) | b[i + 1];
    i += 2;
    size_t end = i + el;
    if (end > n) return 0;
    while (i + 4 <= end) {
        size_t t = ((size_t)b[i] << 8) | b[i + 1];
        size_t l = ((size_t)b[i + 2] << 8) | b[i + 3];
        i += 4;
        if (i + l > end) return 0;
        if (t == 51 && l == 2 + 2 + 32) return b + i + 4;
        i += l;
    }
    return 0;
}

static void send_ccs(int fd)
{
    static const uint8_t ccs[6] = { REC_CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1 };
    long w = write(fd, ccs, sizeof ccs);
    (void)w;
}

static void fin_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    const unsigned kind = (unsigned)fuzz_below(r, FK_COUNT);
    const int expect = kind_should_connect(kind);

    int sv[2];
    if (make_pair(sv) < 0) { fuzz_fail(c, "socketpair failed"); return; }

    uint8_t priv[32];
    fuzz_fill_random(r, priv, sizeof priv);
    priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
    uint8_t pub[32];
    sarm_x25519(pub, priv, (const uint8_t *)sym_basepoint9());

    struct ch_opts o = CH_VALID;
    o.sid_len = fuzz_chance(r, 2) ? 32 : 0;      // both ServerHello echoes
    o.sni     = fuzz_chance(r, 2) ? 0 : 1;
    size_t chlen = build_ch(&o, pub, g_fin.ch);

    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) { close(sv[0]); close(sv[1]); fuzz_fail(c, "fork failed"); return; }
    if (pid == 0) {
        close(sv[0]);
        uint64_t carry = sarm_hs_run(sv[1]);
        if (carry)
            _exit(SRV_REJECTED);
        // A success claim is only worth as much as the state behind
        // it: the driver documents all three of these as part of
        // "connected".
        if (*(uint64_t *)sym_hs_state() != TLS_HS_CONNECTED ||
            *(uint64_t *)sym_transport_mode() != TRANSPORT_TLS)
            _exit(SRV_INCONSISTENT);
        _exit(SRV_CONNECTED);
    }
    close(sv[1]);
    const int fd = sv[0];

    int reached_flight = 0;
    size_t rl = wrap_handshake(g_fin.rec, HS_CLIENT_HELLO, g_fin.ch, chlen);
    if (write(fd, g_fin.rec, rl) < 0)
        goto collect;

    sarm_transcript_init();
    sarm_transcript_add(HS_CLIENT_HELLO, g_fin.ch, chlen);

    // ── the server's ServerHello ──
    int n = read_record(fd, g_fin.rec);
    if (n < 0) goto collect;
    if (g_fin.rec[0] != REC_HANDSHAKE || n < 9) goto collect;
    {
        const uint8_t *shb = g_fin.rec + 9;
        size_t shl = (size_t)n - 9;
        sarm_transcript_add(2, shb, shl);
        const uint8_t *sks = sh_key_share(shb, shl);
        if (!sks) goto collect;
        sarm_x25519((uint8_t *)sym_shared_secret(), priv, sks);
    }

    uint8_t hash[32];
    sarm_transcript_hash(hash);
    sarm_derive_hs_secrets(hash);

    // ── EncryptedExtensions, Certificate, CertificateVerify, Finished ──
    for (uint64_t i = 0; i < 4; i++) {
        n = read_record(fd, g_fin.rec);
        if (n < 0) goto collect;
        struct dec_out d = sarm_decrypt(g_fin.rec, (uint64_t)n,
                                        (const uint8_t *)sym_server_hs_key(),
                                        (const uint8_t *)sym_server_hs_iv(),
                                        i, g_fin.pt);
        if (d.carry || d.inner != REC_HANDSHAKE || d.len < 4) goto collect;
        sarm_transcript_add(g_fin.pt[0], g_fin.pt + 4, d.len - 4);
    }
    reached_flight = 1;

    // ── the client's Finished, then one generated deviation ──
    {
        uint8_t fk[32], vd[32], msg[64];
        sarm_finished_key((const uint8_t *)sym_client_hs_secret(), fk);
        sarm_transcript_hash(hash);
        sarm_verify_data(fk, hash, vd);

        size_t msg_len = 36;
        msg[0] = HS_FINISHED; msg[1] = 0; msg[2] = 0; msg[3] = 32;
        memcpy(msg + 4, vd, 32);

        uint64_t inner = REC_HANDSHAKE;
        uint64_t seq   = 0;
        const uint8_t *key = (const uint8_t *)sym_client_hs_key();
        const uint8_t *iv  = (const uint8_t *)sym_client_hs_iv();

        switch (kind) {
        case FK_CCS:
            for (uint64_t i = fuzz_range(r, 1, 3); i; i--) send_ccs(fd);
            break;
        case FK_CCS_FLOOD:
            for (int i = 0; i < 200; i++) send_ccs(fd);
            break;
        case FK_BAD_VD: {
            size_t at = (size_t)fuzz_below(r, 32);
            msg[4 + at] ^= (uint8_t)(1u << fuzz_below(r, 8));
            break;
        }
        case FK_BAD_TYPE:
            do { msg[0] = fuzz_u8(r); } while (msg[0] == HS_FINISHED);
            break;
        case FK_BAD_BODY_LEN: {
            // A Finished body that is not 32 bytes: the record's own
            // length is what the driver checks, so the body has to
            // actually change size.
            size_t nl = (size_t)fuzz_below(r, 49);
            if (nl == 32) nl = 33;
            msg[1] = 0; msg[2] = (uint8_t)(nl >> 8); msg[3] = (uint8_t)nl;
            msg_len = 4 + nl;
            break;
        }
        case FK_BAD_DECL_LEN: {
            // The counterpart. Here the body really is 32 bytes and
            // the verify_data really is correct — only the message's
            // own uint24 length disagrees, so the record length the
            // driver checks is exactly right and the lie is in the
            // one field nothing used to read (docs/SECURITY.md §14
            // A1). `14 00 00 ff` followed by 32 good bytes completed
            // a handshake before that changed.
            uint32_t nl;
            do { nl = (uint32_t)(fuzz_u64(r) & 0xFFFFFFu); } while (nl == 32);
            msg[1] = (uint8_t)(nl >> 16);
            msg[2] = (uint8_t)(nl >> 8);
            msg[3] = (uint8_t)nl;
            break;
        }
        case FK_BAD_INNER:
            inner = fuzz_chance(r, 2) ? REC_APPLICATION_DATA : REC_ALERT;
            break;
        case FK_WRONG_KEY:
            key = (const uint8_t *)sym_server_hs_key();
            iv  = (const uint8_t *)sym_server_hs_iv();
            break;
        case FK_WRONG_SEQ:
            seq = fuzz_range(r, 1, 8);
            break;
        case FK_GARBAGE:
            msg_len = (size_t)fuzz_range(r, 1, 64);
            fuzz_fill_random(r, msg, msg_len);
            break;
        case FK_OTHER_MSG:
            // Correctly sealed, correctly framed, wrong message: the
            // one case where only the state machine can say no.
            msg[0] = fuzz_chance(r, 2) ? HS_CLIENT_HELLO : 24;  // KeyUpdate
            break;
        default:
            break;
        }

        if (kind == FK_NOTHING) {
            /* send nothing at all */
        } else if (kind == FK_PLAINTEXT) {
            size_t pl = wrap_handshake(g_fin.out, msg[0], msg + 4, 32);
            long w = write(fd, g_fin.out, pl);
            (void)w;
        } else if (kind == FK_GARBAGE) {
            g_fin.out[0] = REC_APPLICATION_DATA;
            g_fin.out[1] = 3; g_fin.out[2] = 3;
            g_fin.out[3] = (uint8_t)(msg_len >> 8);
            g_fin.out[4] = (uint8_t)msg_len;
            memcpy(g_fin.out + 5, msg, msg_len);
            long w = write(fd, g_fin.out, 5 + msg_len);
            (void)w;
        } else {
            struct enc_out en = sarm_encrypt(inner, msg, msg_len, key, iv,
                                             seq, g_fin.out);
            if (!en.carry) {
                long w = write(fd, g_fin.out, en.len);
                (void)w;
            }
        }
    }

collect:
    shutdown(fd, SHUT_WR);
    close(fd);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        ;
    FUZZ_CHECK(c, WIFEXITED(status),
               "tls_server_handshake: the server died on a generated "
               "client flight");
    int code = WEXITSTATUS(status);
    FUZZ_CHECK(c, code != SRV_INCONSISTENT,
               "tls_server_handshake: reported success without reaching "
               "TLS_HS_CONNECTED and TRANSPORT_TLS");
    FUZZ_CHECK(c, code == SRV_CONNECTED || code == SRV_REJECTED,
               "tls_server_handshake: the server exited unexpectedly");

    const int connected = (code == SRV_CONNECTED);
    if (expect) {
        FUZZ_CHECK(c, reached_flight,
                   "the server did not complete its own flight for a valid "
                   "ClientHello");
        FUZZ_CHECK(c, connected,
                   "tls_server_handshake: rejected a correct client Finished");
    } else if (connected) {
        fuzz_tally(c, NB_FINDING);
        fuzz_fail(c, "tls_server_handshake: accepted an invalid client "
                     "Finished");
        return;
    }
    fuzz_tally(c, kind_bucket(kind));
}

// ─────────────────────────────────────────────────────────────────────
// Campaign 4 — framing
// ─────────────────────────────────────────────────────────────────────
// Everything the other three campaigns send is correctly framed: the
// handshake message's own HandshakeType and uint24 length always agree
// with the record fragment carrying them, because wrap_handshake
// writes both from the same number. So none of them could notice that
// tls_server_handshake never read either field (docs/SECURITY.md §9
// observation 12, §14 A1).
//
// It matters because tls_transcript_add *synthesises* the 4-byte
// header from the type and length it is given, rather than hashing the
// bytes that arrived. A message whose header disagreed with its
// contents was therefore normalised into the transcript instead of
// rejected — and the disagreement, if it surfaced at all, surfaced as
// a Finished mismatch five messages later, after the server had signed
// a transcript and sent a full flight to a peer whose first message
// was already malformed.
//
// Six ways to disagree, one control, and one that is not a
// disagreement at all: FR_SPLIT sends a perfectly legal ClientHello
// spread over two handshake records, which RFC 8446 §5.1 permits a
// client to do and this server deliberately does not support. It is
// here so the refusal is pinned by a test rather than only described
// in src/tls/server/README.md — if reassembly is ever implemented,
// this case is the one that has to change, on purpose.

enum {
    FR_VALID = 0,      // correct framing — the control
    FR_DECL_LONG,      // declared length one past the fragment
    FR_DECL_SHORT,     // ... one short of it
    FR_DECL_ZERO,      // ... zero
    FR_DECL_MAX,       // ... 0xFFFFFF, the uint24 ceiling
    FR_BAD_TYPE,       // HandshakeType is not client_hello
    FR_TRAILING,       // a second message packed in behind the first
    FR_SPLIT,          // one message across two records
    FR_COUNT
};

enum { RB_CONTROL = 0, RB_DECL, RB_TYPE, RB_TRAILING, RB_SPLIT, RB_FINDING };

static unsigned frame_bucket(unsigned k)
{
    switch (k) {
    case FR_VALID:                            return RB_CONTROL;
    case FR_BAD_TYPE:                         return RB_TYPE;
    case FR_TRAILING:                         return RB_TRAILING;
    case FR_SPLIT:                            return RB_SPLIT;
    default:                                  return RB_DECL;
    }
}

// Room for two whole messages in one record, plus two record headers.
#define FRAME_CAP (2 * (CH_CAP + 4) + 16)

static struct {
    uint8_t ch[CH_CAP];
    uint8_t rec[FRAME_CAP];
    uint8_t back[SOCK_BUF];
} g_frame;

static int frame_setup(struct fuzz_ctx *c)
{
    (void)c;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static void put_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v;
}

static void frame_check(const uint8_t *bytes, size_t n, unsigned kind,
                        struct fuzz_ctx *c)
{
    int sv[2];
    if (make_pair(sv) < 0) { fuzz_fail(c, "socketpair failed"); return; }

    if (n) { long w = write(sv[0], bytes, n); (void)w; }
    shutdown(sv[0], SHUT_WR);

    *(uint64_t *)sym_transport_mode() = TRANSPORT_PLAIN;
    *(uint64_t *)sym_hs_state() = 0xEE;

    uint64_t carry = sarm_hs_run(sv[1]);

    size_t back = 0;
    for (;;) {
        long got = recv(sv[0], g_frame.back + back,
                        sizeof g_frame.back - back, MSG_DONTWAIT);
        if (got <= 0) break;
        back += (size_t)got;
        if (back == sizeof g_frame.back) break;
    }
    close(sv[0]);
    close(sv[1]);

    unsigned recs = count_records(g_frame.back, back);

    // No case here can complete a handshake — none of them sends a
    // client Finished — so every one fails. What separates them is how
    // far the server got first, and that is the whole measurement.
    if (!carry) {
        fuzz_tally(c, RB_FINDING);
        fuzz_fail(c, "tls_server_handshake: connected without a client "
                     "Finished");
        return;
    }
    FUZZ_CHECK(c, *(uint64_t *)sym_hs_state() == TLS_HS_FAILED,
               "tls_server_handshake: failed without leaving tls_hs_state "
               "at TLS_HS_FAILED");
    FUZZ_CHECK(c, *(uint64_t *)sym_transport_mode() == TRANSPORT_PLAIN,
               "tls_server_handshake: failed with transport_mode switched "
               "to TLS");

    if (kind == FR_VALID) {
        // The control. A correctly framed ClientHello must still get
        // the whole server flight, or every rejection below is a
        // statement about a ClientHello this server cannot parse
        // rather than about its framing.
        if (recs == 0) {
            fuzz_tally(c, RB_FINDING);
            fuzz_fail(c, "a correctly framed ClientHello got no reply — the "
                         "framing checks are rejecting valid messages");
            return;
        }
    } else if (recs != 0) {
        fuzz_tally(c, RB_FINDING);
        fuzz_fail(c, "a mis-framed ClientHello was answered: the server "
                     "sent its flight before noticing");
        return;
    }
    fuzz_tally(c, frame_bucket(kind));
}

static void frame_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    const unsigned kind = (unsigned)fuzz_below(r, FR_COUNT);

    uint8_t ks[32];
    fuzz_fill_random(r, ks, sizeof ks);
    size_t chlen = build_ch(&CH_VALID, ks, g_frame.ch);

    uint8_t *rec = g_frame.rec;
    size_t n = wrap_handshake(rec, HS_CLIENT_HELLO, g_frame.ch, chlen);
    const size_t body = 4 + chlen;               // header + body, the fragment

    switch (kind) {
    case FR_VALID:
        break;
    case FR_DECL_LONG:
        put_u24(rec + 6, (uint32_t)chlen + 1);
        break;
    case FR_DECL_SHORT:
        put_u24(rec + 6, (uint32_t)chlen - 1);
        break;
    case FR_DECL_ZERO:
        put_u24(rec + 6, 0);
        break;
    case FR_DECL_MAX:
        put_u24(rec + 6, 0xFFFFFFu);
        break;
    case FR_BAD_TYPE:
        rec[5] = 2;                              // server_hello, from a client
        break;
    case FR_TRAILING: {
        // The declared length still describes the first message
        // exactly; the record simply carries a second one behind it.
        // Accepting this would hash one message and parse the bytes of
        // two.
        memcpy(rec + 5 + body, rec + 5, body);
        size_t frag = body * 2;
        rec[3] = (uint8_t)(frag >> 8); rec[4] = (uint8_t)frag;
        n = 5 + frag;
        break;
    }
    case FR_SPLIT: {
        // Legal on the wire, unsupported here: the declared length is
        // correct and the first record carries only part of it, with
        // the rest in a second handshake record.
        size_t half = body / 2;
        size_t rest = body - half;
        memmove(rec + 5 + half + 5, rec + 5 + half, rest);
        rec[3] = (uint8_t)(half >> 8); rec[4] = (uint8_t)half;
        rec[5 + half + 0] = REC_HANDSHAKE;
        rec[5 + half + 1] = 3;
        rec[5 + half + 2] = 1;
        rec[5 + half + 3] = (uint8_t)(rest >> 8);
        rec[5 + half + 4] = (uint8_t)rest;
        n = 5 + half + 5 + rest;
        break;
    }
    }

    fuzz_input(c, rec, n);
    frame_check(rec, n, kind, c);
}

// ─────────────────────────────────────────────────────────────────────
// Campaigns
// ─────────────────────────────────────────────────────────────────────
// Case counts differ by three orders of magnitude because the
// campaigns cost that differently: a ClientHello parse is a few
// microseconds, a flight is a socketpair and sometimes an ECDSA
// signature, and a `finished` case is a fork plus a complete
// handshake on both sides. SARM_FUZZ_MULT scales all three together.

static const struct fuzz_target g_targets[] = {
    { "client_hello", ch_case, ch_setup, ch_teardown, 2000000, 0,
      { "!accepted", "!decode_error", "!protocol_version",
        "!handshake_failure", "!no_application_protocol",
        "!unrecognized_name", "!illegal_parameter",
        "an alert it does not document", 0 },
      ch_replay },

    // "ServerHello sent, then rejected" is not required, and that is a
    // property of the driver rather than a gap in the corpus: between
    // sending the ServerHello and sending its own Finished,
    // tls_server_handshake has no failure path a peer can trigger —
    // every step in between is serialization, hashing and encryption
    // of the server's own material. A flight that reaches the
    // ServerHello reaches all five records unless the socket itself
    // fails.
    { "flight", flight_case, flight_setup, 0, 6000, 0,
      { "!rejected before the ServerHello", "ServerHello sent, then rejected",
        "!full flight sent, then rejected", "connected (a finding)", 0 },
      flight_replay },

    { "finished", fin_case, fin_setup, 0, 1000, 0,
      { "!completed (valid Finished)", "!completed after change_cipher_spec",
        "!rejected: verify_data", "!rejected: message or framing",
        "!rejected: key, sequence or ciphertext", "!rejected: not encrypted",
        "!rejected: nothing sent", "accepted an invalid transition (a finding)",
        0 },
      0 },

    // Cheap: one socketpair and, for the control only, one full server
    // flight. Nothing here forks.
    { "framing", frame_case, frame_setup, 0, 4000, 0,
      { "!control accepted (the server replied)",
        "!rejected: declared length", "!rejected: message type",
        "!rejected: trailing bytes in the record",
        "!rejected: message split across records",
        "answered a mis-framed message (a finding)", 0 },
      0 },
};

int main(int argc, char **argv)
{
    (void)argc;
    fuzz_disarm_harness_timeout();
    fuzz_suite("tls_handshake", argv[0]);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  sarm — TLS handshake fuzzing (SECURITY.md Step 7)      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  seed 0x%llx, x%llu cases\n",
           (unsigned long long)fuzz_seed(), (unsigned long long)fuzz_mult());

    TEST_SUITE("TLS handshake — generated inputs and transitions");
    fuzz_run_all(g_targets, sizeof g_targets / sizeof g_targets[0]);

    test_summary();
    return 0;
}
