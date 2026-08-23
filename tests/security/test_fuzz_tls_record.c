// sarm security tests — TLS record layer fuzzing (Step 6)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_fuzz_tls_record.c
//
// Description: The TLS record layer is the first code in the tree that
//   an unauthenticated peer reaches (docs/SECURITY.md §3.1). Five bytes
//   the attacker chose select a content type, a version and a length,
//   and that length decides how far every routine downstream walks.
//   Steps 3-5 asked whether the record layer is right at the edges of
//   its contract and whether its arithmetic can wrap. Step 6 asks the
//   different question: what happens for inputs nobody thought to
//   write down.
//
//   Six campaigns, each a generator plus the invariants that must hold
//   for every input it can produce:
//
//     parse              tls_record_parse over bytes ending flush
//                        against a guard page
//     decrypt            tls_record_decrypt with a fixed key, over
//                        records that are almost never authentic
//     roundtrip          encrypt -> decrypt must return exactly the
//                        plaintext that went in
//     tamper             encrypt, flip one bit anywhere in the record,
//                        decrypt must refuse. Never a different
//                        plaintext, never a success
//     read_record        tls_read_record against a real socket fed
//                        adversarial bytes
//     read_prefilled     tls_read_record_prefilled, whose shortfall
//                        arithmetic (total - already_present) is the
//                        subtlest length calculation in the module
//
//   The invariants are the point. "No crash" is necessary and cheap to
//   check, but a parser can also return success while handing its
//   caller a fragment pointer past the end of the buffer, and nothing
//   crashes until the caller uses it. So every campaign checks the
//   full output contract from the module README — carry, error code
//   range, fragment placement, length bounds — on every case, not just
//   that the process survived.
//
//   Placement does the rest. Every record ends flush against a
//   PROT_NONE page and every output buffer is exactly as large as the
//   contract says it must be, so "did not read past the record" and
//   "did not write past the output" are answered by the MMU.
// ─────────────────────────────────────────────────────────────────────

#include "fuzz_common.h"

#include <sys/socket.h>
#include <string.h>

// ── the record layer's own constants (src/tls/record/_constants.S) ──
#define TLS_RECORD_HEADER_LEN   5
#define TLS_MAX_PLAINTEXT       16384
#define TLS_MAX_CIPHERTEXT      16640
#define TLS_MAX_AEAD            16401
#define TLS_TAG_LEN             16
#define TLS_INNER_TYPE_LEN      1

#define ERR_SHORT   1
#define ERR_TYPE    2
#define ERR_VERSION 3
#define ERR_LENGTH  4
#define ERR_BOUNDS  5
#define ERR_MAC     6
#define ERR_INNER   7
#define ERR_EMPTY   8

// Largest record the layer will ever accept, plus its header.
#define REC_MAX (TLS_RECORD_HEADER_LEN + TLS_MAX_CIPHERTEXT)

// ── the routines under test ─────────────────────────────────────────
// Raw assembly labels, reached through inline asm so the carry flag —
// which is how this tree reports errors — is readable. The multi-
// argument routines take their arguments through a small array: six
// register operands plus thirty clobbers exhausts the allocator.

struct parse_out { uint64_t type, frag, frag_len, total, carry; };

static struct parse_out rec_parse(const uint8_t *buf, uint64_t len)
{
    struct parse_out o;
    uint64_t a0, a1, a2, a3, c;
    __asm__ volatile(
        "mov x0, %5\n"
        "mov x1, %6\n"
        "bl tls_record_parse\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "mov %2, x2\n"
        "mov %3, x3\n"
        "cset %4, cs\n"
        : "=r"(a0), "=r"(a1), "=r"(a2), "=r"(a3), "=r"(c)
        : "r"(buf), "r"(len)
        : "x0", "x1", "x2", "x3", "x5", "x6", "x7", "x9", "x10",
          "x30", "cc", "memory");
    o.type = a0; o.frag = a1; o.frag_len = a2; o.total = a3; o.carry = c;
    return o;
}

#define CRYPTO_CLOBBER \
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", \
    "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24", "x30", \
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", \
    "v11", "v16", "v17", "v18", "v19", "v20", "v21", "cc", "memory"

// tls_record_encrypt/decrypt take an AES-128-GCM key *context* (round
// keys + GHASH subkey, built once per epoch by aes_gcm_ctx_init) rather
// than a bare key. These wrappers keep taking a key and expand it here,
// so the campaigns below stay written in terms of g_key.
//
// Passing the key pointer straight through would not fault — the callee
// would just read GCM_CTX_SIZE bytes from it and use whatever is there
// — campaigns that seal and open through the same wrapper would still
// agree with each other. Only a campaign that mixes gcm_seal with
// rec_decrypt would notice. Expand it properly.
#define GCM_CTX_SIZE 304

extern void aes_gcm_ctx_init(const void *key, void *ctx)
    __asm__("aes_gcm_ctx_init");

struct dec_out { uint64_t content_len, inner_type, carry; };

static struct dec_out rec_decrypt(const uint8_t *rec, uint64_t len,
                                  const uint8_t *key, const uint8_t *iv,
                                  uint64_t seq, uint8_t *out)
{
    uint8_t ctx[GCM_CTX_SIZE] __attribute__((aligned(16)));
    aes_gcm_ctx_init(key, ctx);
    uint64_t a[6];
    a[0] = (uint64_t)rec; a[1] = len; a[2] = (uint64_t)ctx;
    a[3] = (uint64_t)iv;  a[4] = seq; a[5] = (uint64_t)out;
    struct dec_out o;
    uint64_t r0, r1, c;
    __asm__ volatile(
        "ldp x0, x1, [%3]\n"
        "ldp x2, x3, [%3, #16]\n"
        "ldp x4, x5, [%3, #32]\n"
        "bl tls_record_decrypt\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "cset %2, cs\n"
        : "=r"(r0), "=r"(r1), "=r"(c)
        : "r"(a)
        : CRYPTO_CLOBBER);
    o.content_len = r0; o.inner_type = r1; o.carry = c;
    return o;
}

struct enc_out { uint64_t total, carry; };

static struct enc_out rec_encrypt(uint64_t inner_type, const uint8_t *pt,
                                  uint64_t pt_len, const uint8_t *key,
                                  const uint8_t *iv, uint64_t seq,
                                  uint8_t *out)
{
    uint8_t ctx[GCM_CTX_SIZE] __attribute__((aligned(16)));
    aes_gcm_ctx_init(key, ctx);
    uint64_t a[7];
    a[0] = inner_type;    a[1] = (uint64_t)pt; a[2] = pt_len;
    a[3] = (uint64_t)ctx; a[4] = (uint64_t)iv; a[5] = seq;
    a[6] = (uint64_t)out;
    struct enc_out o;
    uint64_t r0, c;
    __asm__ volatile(
        "ldp x0, x1, [%2]\n"
        "ldp x2, x3, [%2, #16]\n"
        "ldp x4, x5, [%2, #32]\n"
        "ldr x6, [%2, #48]\n"
        "bl tls_record_encrypt\n"
        "mov %0, x0\n"
        "cset %1, cs\n"
        : "=r"(r0), "=r"(c)
        : "r"(a)
        : CRYPTO_CLOBBER);
    o.total = r0; o.carry = c;
    return o;
}

// Seals an arbitrary buffer, which tls_record_encrypt deliberately
// cannot do: it appends the inner type itself, so nothing it produces
// ever ends in a zero octet. Reaching decrypt's padding scan means
// building the TLSInnerPlaintext by hand and sealing it directly.
static void gcm_seal(const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, uint64_t aad_len,
                     const uint8_t *pt, uint64_t pt_len,
                     uint8_t *ct, uint8_t *tag)
{
    uint64_t a[8];
    a[0] = (uint64_t)key; a[1] = (uint64_t)nonce; a[2] = (uint64_t)aad;
    a[3] = aad_len;       a[4] = (uint64_t)pt;    a[5] = pt_len;
    a[6] = (uint64_t)ct;  a[7] = (uint64_t)tag;
    __asm__ volatile(
        "ldp x0, x1, [%0]\n"
        "ldp x2, x3, [%0, #16]\n"
        "ldp x4, x5, [%0, #32]\n"
        "ldp x6, x7, [%0, #48]\n"
        "bl aes_gcm_encrypt\n"
        :
        : "r"(a)
        : CRYPTO_CLOBBER);
}

static struct parse_out rec_read(int fd, uint8_t *buf, uint64_t cap)
{
    struct parse_out o;
    uint64_t a0, a1, a2, a3, c;
    uint64_t fdv = (uint64_t)(unsigned)fd;
    __asm__ volatile(
        "mov x0, %5\n"
        "mov x1, %6\n"
        "mov x2, %7\n"
        "bl tls_read_record\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "mov %2, x2\n"
        "mov %3, x3\n"
        "cset %4, cs\n"
        : "=r"(a0), "=r"(a1), "=r"(a2), "=r"(a3), "=r"(c)
        : "r"(fdv), "r"(buf), "r"(cap)
        : "x0", "x1", "x2", "x3", "x5", "x6", "x7", "x9", "x10", "x16",
          "x19", "x20", "x21", "x22", "x30", "cc", "memory");
    o.type = a0; o.frag = a1; o.frag_len = a2; o.total = a3; o.carry = c;
    return o;
}

static struct parse_out rec_read_prefilled(int fd, uint8_t *buf, uint64_t cap,
                                           uint64_t have)
{
    uint64_t a[4];
    a[0] = (uint64_t)(unsigned)fd; a[1] = (uint64_t)buf;
    a[2] = cap;                    a[3] = have;
    struct parse_out o;
    uint64_t a0, a1, a2, a3, c;
    __asm__ volatile(
        "ldp x0, x1, [%5]\n"
        "ldp x2, x3, [%5, #16]\n"
        "bl tls_read_record_prefilled\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "mov %2, x2\n"
        "mov %3, x3\n"
        "cset %4, cs\n"
        : "=r"(a0), "=r"(a1), "=r"(a2), "=r"(a3), "=r"(c)
        : "r"(a)
        : "x0", "x1", "x2", "x3", "x5", "x6", "x7", "x9", "x10", "x16",
          "x19", "x20", "x21", "x22", "x23", "x30", "cc", "memory");
    o.type = a0; o.frag = a1; o.frag_len = a2; o.total = a3; o.carry = c;
    return o;
}

// ── generation ──────────────────────────────────────────────────────
// A record is five bytes of header the attacker chose and a fragment
// the attacker chose. Fully random bytes almost never get past the
// content-type check, so most of the corpus is *structurally* valid
// and wrong only where it matters: the length field against the bytes
// actually present, the version against the two accepted values, the
// type against the four accepted values. Then a mutation pass puts
// some of the pure chaos back.

static uint8_t gen_type(struct fuzz_rng *r)
{
    if (fuzz_chance(r, 4))
        return fuzz_u8(r);                      // anything at all
    return (uint8_t)fuzz_range(r, 20, 23);      // one the parser accepts
}

static void gen_version(struct fuzz_rng *r, uint8_t *p)
{
    switch (fuzz_below(r, 8)) {
    case 0: p[0] = fuzz_u8(r); p[1] = fuzz_u8(r); break;
    case 1: p[0] = 0x03; p[1] = 0x01; break;    // TLS 1.0 — initial CH only
    case 2: p[0] = 0x03; p[1] = 0x04; break;    // the one everyone gets wrong
    default: p[0] = 0x03; p[1] = 0x03; break;   // TLS 1.2 — the normal case
    }
}

// Build a record into buf and return how many bytes of it are actually
// present. The claimed length in the header and the number of bytes
// present are chosen *independently* a good fraction of the time: that
// disagreement is the whole attack surface of a length-prefixed format.
static size_t gen_record(struct fuzz_rng *r, uint8_t *buf, size_t cap)
{
    if (fuzz_chance(r, 8)) {                    // pure chaos
        size_t n = (size_t)fuzz_below(r, 65);
        if (n > cap) n = cap;
        fuzz_fill_random(r, buf, n);
        return n;
    }

    // How big is this case? Small most of the time — that is where the
    // boundaries are — and occasionally the full 16 KiB, to exercise
    // the length field's high byte and the block loops downstream.
    size_t body;
    if (fuzz_chance(r, 32))
        body = (size_t)fuzz_below(r, TLS_MAX_CIPHERTEXT + 1);
    else if (fuzz_chance(r, 4))
        body = (size_t)fuzz_interesting_value(r) % (TLS_MAX_CIPHERTEXT + 1);
    else
        body = (size_t)fuzz_below(r, 96);

    size_t present = body + TLS_RECORD_HEADER_LEN;
    if (present > cap) present = cap;

    // The claimed length: usually consistent with what is present, and
    // otherwise an interesting value in its own right.
    uint64_t claimed = body;
    if (fuzz_chance(r, 3)) {
        switch (fuzz_below(r, 4)) {
        case 0: claimed = fuzz_interesting_value(r); break;
        case 1: claimed = fuzz_below(r, 65536); break;
        case 2: claimed = body + fuzz_range(r, 1, 8); break;
        case 3: claimed = body > 8 ? body - fuzz_range(r, 1, 8) : 0; break;
        }
    }

    if (cap >= TLS_RECORD_HEADER_LEN) {
        buf[0] = gen_type(r);
        gen_version(r, buf + 1);
        buf[3] = (uint8_t)(claimed >> 8);
        buf[4] = (uint8_t)claimed;
        if (present > TLS_RECORD_HEADER_LEN)
            fuzz_fill_random(r, buf + TLS_RECORD_HEADER_LEN,
                             present - TLS_RECORD_HEADER_LEN);
    } else {
        fuzz_fill_random(r, buf, present);
    }

    // Sometimes truncate below a full header, so the SHORT path and
    // the "header split across two reads" case both get exercised.
    if (fuzz_chance(r, 16))
        present = (size_t)fuzz_below(r, TLS_RECORD_HEADER_LEN + 1);

    if (fuzz_chance(r, 3))
        fuzz_mutate(r, buf, present);

    return present;
}

// ── outcome buckets ─────────────────────────────────────────────────
// Every campaign tallies where each case ended up, and declares which
// of those outcomes it must reach (the '!' prefix in the target's
// bucket names). That is what stops a generator from quietly drifting
// into producing nothing but malformed input: the invariants on the
// accepting path would all still hold, vacuously, and the campaign
// would still be green. Here it fails instead.
enum {
    B_OK = 0, B_SHORT, B_TYPE, B_VERSION, B_LENGTH, B_BOUNDS,
    B_MAC, B_INNER, B_OTHER,
};

// Map a returned error code to its bucket.
static unsigned err_bucket(uint64_t err)
{
    switch (err) {
    case ERR_SHORT:   return B_SHORT;
    case ERR_TYPE:    return B_TYPE;
    case ERR_VERSION: return B_VERSION;
    case ERR_LENGTH:  return B_LENGTH;
    case ERR_BOUNDS:  return B_BOUNDS;
    case ERR_MAC:     return B_MAC;
    case ERR_INNER:   return B_INNER;
    default:          return B_OTHER;
    }
}

// ── campaign 1: tls_record_parse ────────────────────────────────────
struct parse_state {
    struct guarded_buffer rec;      // record ends flush against the guard
    uint8_t              *scratch;  // generation area, not guarded
};

static struct parse_state g_parse;

static int parse_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_parse.rec, REC_MAX) != 0)
        return -1;
    static uint8_t scratch[REC_MAX];
    g_parse.scratch = scratch;
    return 0;
}

static void parse_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_parse.rec);
}

// Place `n` bytes so that buf + n is the first guard byte. One mapping
// for the whole campaign: at a million cases a second, an mmap per case
// would cost more than the parser does.
static uint8_t *flush_end(struct guarded_buffer *gb, const uint8_t *src,
                          size_t n)
{
    uint8_t *p = gb->data + gb->size - n;
    memcpy(p, src, n);
    return p;
}

// The case body, from the input bytes on. Split out from parse_case so
// that a preserved input can be run through exactly the same
// invariants as a generated one (Step 14: the corpus is bytes, and it
// has to mean the same thing the generator's case meant).
static void parse_check(uint8_t *p, size_t n, struct fuzz_ctx *c)
{
    struct parse_out o = rec_parse(p, n);

    if (o.carry) {
        FUZZ_CHECK(c, o.type >= ERR_SHORT && o.type <= ERR_BOUNDS,
                   "tls_record_parse: failure with an error code outside "
                   "SHORT..BOUNDS");
        fuzz_tally(c, err_bucket(o.type));
        return;
    }
    fuzz_tally(c, B_OK);

    FUZZ_CHECK(c, o.type >= 20 && o.type <= 23,
               "tls_record_parse: success with a content type outside 20..23");
    FUZZ_CHECK(c, o.frag == (uint64_t)(p + TLS_RECORD_HEADER_LEN),
               "tls_record_parse: fragment pointer is not buf + 5");
    FUZZ_CHECK(c, o.total == o.frag_len + TLS_RECORD_HEADER_LEN,
               "tls_record_parse: total length is not fragment length + 5");
    FUZZ_CHECK(c, o.total <= n,
               "tls_record_parse: success with a record running past the "
               "end of the buffer");
    if (o.type == 23)
        FUZZ_CHECK(c, o.frag_len <= TLS_MAX_CIPHERTEXT,
                   "tls_record_parse: application_data fragment above "
                   "TLS_MAX_CIPHERTEXT");
    else
        FUZZ_CHECK(c, o.frag_len <= TLS_MAX_PLAINTEXT,
                   "tls_record_parse: plaintext fragment above "
                   "TLS_MAX_PLAINTEXT");

    // The header the parser accepted must be the header that is there.
    FUZZ_CHECK(c, o.type == p[0],
               "tls_record_parse: reported a content type the record does "
               "not carry");
    FUZZ_CHECK(c, o.frag_len == (uint64_t)((p[3] << 8) | p[4]),
               "tls_record_parse: reported a length the header does not "
               "carry");
}

static void parse_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_record(r, g_parse.scratch, REC_MAX);
    fuzz_input(c, g_parse.scratch, n);
    uint8_t *p = flush_end(&g_parse.rec, g_parse.scratch, n);
    parse_check(p, n, c);
}

static void parse_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REC_MAX)
        len = REC_MAX;
    uint8_t *p = flush_end(&g_parse.rec, in, len);
    parse_check(p, len, c);
}

// ── campaign 2: tls_record_decrypt ──────────────────────────────────
// A fixed key and IV: the point is not to guess a tag, it is to walk
// every path from the length checks to the padding scan on inputs the
// attacker controls completely. Roughly one case in 2^128 authenticates,
// so the success-path invariants below are carried by campaign 3.
static const uint8_t g_key[16] = {
    0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef,
    0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56,
};
static const uint8_t g_iv[12] = {
    0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a,
    0xad, 0xf1, 0xe9, 0x84,
};

#define POISON 0xA5

struct dec_state {
    struct guarded_buffer rec;
    struct guarded_buffer out;
    uint8_t              *scratch;
};

static struct dec_state g_dec;

static int dec_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_dec.rec, REC_MAX) != 0)
        return -1;
    if (guard_alloc(&g_dec.out, REC_MAX) != 0) {
        guard_free(&g_dec.rec);
        return -1;
    }
    static uint8_t scratch[REC_MAX];
    g_dec.scratch = scratch;
    return 0;
}

static void dec_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_dec.rec);
    guard_free(&g_dec.out);
}

// As with parse: the body from the bytes on, so a preserved input runs
// the same invariants. The sequence number is the one other thing a
// case varies, and a replayed input carries only bytes, so it replays
// at sequence 0 — the record is rejected on its length or its tag long
// before the nonce matters, and every finding this campaign has
// produced was reached that way.
static void dec_check(uint8_t *p, size_t n, uint64_t seq, struct fuzz_ctx *c)
{
    // The contract says the output buffer must hold len - 16 bytes.
    // decrypt bounds the ciphertext by the buffer it was given, so the
    // most it can ever write is n - 5 - 16. Give it exactly that, with
    // the guard page immediately after: one byte more and the case
    // faults.
    size_t outcap = n > (TLS_RECORD_HEADER_LEN + TLS_TAG_LEN)
                  ? n - TLS_RECORD_HEADER_LEN - TLS_TAG_LEN : 0;
    uint8_t *out = g_dec.out.data + g_dec.out.size - outcap;
    memset(out, POISON, outcap);

    struct dec_out o = rec_decrypt(p, n, g_key, g_iv, seq, out);

    if (o.carry) {
        FUZZ_CHECK(c, o.content_len == ERR_SHORT || o.content_len == ERR_LENGTH
                   || o.content_len == ERR_BOUNDS || o.content_len == ERR_MAC
                   || o.content_len == ERR_INNER,
                   "tls_record_decrypt: failure with an unexpected error code");
        fuzz_tally(c, err_bucket(o.content_len));
        // "a bad tag leaves the output untouched" (decrypt.S). A record
        // that fails to authenticate must not have leaked a single
        // keystream byte into the caller's buffer.
        for (size_t i = 0; i < outcap; i++)
            FUZZ_CHECK(c, out[i] == POISON,
                       "tls_record_decrypt: wrote plaintext into the output "
                       "buffer for a record it then rejected");
        return;
    }

    fuzz_tally(c, B_OK);
    uint64_t frag_len = (uint64_t)((p[3] << 8) | p[4]);
    uint64_t pt_len = frag_len - TLS_TAG_LEN;
    FUZZ_CHECK(c, o.inner_type >= 20 && o.inner_type <= 23,
               "tls_record_decrypt: success with an inner type outside 20..23");
    FUZZ_CHECK(c, o.content_len < pt_len,
               "tls_record_decrypt: content length leaves no room for the "
               "inner type byte");
    FUZZ_CHECK(c, o.content_len <= outcap,
               "tls_record_decrypt: content length exceeds the output buffer");
}

static void dec_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_record(r, g_dec.scratch, REC_MAX);
    fuzz_input(c, g_dec.scratch, n);
    uint8_t *p = flush_end(&g_dec.rec, g_dec.scratch, n);
    uint64_t seq = fuzz_chance(r, 2) ? fuzz_below(r, 8) : fuzz_u64(r);
    dec_check(p, n, seq, c);
}

static void dec_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > REC_MAX)
        len = REC_MAX;
    uint8_t *p = flush_end(&g_dec.rec, in, len);
    dec_check(p, len, 0, c);
}

// ── campaigns 3 and 4: encrypt -> decrypt, clean and tampered ───────
struct rt_state {
    struct guarded_buffer pt;       // plaintext in
    struct guarded_buffer rec;      // sealed record — sized exactly
    struct guarded_buffer out;      // plaintext out
    uint8_t              *scratch;
};

static struct rt_state g_rt;

static int rt_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_rt.pt, TLS_MAX_PLAINTEXT) != 0)
        return -1;
    if (guard_alloc(&g_rt.rec, REC_MAX) != 0) { guard_free(&g_rt.pt); return -1; }
    if (guard_alloc(&g_rt.out, REC_MAX) != 0) {
        guard_free(&g_rt.pt); guard_free(&g_rt.rec); return -1;
    }
    static uint8_t scratch[TLS_MAX_PLAINTEXT];
    g_rt.scratch = scratch;
    return 0;
}

static void rt_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_rt.pt);
    guard_free(&g_rt.rec);
    guard_free(&g_rt.out);
}

// Plaintext lengths are mostly small: AES-GCM over 16 KiB is three
// orders of magnitude slower than over 32 bytes, and a campaign that
// spends its budget on bulk throughput is not fuzzing, it is
// benchmarking. The large sizes still appear, just rarely.
static size_t rt_pt_len(struct fuzz_rng *r)
{
    if (fuzz_chance(r, 64))
        return (size_t)fuzz_below(r, TLS_MAX_PLAINTEXT + 1);
    if (fuzz_chance(r, 4))
        return (size_t)(fuzz_interesting_value(r) % 300);
    return (size_t)fuzz_below(r, 64);
}

// Seal one record. Returns 0 if the parameters were legal and the
// record is in g_rt.rec; -1 if encrypt correctly refused them.
static int rt_seal(struct fuzz_rng *r, struct fuzz_ctx *c,
                   uint64_t *inner_type, size_t *pt_len, uint64_t *seq,
                   uint8_t **rec, size_t *rec_len, uint8_t **pt)
{
    *pt_len = rt_pt_len(r);
    *inner_type = fuzz_range(r, 20, 23);
    *seq = fuzz_chance(r, 2) ? fuzz_below(r, 16) : fuzz_u64(r);

    fuzz_fill_random(r, g_rt.scratch, *pt_len);
    fuzz_input(c, g_rt.scratch, *pt_len);
    *pt = g_rt.pt.data + g_rt.pt.size - *pt_len;
    memcpy(*pt, g_rt.scratch, *pt_len);

    size_t total = TLS_RECORD_HEADER_LEN + *pt_len
                 + TLS_INNER_TYPE_LEN + TLS_TAG_LEN;
    *rec = g_rt.rec.data + g_rt.rec.size - total;
    *rec_len = total;

    struct enc_out e = rec_encrypt(*inner_type, *pt, *pt_len, g_key, g_iv,
                                   *seq, *rec);
    if (e.carry) {
        // The only legal refusals: zero-length handshake or alert.
        FUZZ_CHECK(c, e.total == ERR_EMPTY && *pt_len == 0
                   && (*inner_type == 21 || *inner_type == 22),
                   "tls_record_encrypt: refused parameters that are legal");
        fuzz_tally(c, B_OTHER);     // the legal zero-length refusal
        return -1;
    }
    FUZZ_CHECK(c, e.total == total,
               "tls_record_encrypt: reported a length that is not "
               "5 + plaintext + 1 + 16");
    FUZZ_CHECK(c, (*rec)[0] == 23 && (*rec)[1] == 0x03 && (*rec)[2] == 0x03,
               "tls_record_encrypt: outer header is not "
               "application_data / 0x0303");
    FUZZ_CHECK(c, (uint64_t)(((*rec)[3] << 8) | (*rec)[4])
               == *pt_len + TLS_INNER_TYPE_LEN + TLS_TAG_LEN,
               "tls_record_encrypt: header length disagrees with the record");
    return 0;
}

static void rt_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    uint64_t inner_type, seq;
    size_t pt_len, rec_len;
    uint8_t *rec, *pt;
    if (rt_seal(r, c, &inner_type, &pt_len, &seq, &rec, &rec_len, &pt) != 0)
        return;

    size_t outcap = pt_len + TLS_INNER_TYPE_LEN;
    uint8_t *out = g_rt.out.data + g_rt.out.size - outcap;
    memset(out, POISON, outcap);

    struct dec_out d = rec_decrypt(rec, rec_len, g_key, g_iv, seq, out);
    FUZZ_CHECK(c, !d.carry,
               "tls_record_decrypt: refused a record tls_record_encrypt "
               "had just produced");
    FUZZ_CHECK(c, d.inner_type == inner_type,
               "roundtrip: inner content type changed");
    FUZZ_CHECK(c, d.content_len == pt_len,
               "roundtrip: plaintext length changed");
    FUZZ_CHECK(c, memcmp(out, g_rt.scratch, pt_len) == 0,
               "roundtrip: plaintext changed");
    fuzz_tally(c, B_OK);

    // Decrypting under the wrong sequence number is a different nonce
    // and must fail, with the output left alone.
    memset(out, POISON, outcap);
    struct dec_out w = rec_decrypt(rec, rec_len, g_key, g_iv, seq ^ 1, out);
    FUZZ_CHECK(c, w.carry && w.content_len == ERR_MAC,
               "tls_record_decrypt: accepted a record under the wrong "
               "sequence number");
    for (size_t i = 0; i < outcap; i++)
        FUZZ_CHECK(c, out[i] == POISON,
                   "tls_record_decrypt: wrote plaintext for a record that "
                   "failed under the wrong sequence number");
}

// Every byte of a TLS 1.3 record is authenticated: the header is the
// AEAD's additional data and the rest is ciphertext and tag. So there
// is no bit anywhere in the record that can be flipped without the
// open failing. That is a much stronger statement than "the tag is
// checked", and it is exactly what this campaign asserts.
static void tamper_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    uint64_t inner_type, seq;
    size_t pt_len, rec_len;
    uint8_t *rec, *pt;
    if (rt_seal(r, c, &inner_type, &pt_len, &seq, &rec, &rec_len, &pt) != 0)
        return;

    size_t at = (size_t)fuzz_below(r, rec_len);
    uint8_t bit = (uint8_t)(1u << fuzz_below(r, 8));
    rec[at] ^= bit;

    // Flipping the length field changes how many bytes the record
    // claims; hand decrypt the buffer it actually has, which is what a
    // caller that read the record off the wire would do.
    size_t outcap = pt_len + TLS_INNER_TYPE_LEN;
    uint8_t *out = g_rt.out.data + g_rt.out.size - outcap;
    memset(out, POISON, outcap);

    struct dec_out d = rec_decrypt(rec, rec_len, g_key, g_iv, seq, out);
    FUZZ_CHECK(c, d.carry,
               "tls_record_decrypt: accepted a record with a flipped bit");
    FUZZ_CHECK(c, d.content_len == ERR_LENGTH || d.content_len == ERR_BOUNDS
               || d.content_len == ERR_MAC || d.content_len == ERR_SHORT,
               "tls_record_decrypt: rejected a tampered record with an "
               "unexpected error code");
    fuzz_tally(c, err_bucket(d.content_len));
    for (size_t i = 0; i < outcap; i++)
        FUZZ_CHECK(c, out[i] == POISON,
                   "tls_record_decrypt: wrote plaintext for a tampered record");
}

// ── campaigns 5 and 6: tls_read_record over a real socket ──────────
// The record layer's actual entrypoint. Everything above hands the
// parser a buffer that is already full; this hands it a file
// descriptor and lets it decide how much to pull. The bytes are
// written and the writer closed before the call, so a record claiming
// more than was sent hits EOF rather than blocking forever — a hang
// here would be a genuine finding, not a test artefact.
#define READ_MAX 3072

struct read_state {
    struct guarded_buffer dst;
    uint8_t              *scratch;
};

static struct read_state g_read;

static int read_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_read.dst, READ_MAX) != 0)
        return -1;
    static uint8_t scratch[READ_MAX];
    g_read.scratch = scratch;
    return 0;
}

static void read_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_read.dst);
}

// Returns the read end of a socketpair holding `n` bytes, already
// shut down for writing. -1 on failure.
static int feed(const uint8_t *bytes, size_t n)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return -1;
    int bufsz = 1 << 17;
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz);
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(sv[1], bytes + off, n - off);
        if (w <= 0) { close(sv[0]); close(sv[1]); return -1; }
        off += (size_t)w;
    }
    close(sv[1]);                   // EOF for anything beyond `n`
    return sv[0];
}

static void check_read_result(struct fuzz_ctx *c, struct parse_out o,
                              const uint8_t *dst, uint64_t cap)
{
    if (o.carry) {
        FUZZ_CHECK(c, o.type >= ERR_SHORT && o.type <= ERR_BOUNDS,
                   "tls_read_record: failure with an error code outside "
                   "SHORT..BOUNDS");
        fuzz_tally(c, err_bucket(o.type));
        return;
    }
    fuzz_tally(c, B_OK);
    FUZZ_CHECK(c, o.type >= 20 && o.type <= 23,
               "tls_read_record: success with a content type outside 20..23");
    FUZZ_CHECK(c, o.frag == (uint64_t)(dst + TLS_RECORD_HEADER_LEN),
               "tls_read_record: fragment pointer is not buf + 5");
    FUZZ_CHECK(c, o.total == o.frag_len + TLS_RECORD_HEADER_LEN,
               "tls_read_record: total length is not fragment length + 5");
    FUZZ_CHECK(c, o.total <= cap,
               "tls_read_record: success with a record larger than the "
               "destination buffer");
    FUZZ_CHECK(c, o.type == dst[0],
               "tls_read_record: reported a content type the buffer does "
               "not hold");
}

// From the bytes on the wire onward, so that a preserved input replays
// through the same socket and the same invariants.
static void read_check(const uint8_t *bytes, size_t n, uint64_t cap,
                       struct fuzz_ctx *c)
{
    uint8_t *dst = g_read.dst.data + g_read.dst.size - cap;

    int fd = feed(bytes, n);
    FUZZ_CHECK(c, fd >= 0, "test bug: could not set up the socketpair");

    struct parse_out o = rec_read(fd, dst, cap);
    close(fd);
    check_read_result(c, o, dst, cap);
}

static void read_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_record(r, g_read.scratch, READ_MAX);
    fuzz_input(c, g_read.scratch, n);
    uint64_t cap = fuzz_chance(r, 4)
                 ? fuzz_below(r, TLS_RECORD_HEADER_LEN + 1)  // below a header
                 : fuzz_range(r, TLS_RECORD_HEADER_LEN, READ_MAX);
    read_check(g_read.scratch, n, cap, c);
}

// A replayed input is the bytes a peer sent; the destination capacity
// is the harness's own knob, so it replays at the full buffer — the
// case that is reachable from the server, where the destination is a
// whole record buffer.
static void read_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > READ_MAX)
        len = READ_MAX;
    read_check(in, len, READ_MAX, c);
}

// tls_read_record_prefilled subtracts what is already in the buffer
// from what the record needs, twice — once for the header and once for
// the fragment. Both subtractions are on wire-derived values, so both
// are fuzzed with the split between "already there" and "still on the
// wire" chosen independently of the record's own length.
static void read_pre_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t n = gen_record(r, g_read.scratch, READ_MAX);
    fuzz_input(c, g_read.scratch, n);
    uint64_t cap = fuzz_range(r, TLS_RECORD_HEADER_LEN, READ_MAX);
    uint8_t *dst = g_read.dst.data + g_read.dst.size - cap;

    // How much of the record is "already in the buffer"? Anything from
    // none of it to more than the record turns out to hold.
    uint64_t have = fuzz_below(r, n + 1);
    if (fuzz_chance(r, 8))
        have = fuzz_below(r, cap + 1);
    if (have > cap) have = cap;
    if (have > n) have = n;

    memcpy(dst, g_read.scratch, have);
    int fd = feed(g_read.scratch + have, n - have);
    FUZZ_CHECK(c, fd >= 0, "test bug: could not set up the socketpair");

    struct parse_out o = rec_read_prefilled(fd, dst, cap, have);
    close(fd);

    if (o.carry) {
        FUZZ_CHECK(c, o.type >= ERR_SHORT && o.type <= ERR_BOUNDS,
                   "tls_read_record_prefilled: failure with an error code "
                   "outside SHORT..BOUNDS");
        fuzz_tally(c, err_bucket(o.type));
        return;
    }
    check_read_result(c, o, dst, cap);
}

// ── campaigns ───────────────────────────────────────────────────────
// Case counts are per-campaign and scale with SARM_FUZZ_MULT. The
// defaults are chosen so that `make test-security` stays a few seconds
// and still runs over a million record parses; the campaigns recorded
// in docs/SECURITY.md §10 were run with SARM_FUZZ_MULT set high
// enough to reach tens of millions.
#define PARSE_BUCKETS \
    { "!accepted", "!short", "!bad type", "!bad version", "!bad length", \
      "!past the buffer", "mac", "inner", "other", 0 }

#define READ_BUCKETS \
    { "!accepted", "!short/EOF", "!bad type", "!bad version", \
      "!too big for the buffer", "past the buffer", "mac", "inner", \
      "other", 0 }

// ── campaign 7: the inner-plaintext scan (Step 7) ──────────────────
// RFC 8446 §5.4: the sealed plaintext is `content || type ||
// zeros(padding)`, and the reader finds the type by scanning back from
// the end for the first non-zero octet. Nothing above can reach that
// scan with real padding — tls_record_encrypt appends the type last,
// so its plaintexts never end in a zero — which is why the `inner`
// bucket is empty in every campaign of Step 6. This one seals a
// *chosen* inner plaintext with aes_gcm_encrypt directly and asks the
// scan the three questions the contract in decrypt.S answers: the
// padded record, the all-zero record of Appendix C.3, and the record
// whose type octet is not a content type.

enum { PB_OK = 0, PB_PADDED, PB_ALL_ZERO, PB_BAD_TYPE };

struct pad_state {
    struct guarded_buffer rec;
    struct guarded_buffer out;
    uint8_t              *plain;
};

static struct pad_state g_pad;

#define PAD_MAX_CONTENT 96
#define PAD_MAX_PAD     64
#define PAD_MAX_PLAIN   (PAD_MAX_CONTENT + 1 + PAD_MAX_PAD)

static int pad_setup(struct fuzz_ctx *c)
{
    (void)c;
    if (guard_alloc(&g_pad.rec, TLS_RECORD_HEADER_LEN + PAD_MAX_PLAIN
                                + TLS_TAG_LEN) != 0)
        return -1;
    if (guard_alloc(&g_pad.out, PAD_MAX_PLAIN) != 0) {
        guard_free(&g_pad.rec);
        return -1;
    }
    static uint8_t plain[PAD_MAX_PLAIN];
    g_pad.plain = plain;
    return 0;
}

static void pad_teardown(struct fuzz_ctx *c)
{
    (void)c;
    guard_free(&g_pad.rec);
    guard_free(&g_pad.out);
}

// RFC 8446 §5.3, written out here rather than calling tls_record_nonce:
// an independent second implementation of the per-record nonce means a
// disagreement shows up as a tag that does not verify.
static void pad_nonce(const uint8_t *iv, uint64_t seq, uint8_t *out)
{
    for (int i = 0; i < 12; i++)
        out[i] = iv[i];
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

// The inner plaintext is the whole input here: content, type octet and
// padding are just names for byte positions in it. So a preserved case
// is that buffer, and the replay seals it and reads it back exactly as
// a generated one does.
static void pad_check(uint8_t *pt, size_t pt_len, uint64_t seq,
                      struct fuzz_ctx *c)
{
    // What §5.4 says the reader must find, derived from the bytes as
    // built rather than from the knobs that built them. The two differ
    // more often than it looks: a type octet of 0 is padding, and then
    // the last non-zero octet of `content` becomes the type — which is
    // correct behaviour, and was worth one wrong expectation here
    // before the scan below replaced it.
    size_t scan = pt_len;
    while (scan && pt[scan - 1] == 0)
        scan--;
    const int    zeros_only  = (scan == 0);
    const uint64_t exp_type  = zeros_only ? 0 : pt[scan - 1];
    const size_t exp_content = zeros_only ? 0 : scan - 1;
    const int    type_ok     = !zeros_only && exp_type >= 20 && exp_type <= 23;

    const size_t frag = pt_len + TLS_TAG_LEN;

    uint8_t *rec = g_pad.rec.data + g_pad.rec.size
                 - (TLS_RECORD_HEADER_LEN + frag);
    rec[0] = 23; rec[1] = 3; rec[2] = 3;
    rec[3] = (uint8_t)(frag >> 8); rec[4] = (uint8_t)frag;

    uint8_t nonce[12];
    pad_nonce(g_iv, seq, nonce);
    gcm_seal(g_key, nonce, rec, TLS_RECORD_HEADER_LEN, pt, pt_len,
             rec + TLS_RECORD_HEADER_LEN,
             rec + TLS_RECORD_HEADER_LEN + pt_len);

    // The plaintext is about to be overwritten in place by decrypt's
    // output buffer in the guarded page, so keep a copy to compare
    // against — the sealed record is the only other copy.
    uint8_t sealed_pt[PAD_MAX_PLAIN];
    memcpy(sealed_pt, pt, pt_len);

    uint8_t *out = g_pad.out.data + g_pad.out.size - pt_len;
    memset(out, POISON, pt_len);

    struct dec_out o = rec_decrypt(rec, TLS_RECORD_HEADER_LEN + frag,
                                   g_key, g_iv, seq, out);

    if (!type_ok) {
        FUZZ_CHECK(c, o.carry,
                   "tls_record_decrypt: accepted an inner plaintext with no "
                   "valid content type");
        FUZZ_CHECK(c, o.content_len == ERR_INNER,
                   "tls_record_decrypt: rejected a malformed inner plaintext "
                   "with something other than INNER");
        // Deliberately no poison check here. "A bad tag leaves the
        // output untouched" is a claim about *authentication*: the
        // caller must never see keystream for a record nobody with the
        // key produced. This record authenticates — the peer really
        // did seal it — and is then rejected for being malformed
        // inside, after the plaintext has already been written. The
        // `decrypt` campaign checks the confidentiality claim on the
        // path where it applies.
        fuzz_tally(c, zeros_only ? PB_ALL_ZERO : PB_BAD_TYPE);
        return;
    }

    FUZZ_CHECK(c, !o.carry,
               "tls_record_decrypt: rejected a record it sealed correctly "
               "itself");
    FUZZ_CHECK(c, o.inner_type == exp_type,
               "tls_record_decrypt: reported an inner type other than the "
               "last non-zero octet");
    FUZZ_CHECK(c, o.content_len == exp_content,
               "tls_record_decrypt: content length does not strip exactly "
               "the type octet and the padding");
    FUZZ_CHECK(c, memcmp(out, sealed_pt, exp_content) == 0,
               "tls_record_decrypt: the content is not what was sealed");
    fuzz_tally(c, (pt_len - scan) ? PB_PADDED : PB_OK);
}

static void pad_case(struct fuzz_rng *r, struct fuzz_ctx *c)
{
    size_t content = (size_t)fuzz_below(r, PAD_MAX_CONTENT + 1);
    size_t pad     = fuzz_chance(r, 2) ? (size_t)fuzz_below(r, PAD_MAX_PAD + 1)
                                       : 0;
    // 1 in 8 is all zeros — the malformed case of Appendix C.3, with
    // no type octet anywhere.
    int all_zero = fuzz_chance(r, 8);
    uint64_t type = fuzz_chance(r, 4) ? fuzz_u8(r) : fuzz_range(r, 20, 23);

    uint8_t *pt = g_pad.plain;
    size_t pt_len;
    if (all_zero) {
        pt_len = content + 1 + pad;
        if (pt_len == 0) pt_len = 1;
        memset(pt, 0, pt_len);
    } else {
        fuzz_fill_random(r, pt, content);
        pt[content] = (uint8_t)type;
        memset(pt + content + 1, 0, pad);
        pt_len = content + 1 + pad;
    }

    fuzz_input(c, pt, pt_len);
    const uint64_t seq0 = fuzz_chance(r, 2) ? fuzz_below(r, 8) : fuzz_u64(r);
    pad_check(pt, pt_len, seq0, c);
}

static void pad_replay(const uint8_t *in, size_t len, struct fuzz_ctx *c)
{
    if (len > PAD_MAX_PLAIN)
        len = PAD_MAX_PLAIN;
    if (len == 0)
        return;                     // there is no zero-length inner plaintext
    memcpy(g_pad.plain, in, len);
    pad_check(g_pad.plain, len, 0, c);
}

// The last field of each entry is the byte-level replay entry (Step
// 14): the campaigns whose input is one flat string a peer controls
// can run a preserved file through the same invariants, and are the
// ones whose findings become regression tests. `roundtrip` and
// `tamper` have none — their input is the server's own plaintext plus
// a bit position, not a peer's bytes.
static const struct fuzz_target g_targets[] = {
    { "parse", parse_case, parse_setup, parse_teardown, 1000000, 0,
      PARSE_BUCKETS, parse_replay },
    // decrypt never authenticates by chance, so "accepted" is not
    // required here — campaign 3 owns the accepting path.
    { "decrypt", dec_case, dec_setup, dec_teardown, 60000, 0,
      { "accepted", "!short", "type", "version", "!bad length",
        "!past the buffer", "!bad mac", "inner", "other", 0 },
      dec_replay },
    { "roundtrip", rt_case, rt_setup, rt_teardown, 20000, 0,
      { "!round-tripped", "short", "type", "version", "length", "bounds",
        "mac", "inner", "!zero-length refusal", 0 }, 0 },
    { "tamper", tamper_case, rt_setup, rt_teardown, 20000, 0,
      { "accepted (a finding)", "short", "type", "version", "!bad length",
        "past the buffer", "!bad mac", "inner", "zero-length refusal", 0 },
      0 },
    // The read paths cannot produce BOUNDS, and that is a property of
    // the code rather than a gap in the corpus: tls_read_record reads
    // exactly `total` bytes and then hands tls_record_parse a buffer
    // length of exactly `total`, so parse's "fragment runs past the
    // end" branch is unreachable from here. It is the size check
    // against the destination buffer (LENGTH) that stands in its place,
    // and that one is required.
    { "read_record", read_case, read_setup, read_teardown, 20000, 0,
      READ_BUCKETS, read_replay },
    { "read_prefilled", read_pre_case, read_setup, read_teardown, 20000, 0,
      READ_BUCKETS, 0 },
    { "inner_plaintext", pad_case, pad_setup, pad_teardown, 20000, 0,
      { "!unpadded", "!padded", "!all-zero refused", "!bad type refused",
        0 },
      pad_replay },
};

int main(int argc, char **argv)
{
    (void)argc;
    fuzz_disarm_harness_timeout();
    fuzz_suite("tls_record", argv[0]);

    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║  sarm — TLS record layer fuzzing (SECURITY.md Step 6)   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("  seed 0x%llx, x%llu cases\n",
           (unsigned long long)fuzz_seed(), (unsigned long long)fuzz_mult());

    TEST_SUITE("TLS record layer — generated inputs");
    fuzz_run_all(g_targets, sizeof g_targets / sizeof g_targets[0]);

    test_summary();
    return 0;
}
