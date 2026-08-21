// sarm security tests — HPACK integer-overflow corpus (Step 5)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_overflow_hpack.c
//
// Description: HPACK is the deepest attacker-controlled decode path in
//   the tree (threat-model.md §3.3): a 24-bit frame length reaches a
//   block decoder, which reaches a field decoder, which reaches a
//   string decoder, which reaches an integer decoder whose value is
//   then used as a length, an index or a table size. Every one of those
//   hops is a place where a wire number becomes an argument to
//   arithmetic, which is what Step 5 is about.
//
//   Three families of case:
//
//     1. Values that overflow their declared bound. The RFC 7541 §5.1
//        integer is bounded to 32 bits; the corpus includes the
//        over-long encodings and — the interesting ones — the encodings
//        whose overflow lands above bit 32 without setting it. Those
//        were accepted before Step 5, because the check tested a single
//        bit rather than the range.
//
//     2. Lengths that point outside the block. A string whose declared
//        length runs past the end of the HEADERS payload, in both the
//        literal and the Huffman form. The Huffman form is the one that
//        used to read: h2_huffman_decode expands until its output area
//        fills, so a 4 GB declared length walked ~2.5 KB past the block
//        before anything noticed.
//
//     3. Truncated encodings at the very end of a block, where the
//        decoder must stop because it has run out of input rather than
//        because a counter said so.
//
//   Every block is placed flush against a guard page, so "the decoder
//   did not read past the end" is checked by the MMU rather than by
//   the decoder agreeing with itself.
// ─────────────────────────────────────────────────────────────────────

#include "overflow_common.h"

#define H2_ERR_COMPRESSION_ERROR 9

// ── the routines under test ─────────────────────────────────────────
// Raw labels, so these use inline asm rather than externs, matching
// tests/unit/test_h2_common.h.

struct hpack_int_result { int64_t value, consumed, carry; };

static struct hpack_int_result hpack_decode_int(const uint8_t *p, int64_t n,
                                                const uint8_t *end)
{
    struct hpack_int_result r;
    int64_t value, consumed, carry;
    __asm__ volatile(
        "mov x0, %3\n"
        "mov x1, %4\n"
        "mov x2, %5\n"
        "bl h2_hpack_decode_int\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "cset %2, cs\n"
        : "=r"(value), "=r"(consumed), "=r"(carry)
        : "r"(p), "r"(n), "r"(end)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
          "x30", "cc", "memory");
    r.value = value; r.consumed = consumed; r.carry = carry;
    return r;
}

struct hpack_str_result { const uint8_t *str; int64_t len, consumed, carry; };

static struct hpack_str_result hpack_decode_string(const uint8_t *p,
                                                   const uint8_t *end)
{
    struct hpack_str_result r;
    const uint8_t *s;
    int64_t len, consumed, carry;
    __asm__ volatile(
        "mov x0, %4\n"
        "mov x1, %5\n"
        "bl h2_hpack_decode_string\n"
        "mov %0, x0\n"
        "mov %1, x1\n"
        "mov %2, x2\n"
        "cset %3, cs\n"
        : "=r"(s), "=r"(len), "=r"(consumed), "=r"(carry)
        : "r"(p), "r"(end)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x19", "x20", "x21", "x22",
          "x30", "cc", "memory");
    r.str = s; r.len = len; r.consumed = consumed; r.carry = carry;
    return r;
}

static int64_t hpack_decode_block(const uint8_t *p, int64_t len,
                                  int64_t *carry_out)
{
    int64_t count, carry;
    __asm__ volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl h2_hpack_decode_block\n"
        "mov %0, x0\n"
        "cset %1, cs\n"
        : "=r"(count), "=r"(carry)
        : "r"(p), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "x30", "cc", "memory");
    *carry_out = carry;
    return count;
}

extern void h2_hpack_dyn_reset(void) __asm__("h2_hpack_dyn_reset");

// ── case contexts ───────────────────────────────────────────────────

struct block_ctx {
    const uint8_t *bytes;
    size_t         len;
};

// Decode a whole header block placed flush against a guard page.
static void probe_block(void *vctx)
{
    struct block_ctx *c = vctx;
    struct guarded_buffer gb;
    if (ov_place(&gb, c->bytes, c->len) == NULL)
        _exit(OV_BADSETUP);
    h2_hpack_dyn_reset();
    int64_t carry;
    (void)hpack_decode_block(gb.data, (int64_t)c->len, &carry);
    _exit(carry ? OV_REJECTED : OV_ACCEPTED);
}

struct int_ctx {
    const uint8_t *bytes;
    size_t         len;
    int64_t        prefix;
    int64_t        want_value;   // checked only when the case expects success
};

static void probe_int(void *vctx)
{
    struct int_ctx *c = vctx;
    struct guarded_buffer gb;
    if (ov_place(&gb, c->bytes, c->len) == NULL)
        _exit(OV_BADSETUP);
    struct hpack_int_result r =
        hpack_decode_int(gb.data, c->prefix, gb.data + c->len);
    if (r.carry) {
        if (r.value != H2_ERR_COMPRESSION_ERROR)
            _exit(OV_WRONG);
        _exit(OV_REJECTED);
    }
    if (c->want_value >= 0 && r.value != c->want_value)
        _exit(OV_WRONG);
    _exit(OV_ACCEPTED);
}

struct str_ctx {
    const uint8_t *bytes;
    size_t         len;
};

static void probe_string(void *vctx)
{
    struct str_ctx *c = vctx;
    struct guarded_buffer gb;
    if (ov_place(&gb, c->bytes, c->len) == NULL)
        _exit(OV_BADSETUP);
    struct hpack_str_result r = hpack_decode_string(gb.data, gb.data + c->len);
    _exit(r.carry ? OV_REJECTED : OV_ACCEPTED);
}

// ── 1. the 32-bit bound on RFC 7541 §5.1 integers ───────────────────

static void test_int_bound(void)
{
    TEST_SUITE("h2_hpack_decode_int — the 32-bit value bound");

    // The encoding this suite exists for. Five continuation octets put
    // the last group at shift 28, where a 7-bit payload is worth up to
    // 2^35: the value leaves the 32-bit range without bit 32 ever being
    // set, so a `tbnz x2, #32` bound never fires. 48 of the 128
    // possible final octets escape that way — every one whose bit 4 is
    // clear. Three of them, one per run of sixteen.
    static const uint8_t esc20[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x20 };
    static const uint8_t esc40[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x40 };
    static const uint8_t esc6f[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x6f };
    struct int_ctx c;

    c = (struct int_ctx){ esc20, sizeof esc20, 7, -1 };
    ov_case("2^33 + 127 (bit 32 clear) rejected", OV_REJECTED, probe_int, &c);
    c = (struct int_ctx){ esc40, sizeof esc40, 7, -1 };
    ov_case("2^34 + 127 (bit 32 clear) rejected", OV_REJECTED, probe_int, &c);
    c = (struct int_ctx){ esc6f, sizeof esc6f, 7, -1 };
    ov_case("0x6f at shift 28 rejected", OV_REJECTED, probe_int, &c);

    // the encoding that did fire the old check — kept so a regression
    // that removes the new check but leaves the old one still fails
    static const uint8_t hi32[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x10 };
    c = (struct int_ctx){ hi32, sizeof hi32, 7, -1 };
    ov_case("2^32 + 127 (bit 32 set) rejected", OV_REJECTED, probe_int, &c);

    // an over-long encoding: the sixth continuation octet sits at shift
    // 35, past the bound, whatever it carries
    static const uint8_t longenc[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80,
                                       0x00 };
    c = (struct int_ctx){ longenc, sizeof longenc, 7, -1 };
    ov_case("shift past 32 rejected (over-long encoding)", OV_REJECTED,
            probe_int, &c);

    // all-ones, the classic
    static const uint8_t ones[] = { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0x01 };
    c = (struct int_ctx){ ones, sizeof ones, 7, -1 };
    ov_case("all-ones continuation rejected", OV_REJECTED, probe_int, &c);

    // ...and the two largest values that must still be *accepted*, so
    // the suite cannot pass by rejecting everything
    static const uint8_t max32[] = { 0x7f, 0x80, 0x80, 0x80, 0x80, 0x0f };
    c = (struct int_ctx){ max32, sizeof max32, 7,
                          (int64_t)127 + ((int64_t)0x0f << 28) };
    ov_case("largest value below 2^32 accepted", OV_ACCEPTED, probe_int, &c);
    static const uint8_t small[] = { 0x7f, 0x00 };
    c = (struct int_ctx){ small, sizeof small, 7, 127 };
    ov_case("127 still accepted", OV_ACCEPTED, probe_int, &c);

    // every prefix width, since the mask is computed from N
    static const int64_t prefixes[] = { 4, 5, 6, 7, 8 };
    for (unsigned i = 0; i < sizeof prefixes / sizeof prefixes[0]; i++) {
        static const uint8_t esc[] = { 0xff, 0x80, 0x80, 0x80, 0x80, 0x20 };
        struct int_ctx pc = { esc, sizeof esc, prefixes[i], -1 };
        char label[64];
        snprintf(label, sizeof label,
                 "N=%d: overflow above bit 32 rejected", (int)prefixes[i]);
        ov_case(label, OV_REJECTED, probe_int, &pc);
    }
}

// ── 2. reads that would leave the block ─────────────────────────────

static void test_int_truncation(void)
{
    TEST_SUITE("h2_hpack_decode_int — reads bounded by the block");

    // A prefix of all ones promises continuation octets. Put it at the
    // very last byte of the block and there are none: the decoder must
    // stop because it has run out of input. Before Step 5 the loop was
    // bounded only by the shift counter, so it read up to five octets
    // past the block — here, straight into the guard page.
    static const uint8_t trunc1[] = { 0x7f };
    struct int_ctx c = { trunc1, sizeof trunc1, 7, -1 };
    ov_case("prefix with no continuation octet rejected", OV_REJECTED,
            probe_int, &c);

    static const uint8_t trunc2[] = { 0x7f, 0x80 };
    c = (struct int_ctx){ trunc2, sizeof trunc2, 7, -1 };
    ov_case("continuation run cut short at 1 octet rejected", OV_REJECTED,
            probe_int, &c);

    static const uint8_t trunc4[] = { 0x7f, 0x80, 0x80, 0x80 };
    c = (struct int_ctx){ trunc4, sizeof trunc4, 7, -1 };
    ov_case("continuation run cut short at 3 octets rejected", OV_REJECTED,
            probe_int, &c);

    // a zero-length block: not even the prefix octet is readable
    static const uint8_t empty[] = { 0x00 };
    c = (struct int_ctx){ empty, 0, 7, -1 };
    ov_case("empty input rejected without reading", OV_REJECTED,
            probe_int, &c);
}

static void test_string_bounds(void)
{
    TEST_SUITE("h2_hpack_decode_string — lengths bounded before the read");

    // A literal string that claims more bytes than the block holds.
    // This one never read — the literal path is zero-copy, so the
    // pointer was handed back unread and h2_hpack_decode_block caught
    // the overrun afterwards. It is here because "caught afterwards"
    // stops being good enough the moment a caller uses the value, which
    // h2_hpack_decode_field's dynamic-table insert does.
    static const uint8_t lit[] = { 0x7f, 0x00, 'a', 'b', 'c' };  // len 127
    struct str_ctx c = { lit, sizeof lit };
    ov_case("literal length past the block rejected", OV_REJECTED,
            probe_string, &c);

    // A Huffman string claiming 4 GB inside a 6-byte block. This is the
    // one that read: h2_huffman_decode is handed a length and expands
    // until its 4096-byte output area fills, so it walked roughly 2.5 KB
    // past the block. With the block flush against a guard page, that
    // walk is a SIGSEGV and the case reports OUT OF BOUNDS.
    static const uint8_t huff4g[] = { 0xff, 0x80, 0x80, 0x80, 0x0f, 0x00 };
    c = (struct str_ctx){ huff4g, sizeof huff4g };
    ov_case("Huffman length of ~2^32 rejected before expanding", OV_REJECTED,
            probe_string, &c);

    // the same shape one byte over, which is where an off-by-one in the
    // new check would show
    static const uint8_t huff_over[] = { 0x83, 0xff, 0xff };  // 3 encoded, 2 present
    c = (struct str_ctx){ huff_over, sizeof huff_over };
    ov_case("Huffman length one past the block rejected", OV_REJECTED,
            probe_string, &c);

    static const uint8_t lit_over[] = { 0x03, 'a', 'b' };      // 3 declared, 2 present
    c = (struct str_ctx){ lit_over, sizeof lit_over };
    ov_case("literal length one past the block rejected", OV_REJECTED,
            probe_string, &c);

    // ...and the exactly-fitting versions, which must still be accepted
    static const uint8_t lit_fit[] = { 0x03, 'a', 'b', 'c' };
    c = (struct str_ctx){ lit_fit, sizeof lit_fit };
    ov_case("literal that exactly fills the block accepted", OV_ACCEPTED,
            probe_string, &c);

    // "www.example.com" Huffman-coded (RFC 7541 C.4.1), 12 encoded octets
    static const uint8_t huff_fit[] = {
        0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
        0x90, 0xf4, 0xff
    };
    c = (struct str_ctx){ huff_fit, sizeof huff_fit };
    ov_case("Huffman string that exactly fills the block accepted",
            OV_ACCEPTED, probe_string, &c);
}

// ── 3. the same shapes, through the block decoder ───────────────────

static void test_block(void)
{
    TEST_SUITE("h2_hpack_decode_block — the corpus through the real entry");

    // Literal with incremental indexing (§6.2.1), new name: the field
    // decoder hands the name and value straight to h2_hpack_dyn_insert,
    // which copies both into the table arena. A name length larger than
    // the block therefore used to be *copied* out of adjacent memory
    // and rejected afterwards. 0x40 = literal/incremental, index 0
    // (new name), then a name length of 127 in a 4-byte block.
    static const uint8_t insert_over[] = { 0x40, 0x7f, 0x00, 'a' };
    struct block_ctx c = { insert_over, sizeof insert_over };
    ov_case("oversized name is not copied into the dynamic table",
            OV_REJECTED, probe_block, &c);

    // the same, with the overrun in the value rather than the name
    static const uint8_t insert_val[] = { 0x40, 0x01, 'a', 0x7f, 0x00 };
    c = (struct block_ctx){ insert_val, sizeof insert_val };
    ov_case("oversized value is not copied into the dynamic table",
            OV_REJECTED, probe_block, &c);

    // Huffman name on the insert path — the read case, through the
    // entry point the server actually calls
    static const uint8_t insert_huff[] = { 0x40, 0xff, 0x80, 0x80, 0x80, 0x0f,
                                           0x00 };
    c = (struct block_ctx){ insert_huff, sizeof insert_huff };
    ov_case("oversized Huffman name refused before expansion", OV_REJECTED,
            probe_block, &c);

    // an indexed field whose index overflows 32 bits
    static const uint8_t idx_over[] = { 0xff, 0x80, 0x80, 0x80, 0x80, 0x20 };
    c = (struct block_ctx){ idx_over, sizeof idx_over };
    ov_case("index above 2^32 rejected", OV_REJECTED, probe_block, &c);

    // an indexed field with a large but in-range index — out of the
    // static+dynamic space, so still an error, but reached by the table
    // lookup rather than by the integer bound
    static const uint8_t idx_big[] = { 0xff, 0xff, 0xff, 0xff, 0x0f };
    c = (struct block_ctx){ idx_big, sizeof idx_big };
    ov_case("index beyond the table rejected", OV_REJECTED, probe_block, &c);

    // dynamic table size update above the advertised 4096 (§6.3), and
    // one whose encoding overflows outright
    static const uint8_t size_over[] = { 0x3f, 0xe2, 0x1f };  // 31 + 4067 = 4098
    c = (struct block_ctx){ size_over, sizeof size_over };
    ov_case("size update above the advertised maximum rejected", OV_REJECTED,
            probe_block, &c);

    static const uint8_t size_huge[] = { 0x3f, 0x80, 0x80, 0x80, 0x80, 0x20 };
    c = (struct block_ctx){ size_huge, sizeof size_huge };
    ov_case("size update above 2^32 rejected", OV_REJECTED, probe_block, &c);

    // truncated at every length: take a valid two-field block and cut
    // it short one byte at a time. Every prefix must be refused without
    // reading past what is left.
    static const uint8_t good[] = {
        0x82,                                       // :method GET
        0x44, 0x03, '/', 'a', 'b',                  // :path /ab, no indexing
    };
    for (size_t n = 1; n < sizeof good; n++) {
        struct block_ctx tc = { good, n };
        char label[80];
        snprintf(label, sizeof label,
                 "truncated to %zu of %zu bytes handled in bounds",
                 n, sizeof good);
        // Some prefixes are legal blocks in their own right (0x82 alone
        // is a complete indexed field), so the assertion here is only
        // that the decoder stays inside the block — which the guard
        // page checks and ov_case reports. Accept either verdict.
        int verdict = 0;
        const int r = guard_probe_status(probe_block, &tc, &verdict);
        if (r == GUARD_PROBE_FAULT)
            _FAIL("%s — OUT OF BOUNDS", label);
        else if (r == GUARD_PROBE_TIMEOUT)
            _FAIL("%s — DID NOT TERMINATE", label);
        else if (r != GUARD_PROBE_OK || verdict == OV_BADSETUP)
            _FAIL("%s — probe error", label);
        else
            _PASS(label);
    }

    // the whole block, which must still decode
    c = (struct block_ctx){ good, sizeof good };
    ov_case("the intact block still decodes", OV_ACCEPTED, probe_block, &c);
}

int main(void)
{
    ov_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  overflow: HPACK length arithmetic        ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    test_int_bound();
    test_int_truncation();
    test_string_bounds();
    test_block();

    test_summary();
    return 0;
}
