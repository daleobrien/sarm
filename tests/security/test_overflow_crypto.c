// sarm security tests — crypto length-precondition corpus (Step 5)
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// ─────────────────────────────────────────────────────────────────────
// Suite: tests/security/test_overflow_crypto.c
//
// Description: The crypto module takes no lengths from the wire — its
//   callers pass compile-time constants, which is why the Step 3 bounds
//   suite and the Step 4 differential suites found no defect in it. What
//   Step 3 did find was two routines whose *documented* preconditions,
//   if violated, fail catastrophically rather than gracefully
//   (threat-model.md §9.9):
//
//     hkdf_expand        infolen > 607 walks the assembled HMAC input
//                        off the end of a 640-byte stack buffer, over
//                        the saved registers and the return address
//     hkdf_expand_label  label_len > 249 or context_len > 255 overruns
//                        the 520-byte HkdfLabel buffer, and truncates
//                        the length octet on the way
//     x25519_fe_sqr_times  count == 0 falls into a do-while and runs
//                        2^64 times: a hang, not a wrong answer
//
//   Step 5 turns all three from header comments into code. This suite
//   is what says so — and, as importantly, says the checks fire
//   *before* the read: each case hands the routine a small guarded
//   buffer together with a huge declared length, so a routine that
//   trusts the length and starts copying takes SIGSEGV on the guard
//   page instead of returning an error it never earned.
//
//   The boundary cases below the limit are here too. A check that
//   rejects 608 but also rejects 607 has not made the routine safer,
//   it has made it useless, and only the second half of the pair
//   notices.
// ─────────────────────────────────────────────────────────────────────

#include "overflow_common.h"

// ── the routines under test ─────────────────────────────────────────
// hkdf_expand and hkdf_expand_label now report their preconditions
// through the carry flag, so both need an asm wrapper rather than a
// plain extern.

// The arguments go through a small array rather than six register
// operands: with x0-x17, x19-x27 and x30 all clobbered there is no
// register left for the compiler to pass a seventh input in. x28 is
// deliberately not clobbered — neither routine touches it — so it can
// hold the array's address across the call.
static int64_t hkdf_expand_carry(const uint8_t *prk, uint64_t prklen,
                                 const uint8_t *info, uint64_t infolen,
                                 uint8_t *okm, uint64_t okmlen)
{
    uint64_t a[6] = { (uint64_t)(uintptr_t)prk, prklen,
                      (uint64_t)(uintptr_t)info, infolen,
                      (uint64_t)(uintptr_t)okm, okmlen };
    int64_t carry;
    __asm__ volatile(
        "ldp x0, x1, [%1]\n"
        "ldp x2, x3, [%1, #16]\n"
        "ldp x4, x5, [%1, #32]\n"
        "bl hkdf_expand\n"
        "cset %0, cs\n"
        : "=r"(carry)
        : "r"(a)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
          "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "x30", "cc", "memory",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v16", "v17", "v18", "v19", "v20", "v21");
    return carry;
}

static int64_t hkdf_expand_label_carry(const uint8_t *secret,
                                       const uint8_t *label, uint64_t label_len,
                                       const uint8_t *ctx, uint64_t ctx_len,
                                       uint8_t *out, uint64_t outlen)
{
    uint64_t a[8] = { (uint64_t)(uintptr_t)secret,
                      (uint64_t)(uintptr_t)label, label_len,
                      (uint64_t)(uintptr_t)ctx, ctx_len,
                      (uint64_t)(uintptr_t)out, outlen, 0 };
    int64_t carry;
    __asm__ volatile(
        "ldp x0, x1, [%1]\n"
        "ldp x2, x3, [%1, #16]\n"
        "ldp x4, x5, [%1, #32]\n"
        "ldr x6, [%1, #48]\n"
        "bl hkdf_expand_label\n"
        "cset %0, cs\n"
        : "=r"(carry)
        : "r"(a)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
          "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "x30", "cc", "memory",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
          "v16", "v17", "v18", "v19", "v20", "v21");
    return carry;
}

extern void x25519_fe_sqr_times(uint64_t *out, const uint64_t *in,
                                uint64_t count)
    __asm__("x25519_fe_sqr_times");
extern void x25519_fe_sqr(uint64_t *out, const uint64_t *in)
    __asm__("x25519_fe_sqr");

// ── hkdf_expand: infolen ────────────────────────────────────────────

struct expand_ctx {
    size_t   info_present;   // bytes actually allocated and readable
    uint64_t infolen;        // what the routine is told
    uint64_t okmlen;
};

// The info buffer holds `info_present` bytes flush against a guard
// page, but the routine is told `infolen`. When infolen is the larger
// of the two, a routine that reads before checking faults.
static void probe_expand_info(void *vctx)
{
    struct expand_ctx *c = vctx;
    struct guarded_buffer info, okm;
    uint8_t prk[32];

    for (int i = 0; i < 32; i++)
        prk[i] = (uint8_t)(i * 7 + 1);
    if (guard_alloc_side(&info, c->info_present, GUARD_OVERRUN) != 0)
        _exit(OV_BADSETUP);
    if (guard_alloc_side(&okm, c->okmlen ? c->okmlen : 1, GUARD_OVERRUN) != 0)
        _exit(OV_BADSETUP);
    guard_fill(&info, 0x5c);
    guard_fill(&okm, 0xA5);

    const int64_t carry = hkdf_expand_carry(prk, 32, info.data, c->infolen,
                                            okm.data, c->okmlen);
    if (!carry)
        _exit(OV_ACCEPTED);

    // Rejected — and a rejection must leave the output alone, or a
    // caller that ignores the flag gets half a key rather than none.
    for (size_t i = 0; i < (c->okmlen ? c->okmlen : 1); i++)
        if (okm.data[i] != 0xA5)
            _exit(OV_WRONG);
    _exit(OV_REJECTED);
}

static void test_expand_info(void)
{
    TEST_SUITE("hkdf_expand — the 607-octet info limit");

    struct expand_ctx c;

    // the two sides of the boundary, both with the info fully present,
    // so the only thing that differs is the length
    c = (struct expand_ctx){ 607, 607, 32 };
    ov_case("infolen 607 (the documented maximum) accepted", OV_ACCEPTED,
            probe_expand_info, &c);
    c = (struct expand_ctx){ 608, 608, 32 };
    ov_case("infolen 608 rejected", OV_REJECTED, probe_expand_info, &c);

    // the length the Step 3 bounds suite trapped on
    c = (struct expand_ctx){ 1023, 1023, 32 };
    ov_case("infolen 1023 rejected (was a guard-page trap in Step 3)",
            OV_REJECTED, probe_expand_info, &c);

    // Declared lengths with nothing behind them. The buffer holds 16
    // readable bytes and the guard page starts at 17; if the check ran
    // after the copy rather than before it, every one of these faults.
    static const uint64_t huge[] = {
        4096, 65535, 65536,
        0xffffffffull,          // 2^32 - 1
        0x100000000ull,         // 2^32
        0x8000000000000000ull,  // 2^63
        0xffffffffffffffffull,  // 2^64 - 1
    };
    for (unsigned i = 0; i < sizeof huge / sizeof huge[0]; i++) {
        struct expand_ctx hc = { 16, huge[i], 32 };
        char label[96];
        snprintf(label, sizeof label,
                 "infolen 0x%llx rejected without reading the info",
                 (unsigned long long)huge[i]);
        ov_case(label, OV_REJECTED, probe_expand_info, &hc);
    }

    // 32 + infolen + 1 == 640 exactly is the largest that fits; one
    // more is the first that does not. Stated the other way round from
    // the check itself, so a transcription error in either shows.
    c = (struct expand_ctx){ 640 - 32 - 1, 640 - 32 - 1, 32 };
    ov_case("32 + infolen + 1 == 640 accepted", OV_ACCEPTED,
            probe_expand_info, &c);
    c = (struct expand_ctx){ 16, 640 - 32, 32 };
    ov_case("32 + infolen + 1 == 641 rejected", OV_REJECTED,
            probe_expand_info, &c);
}

// ── hkdf_expand: okmlen ─────────────────────────────────────────────

struct okm_ctx {
    uint64_t okmlen;         // what the routine is told
    size_t   okm_present;    // bytes actually allocated
};

static void probe_expand_okm(void *vctx)
{
    struct okm_ctx *c = vctx;
    struct guarded_buffer okm;
    uint8_t prk[32], info[8];

    for (int i = 0; i < 32; i++) prk[i]  = (uint8_t)(i * 7 + 1);
    for (int i = 0; i < 8; i++)  info[i] = (uint8_t)(i + 0x20);
    if (guard_alloc_side(&okm, c->okm_present, GUARD_OVERRUN) != 0)
        _exit(OV_BADSETUP);
    guard_fill(&okm, 0xA5);

    const int64_t carry = hkdf_expand_carry(prk, 32, info, 8,
                                            okm.data, c->okmlen);
    if (!carry)
        _exit(OV_ACCEPTED);
    for (size_t i = 0; i < c->okm_present; i++)
        if (okm.data[i] != 0xA5)
            _exit(OV_WRONG);
    _exit(OV_REJECTED);
}

static void test_expand_okm(void)
{
    TEST_SUITE("hkdf_expand — the 8160-octet output limit");

    // 255 * 32: the counter octet in T(i) is one byte, so block 256
    // would reuse counter 0 and silently produce a repeat of block 1
    // rather than an error. Wrong output, not a memory fault — which is
    // why the boundary matters and why the case is here.
    struct okm_ctx c = { 8160, 8160 };
    ov_case("okmlen 8160 (255 blocks) accepted", OV_ACCEPTED,
            probe_expand_okm, &c);
    c = (struct okm_ctx){ 8161, 8161 };
    ov_case("okmlen 8161 (256 blocks) rejected", OV_REJECTED,
            probe_expand_okm, &c);

    static const uint64_t huge[] = {
        65536, 0xffffffffull, 0xffffffffffffffffull,
    };
    for (unsigned i = 0; i < sizeof huge / sizeof huge[0]; i++) {
        struct okm_ctx hc = { huge[i], 64 };
        char label[96];
        snprintf(label, sizeof label,
                 "okmlen 0x%llx rejected without writing the output",
                 (unsigned long long)huge[i]);
        ov_case(label, OV_REJECTED, probe_expand_okm, &hc);
    }

    // zero is legal and means "write nothing"
    c = (struct okm_ctx){ 0, 32 };
    ov_case("okmlen 0 accepted (empty OKM)", OV_ACCEPTED,
            probe_expand_okm, &c);
}

// ── hkdf_expand_label: label and context ────────────────────────────

struct label_ctx {
    size_t   label_present;
    uint64_t label_len;
    size_t   ctx_present;
    uint64_t ctx_len;
};

static void probe_expand_label(void *vctx)
{
    struct label_ctx *c = vctx;
    struct guarded_buffer label, context, out;
    uint8_t secret[32];

    for (int i = 0; i < 32; i++)
        secret[i] = (uint8_t)(i * 3 + 5);
    if (guard_alloc_side(&label, c->label_present ? c->label_present : 1,
                         GUARD_OVERRUN) != 0 ||
        guard_alloc_side(&context, c->ctx_present ? c->ctx_present : 1,
                         GUARD_OVERRUN) != 0 ||
        guard_alloc_side(&out, 32, GUARD_OVERRUN) != 0)
        _exit(OV_BADSETUP);
    guard_fill(&label, 'k');
    guard_fill(&context, 0x11);
    guard_fill(&out, 0xA5);

    const int64_t carry =
        hkdf_expand_label_carry(secret, label.data, c->label_len,
                                context.data, c->ctx_len, out.data, 32);
    if (!carry)
        _exit(OV_ACCEPTED);
    for (int i = 0; i < 32; i++)
        if (out.data[i] != 0xA5)
            _exit(OV_WRONG);
    _exit(OV_REJECTED);
}

static void test_expand_label(void)
{
    TEST_SUITE("hkdf_expand_label — the one-octet label and context fields");

    struct label_ctx c;

    // 6 + label_len must fit one octet, so 249 is the largest label
    c = (struct label_ctx){ 249, 249, 8, 8 };
    ov_case("label_len 249 accepted", OV_ACCEPTED, probe_expand_label, &c);
    c = (struct label_ctx){ 250, 250, 8, 8 };
    ov_case("label_len 250 rejected", OV_REJECTED, probe_expand_label, &c);

    // 256 is the value that used to be interesting for a different
    // reason: `add w7, w21, #6; strb w7` truncates, so the length octet
    // would have said 6 rather than 262 and the peer would have been
    // handed a label nobody sent
    c = (struct label_ctx){ 16, 256, 8, 8 };
    ov_case("label_len 256 rejected without reading the label", OV_REJECTED,
            probe_expand_label, &c);
    c = (struct label_ctx){ 16, 0xffffffffffffffffull, 8, 8 };
    ov_case("label_len 2^64-1 rejected without reading the label",
            OV_REJECTED, probe_expand_label, &c);

    // context is a plain one-octet field, so 255 is the maximum
    c = (struct label_ctx){ 8, 8, 255, 255 };
    ov_case("context_len 255 accepted", OV_ACCEPTED, probe_expand_label, &c);
    c = (struct label_ctx){ 8, 8, 256, 256 };
    ov_case("context_len 256 rejected", OV_REJECTED, probe_expand_label, &c);
    c = (struct label_ctx){ 8, 8, 16, 0xffffffffull };
    ov_case("context_len 2^32-1 rejected without reading the context",
            OV_REJECTED, probe_expand_label, &c);

    // both at their maxima together: 10 + 249 + 255 = 514, the largest
    // HkdfLabel there is, and the number hkdf_expand's 607 has to clear
    c = (struct label_ctx){ 249, 249, 255, 255 };
    ov_case("the largest legal HkdfLabel (514 octets) accepted", OV_ACCEPTED,
            probe_expand_label, &c);

    // a zero-length context is legal (the "key" / "finished" derivations)
    c = (struct label_ctx){ 3, 3, 0, 0 };
    ov_case("zero-length context accepted", OV_ACCEPTED,
            probe_expand_label, &c);
}

// ── x25519_fe_sqr_times: the zero count ─────────────────────────────

struct sqr_ctx { uint64_t count; };

static void probe_sqr_times(void *vctx)
{
    struct sqr_ctx *c = vctx;
    // A field element the routine has to actually move: 5 limbs, each
    // below 2^51, none of them zero or equal to another.
    uint64_t in[5]  = { 0x0007ffffffffff01ull, 0x0001234567890abull,
                        0x00055555aaaaa33ull,  0x0000000000000002ull,
                        0x0004fedcba9876ull };
    uint64_t out[5] = { 0, 0, 0, 0, 0 };
    uint64_t want[5];

    if (c->count == 0) {
        for (int i = 0; i < 5; i++) want[i] = in[i];
    } else {
        x25519_fe_sqr(want, in);
    }
    x25519_fe_sqr_times(out, in, c->count);
    for (int i = 0; i < 5; i++)
        if (out[i] != want[i])
            _exit(OV_WRONG);
    _exit(OV_REJECTED);   // "handled without hanging" is the pass here
}

static void test_sqr_times(void)
{
    TEST_SUITE("x25519_fe_sqr_times — a zero count terminates");

    // The loop is `subs x2, x2, #1 / b.ne`, so a zero count wraps to
    // 2^64-1 iterations. At roughly a nanosecond each that is about 580
    // years — the probe's 10-second timeout is what turns it into a
    // reported failure rather than a hung test run.
    struct sqr_ctx c = { 0 };
    ov_case("count 0 returns the input unchanged (a^(2^0) == a)",
            OV_REJECTED, probe_sqr_times, &c);

    // and the boundary above it still squares once, so the guard cannot
    // have swallowed the first iteration
    c = (struct sqr_ctx){ 1 };
    ov_case("count 1 still squares exactly once", OV_REJECTED,
            probe_sqr_times, &c);
}

// ── in-place aliasing on the zero-count path ────────────────────────

static void probe_sqr_alias(void *vctx)
{
    (void)vctx;
    uint64_t a[5] = { 0x0007ffffffffff01ull, 0x0001234567890abull,
                      0x00055555aaaaa33ull,  0x0000000000000002ull,
                      0x0004fedcba9876ull };
    uint64_t want[5];
    for (int i = 0; i < 5; i++) want[i] = a[i];
    x25519_fe_sqr_times(a, a, 0);   // out == in, the ladder's usual shape
    for (int i = 0; i < 5; i++)
        if (a[i] != want[i])
            _exit(OV_WRONG);
    _exit(OV_REJECTED);
}

static void test_sqr_alias(void)
{
    TEST_SUITE("x25519_fe_sqr_times — the zero-count path may alias");

    // Every other x25519 field routine documents that out may alias in,
    // and the Montgomery ladder relies on it. A copy path that wrote
    // limb 0 before reading limb 4 would be correct for distinct
    // buffers and wrong here.
    ov_case("out == in with count 0 leaves the element intact",
            OV_REJECTED, probe_sqr_alias, NULL);
}

int main(void)
{
    ov_extend_timeout();

    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  overflow: crypto length preconditions    ║\n");
    printf("╚═══════════════════════════════════════════╝\n");

    test_expand_info();
    test_expand_okm();
    test_expand_label();
    test_sqr_times();
    test_sqr_alias();

    test_summary();
    return 0;
}
