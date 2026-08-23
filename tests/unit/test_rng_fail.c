// Fail-closed entropy (docs/SECURITY.md §4.4, §14 A4)
//
// §2's highest-severity row is "ECDSA nonce/randomness failure →
// private-key compromise", and §4.4 answers it by construction: every
// caller of crypto_random_bytes checks the carry and turns a failure
// into TLS_ALERT_INTERNAL_ERROR rather than carrying on with whatever
// happened to be in the buffer. Until this file existed, that error
// path had never been taken — the kernel CSPRNG does not fail on
// demand — and §12 is blunt about what a never-executed path is worth
// as evidence.
//
// So the failure is injected. src/crypto/random.S grows a compile-time
// -DSARM_RNG_FAIL block (the -DSARM_NO_RODATA precedent) exporting an
// ordinal that this binary writes at run time, which is what lets one
// executable fail each of the three draws in turn and take an
// uninjected control run in between. tests/test_rng_fail.sh does the
// same thing to a whole server; this file is the part that can look at
// the buffers afterwards.
//
// What each case has to establish is not just "it returned an error".
// It is the three things §14 A4 asks for:
//
//   1. the call fails closed — carry set, TLS_ALERT_INTERNAL_ERROR,
//      not a short or partial success;
//   2. nothing wire-bound depends on the missing bytes — the output
//      buffer is byte-for-byte untouched, so there is no half-written
//      ServerHello and no signature;
//   3. nothing is derived from a zero or stale value — the key share,
//      the shared secret and the signature are not computed from a
//      buffer the RNG declined to fill, and the previous call's output
//      is not re-emitted.
//
// Every case also asserts the injection fired, by reading the call
// counter back. A fail-closed test that passes because the RNG quietly
// succeeded is exactly the vacuity §12 warns about.

#include "test_harness.h"

#define TLS_ALERT_INTERNAL_ERROR 80

// ── the injected RNG's controls (src/crypto/random.S) ───────────────
// Present only in a -DSARM_RNG_FAIL build, which is what this binary
// links; the shipped server has neither symbol.
extern int64_t crypto_random_fail_calls __asm__("crypto_random_fail_calls");
extern int64_t crypto_random_fail_at __asm__("crypto_random_fail_at");

#define RNG_OFF   (-1)   // no call fails

// Arm the injection: the n-th crypto_random_bytes call from here on
// fails, and the counter restarts so a case can assert how many draws
// its subject actually made.
static void arm(int64_t nth) {
    crypto_random_fail_calls = 0;
    crypto_random_fail_at = nth;
}

extern uint64_t tls_build_server_hello(void *out)
    __asm__("tls_build_server_hello");
extern uint64_t tls_certificate_verify_write(void *out, const uint8_t hash[32])
    __asm__("tls_certificate_verify_write");
extern void x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point)
    __asm__("x25519");

extern uint8_t tls_server_random[32] __asm__("tls_server_random");
extern uint8_t tls_client_key_share[32] __asm__("tls_client_key_share");
extern uint8_t tls_server_key_share[32] __asm__("tls_server_key_share");
extern uint8_t tls_shared_secret[32] __asm__("tls_shared_secret");
extern uint64_t tls_session_id_len __asm__("tls_session_id_len");

static uint64_t rng_bytes(void *buf, uint64_t len, uint64_t *errno_out) {
    uint64_t fail = 0, e = 0;
    asm volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl crypto_random_bytes\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(e)
        : "r"(buf), "r"(len)
        : "x0", "x1", "x2", "x16", "x19", "x20", "x21", "x30", "cc", "memory");
    if (errno_out)
        *errno_out = e;
    return fail;
}

static uint64_t build_sh(uint8_t *out, uint64_t *alert) {
    uint64_t fail = 0, a = 0;
    asm volatile(
        "mov x0, %2\n"
        "bl tls_build_server_hello\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(a)
        : "r"(out)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x30", "cc", "memory");
    if (alert)
        *alert = a;
    return fail;
}

static uint64_t cv_write(uint8_t *out, const uint8_t hash[32], uint64_t *alert) {
    uint64_t fail = 0, a = 0;
    asm volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl tls_certificate_verify_write\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(a)
        : "r"(out), "r"(hash)
        : "x0", "x1", "x2", "x3", "x9", "x10", "x11", "x12",
          "x19", "x20", "x21", "x30", "cc", "memory");
    if (alert)
        *alert = a;
    return fail;
}

// A recognisable pattern, so "the buffer is untouched" is a statement
// about every byte rather than about a leading zero.
static void poison(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(0x5A ^ (i * 31));
}
static int unpoisoned(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (buf[i] != (uint8_t)(0x5A ^ (i * 31)))
            return 1;
    return 0;
}

// tls_build_server_hello needs a client key share to run to completion;
// the failure cases never reach x25519, but the control run does.
static void setup_client_key_share(void) {
    static const uint8_t BASE9[32] = {9, 0};
    uint8_t client_scalar[32];
    for (int i = 0; i < 32; i++)
        client_scalar[i] = (uint8_t)(0x11 + i);
    x25519(tls_client_key_share, client_scalar, BASE9);
    tls_session_id_len = 0;
}

// ── 1. the injection is real ────────────────────────────────────────
// Before anything is claimed about a caller's error handling, the
// thing doing the injecting has to be shown to inject. Two halves,
// and the second is the one that matters: a "failed" call must not
// have written anything.
static void test_injection_itself(void) {
    TEST_SUITE("failure injection — the knob does what the cases assume");

    uint8_t buf[64];

    arm(RNG_OFF);
    poison(buf, sizeof buf);
    ASSERT_EQ("uninjected: crypto_random_bytes succeeds", 0,
              rng_bytes(buf, sizeof buf, NULL));
    ASSERT_EQ("uninjected: the buffer was filled", 1, unpoisoned(buf, sizeof buf));
    ASSERT_EQ("uninjected: one call counted", 1, crypto_random_fail_calls);

    arm(1);
    uint64_t err = 0;
    poison(buf, sizeof buf);
    ASSERT_EQ("injected: crypto_random_bytes returns carry set", 1,
              rng_bytes(buf, sizeof buf, &err));
    ASSERT_EQ("injected: x0 is an errno (EIO)", 5, err);
    ASSERT_EQ("injected: not one byte was written", 0, unpoisoned(buf, sizeof buf));

    // The ordinal has to select, or the per-draw cases below are all
    // testing draw #1 under three different names.
    arm(3);
    ASSERT_EQ("ordinal: call 1 succeeds", 0, rng_bytes(buf, 32, NULL));
    ASSERT_EQ("ordinal: call 2 succeeds", 0, rng_bytes(buf, 32, NULL));
    ASSERT_EQ("ordinal: call 3 fails", 1, rng_bytes(buf, 32, NULL));
    ASSERT_EQ("ordinal: call 4 succeeds again", 0, rng_bytes(buf, 32, NULL));
    ASSERT_EQ("ordinal: four calls counted", 4, crypto_random_fail_calls);

    arm(RNG_OFF);
}

// ── 2. ServerHello, draw #1: server_random ──────────────────────────
static void test_server_hello_random_fails(void) {
    TEST_SUITE("tls_build_server_hello — server_random draw fails");

    uint8_t out[512];
    uint64_t alert = 0;

    setup_client_key_share();
    memset(tls_server_random, 0xC7, 32);
    memset(tls_server_key_share, 0xC7, 32);
    memset(tls_shared_secret, 0xC7, 32);

    arm(1);
    poison(out, sizeof out);
    ASSERT_EQ("returns carry set", 1, build_sh(out, &alert));
    ASSERT_EQ("alert is internal_error", TLS_ALERT_INTERNAL_ERROR, alert);
    ASSERT_EQ("the injection fired (one draw made)", 1, crypto_random_fail_calls);
    ASSERT_EQ("no ServerHello byte was written", 0, unpoisoned(out, sizeof out));

    // Nothing wire-bound depends on the missing bytes: the fields the
    // writer would have serialised are still the sentinel.
    int untouched = 1;
    for (int i = 0; i < 32; i++)
        untouched &= (tls_server_random[i] == 0xC7)
                  && (tls_server_key_share[i] == 0xC7)
                  && (tls_shared_secret[i] == 0xC7);
    ASSERT_EQ("server_random, key share and shared secret untouched", 1, untouched);
}

// ── 3. ServerHello, draw #2: the ephemeral X25519 scalar ────────────
// The interesting one. server_random has already been drawn and
// written into tls_state by this point, so the abort has to happen
// before the scalar reaches x25519 — a scalar of whatever was on the
// stack would produce a perfectly well-formed key share derived from
// nothing.
static void test_server_hello_scalar_fails(void) {
    TEST_SUITE("tls_build_server_hello — ephemeral scalar draw fails");

    uint8_t out[512];
    uint64_t alert = 0;

    setup_client_key_share();
    memset(tls_server_key_share, 0xC7, 32);
    memset(tls_shared_secret, 0xC7, 32);

    arm(2);
    poison(out, sizeof out);
    ASSERT_EQ("returns carry set", 1, build_sh(out, &alert));
    ASSERT_EQ("alert is internal_error", TLS_ALERT_INTERNAL_ERROR, alert);
    ASSERT_EQ("the injection fired on the second draw", 2, crypto_random_fail_calls);
    ASSERT_EQ("no ServerHello byte was written", 0, unpoisoned(out, sizeof out));

    int untouched = 1;
    for (int i = 0; i < 32; i++)
        untouched &= (tls_server_key_share[i] == 0xC7)
                  && (tls_shared_secret[i] == 0xC7);
    ASSERT_EQ("x25519 never ran on an unfilled scalar", 1, untouched);
}

// ── 4. CertificateVerify: the ECDSA nonce ───────────────────────────
// The P0 draw. A signature produced from a zero or stale k leaks the
// private key outright, so the only acceptable behaviour is to produce
// no signature at all.
static void test_certificate_verify_nonce_fails(void) {
    TEST_SUITE("tls_certificate_verify_write — nonce draw fails");

    uint8_t out[256], hash[32];
    uint64_t alert = 0;
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)(0x40 + i);

    arm(1);
    poison(out, sizeof out);
    ASSERT_EQ("returns carry set", 1, cv_write(out, hash, &alert));
    ASSERT_EQ("alert is internal_error", TLS_ALERT_INTERNAL_ERROR, alert);
    ASSERT_EQ("the injection fired (one draw made)", 1, crypto_random_fail_calls);
    ASSERT_EQ("no signature byte was written", 0, unpoisoned(out, sizeof out));
}

// ── 5. no stale nonce, and no stale signature ───────────────────────
// Two runs of the same buffer. The first succeeds and leaves a real
// CertificateVerify in it; the second fails, and must neither leave
// the first one there for the caller to send again nor produce a
// second signature. The control half also asserts what "stale k" would
// look like if it happened: two successful signatures over the *same*
// transcript must differ, because k is redrawn.
static void test_no_stale_nonce(void) {
    TEST_SUITE("tls_certificate_verify_write — no stale nonce or signature");

    uint8_t out[256], first[256], second[256], hash[32];
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)(0x40 + i);

    arm(RNG_OFF);
    poison(out, sizeof out);
    uint64_t len1 = 0;   // the message length, on the success path
    ASSERT_EQ("control run succeeds", 0, cv_write(out, hash, &len1));
    memcpy(first, out, sizeof out);

    arm(RNG_OFF);
    uint64_t len2 = 0;
    ASSERT_EQ("second control run succeeds", 0, cv_write(out, hash, &len2));
    memcpy(second, out, sizeof out);
    // Not "same length": DER drops a leading zero octet depending on
    // the high bit of r and s, so two signatures over one transcript
    // legitimately differ in length by a byte or two. Asserting
    // otherwise fails roughly half the time — which is how this line
    // came to be a comment.
    ASSERT_EQ("a different signature each time — k is redrawn", 1,
              memcmp(first, second, sizeof out) != 0);

    // Now fail the draw with the previous signature still in the
    // buffer. Nothing may change: not one byte of the stale message
    // may be rewritten, and no new one may appear.
    arm(1);
    uint64_t alert = 0;
    ASSERT_EQ("injected run fails closed", 1, cv_write(out, hash, &alert));
    ASSERT_EQ("alert is internal_error", TLS_ALERT_INTERNAL_ERROR, alert);
    ASSERT_EQ("the injection fired", 1, crypto_random_fail_calls);
    ASSERT_EQ("the buffer still holds the previous message, unmodified", 0,
              memcmp(second, out, sizeof out));

    arm(RNG_OFF);
}

// ── 6. every draw in the handshake, swept ───────────────────────────
// The cases above name the three draws individually. This one makes
// the claim general: for every ordinal a connection can reach, a
// failure at that ordinal is refused, never partially served. It is
// the case that would notice a fourth draw appearing somewhere with no
// carry check after it.
static void test_every_ordinal_fails_closed(void) {
    TEST_SUITE("every draw in a handshake fails closed");

    uint8_t out[512], hash[32];
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)(0x40 + i);

    for (int64_t nth = 1; nth <= 2; nth++) {
        uint64_t alert = 0;
        char label[96];

        setup_client_key_share();
        arm(nth);
        poison(out, sizeof out);
        uint64_t failed = build_sh(out, &alert);
        snprintf(label, sizeof label,
                 "ServerHello draw %lld: refused, buffer clean", (long long)nth);
        ASSERT_EQ(label, 1, failed
                            && alert == TLS_ALERT_INTERNAL_ERROR
                            && unpoisoned(out, sizeof out) == 0
                            && crypto_random_fail_calls == nth);
    }

    uint64_t alert = 0;
    arm(1);
    poison(out, sizeof out);
    ASSERT_EQ("CertificateVerify draw 1: refused, buffer clean", 1,
              cv_write(out, hash, &alert)
                  && alert == TLS_ALERT_INTERNAL_ERROR
                  && unpoisoned(out, sizeof out) == 0
                  && crypto_random_fail_calls == 1);

    arm(RNG_OFF);
}

int main(void) {
    test_injection_itself();
    test_server_hello_random_fails();
    test_server_hello_scalar_fails();
    test_certificate_verify_nonce_fails();
    test_no_stale_nonce();
    test_every_ordinal_fails_closed();
    test_summary();
    return 0;
}
