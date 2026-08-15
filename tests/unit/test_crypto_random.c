// Unit tests for src/crypto/random.S
//
// crypto_random_bytes(buf=x0, len=x1) reads len bytes from /dev/urandom.
// There's no known-answer vector for randomness, so these tests check
// what can actually be verified: the call succeeds, it doesn't touch
// bytes past the requested length, a zero-length request is a no-op,
// and two consecutive calls don't return the same bytes (with
// overwhelming probability — a collision here would mean the RNG is
// broken, not bad luck: 2^-256).

#include "test_harness.h"

extern uint64_t crypto_random_bytes(void *buf, uint64_t len)
    __asm__("crypto_random_bytes");

// crypto_random_bytes(buf=x0, len=x1) → x0=0 (or -1 on EOF) + carry set
// on failure; carry clear on success (same idiom as ch_parse).
static uint64_t rand_bytes(uint8_t *buf, uint64_t len, uint64_t *err) {
    uint64_t fail = 0, e = 0;
    asm volatile(
        "mov x0, %2\n"
        "mov x1, %3\n"
        "bl crypto_random_bytes\n"
        "cset %0, cs\n"
        "mov %1, x0\n"
        : "=r"(fail), "=r"(e)
        : "r"(buf), "r"(len)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
          "x19", "x20", "x21", "x22", "x30", "cc", "memory");
    if (err)
        *err = e;
    return fail;
}

static void test_basic(void) {
    TEST_SUITE("crypto_random_bytes basic behavior");

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    uint64_t err = 1;
    ASSERT_EQ("32 bytes succeeds", 0, rand_bytes(buf, 32, &err));

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++)
        if (buf[i] != 0)
            all_zero = 0;
    ASSERT_EQ("32 random bytes are not all zero", 0, all_zero);
}

static void test_two_calls_differ(void) {
    TEST_SUITE("crypto_random_bytes independence");

    uint8_t a[32], b[32];
    ASSERT_EQ("first call succeeds", 0, rand_bytes(a, sizeof(a), NULL));
    ASSERT_EQ("second call succeeds", 0, rand_bytes(b, sizeof(b), NULL));
    ASSERT_EQ("two calls return different bytes", 0,
              memcmp(a, b, sizeof(a)) == 0);
}

static void test_zero_length(void) {
    TEST_SUITE("crypto_random_bytes zero length");

    uint8_t sentinel[8];
    memset(sentinel, 0xAA, sizeof(sentinel));
    ASSERT_EQ("zero-length request succeeds", 0,
              rand_bytes(sentinel, 0, NULL));
    static const uint8_t expected[8] = {0xAA, 0xAA, 0xAA, 0xAA,
                                         0xAA, 0xAA, 0xAA, 0xAA};
    ASSERT_EQ("buffer untouched", 0,
              memcmp(sentinel, expected, sizeof(sentinel)));
}

static void test_no_overrun(void) {
    TEST_SUITE("crypto_random_bytes doesn't overrun");

    uint8_t buf[16];
    memset(buf, 0xAA, sizeof(buf));
    ASSERT_EQ("8-byte request succeeds", 0, rand_bytes(buf, 8, NULL));
    ASSERT_EQ("bytes past the request are untouched", 0xAA, buf[8]);
    ASSERT_EQ("bytes past the request are untouched (last)", 0xAA,
              buf[15]);
}

int main(void) {
    test_basic();
    test_two_calls_differ();
    test_zero_length();
    test_no_overrun();
    test_summary();
    return 0;
}
