// Unit tests for src/crypto/random.S
//
// crypto_random_bytes(buf=x0, len=x1) fills len bytes from the kernel
// CSPRNG (getentropy on macOS, getrandom on Linux).
// There's no known-answer vector for randomness, so these tests check
// what can actually be verified: the call succeeds, it doesn't touch
// bytes past the requested length, a zero-length request is a no-op,
// and two consecutive calls don't return the same bytes (with
// overwhelming probability — a collision here would mean the RNG is
// broken, not bad luck: 2^-256).
//
// test_chunked below covers the loop specifically. getentropy refuses
// more than 256 bytes in one call, so anything larger is filled in
// several passes, and an off-by-one in that loop would leave a whole
// 256-byte stretch of the buffer untouched — which is exactly the kind
// of bug that produces a predictable key while every other test here
// still passes.

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

// Sizes around and well past getentropy's 256-byte per-call maximum,
// so the chunking loop runs 1, 2, 3 and 4 times. The buffer is
// pre-filled with a sentinel; a skipped or misaligned chunk leaves at
// least 256 sentinel bytes behind, while a correctly filled buffer
// leaves only however many random bytes happen to equal the sentinel
// (size/256 on average, so 4 for the largest case here). The threshold
// sits far above the one and far below the other.
static void test_chunked(void) {
    TEST_SUITE("crypto_random_bytes chunking past 256 bytes");

    static const uint64_t sizes[] = {255, 256, 257, 512, 1000};
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        uint64_t n = sizes[s];
        static uint8_t buf[1024 + 8];
        memset(buf, 0xAA, n + 8);
        ASSERT_EQ("large request succeeds", 0, rand_bytes(buf, n, NULL));

        uint64_t sentinels = 0;
        for (uint64_t i = 0; i < n; i++)
            if (buf[i] == 0xAA)
                sentinels++;
        ASSERT_TRUE("every chunk of the buffer was written",
                    sentinels < 64);

        int guard_ok = 1;
        for (int g = 0; g < 8; g++)
            if (buf[n + g] != 0xAA)
                guard_ok = 0;
        ASSERT_TRUE("nothing written past the requested length", guard_ok);
    }

    // Two large fills must differ across their whole length, not just in
    // the first chunk.
    static uint8_t a[512], b[512];
    ASSERT_EQ("first large call succeeds", 0, rand_bytes(a, sizeof(a), NULL));
    ASSERT_EQ("second large call succeeds", 0, rand_bytes(b, sizeof(b), NULL));
    ASSERT_EQ("large fills differ in the first chunk", 0,
              memcmp(a, b, 256) == 0);
    ASSERT_EQ("large fills differ in the second chunk", 0,
              memcmp(a + 256, b + 256, 256) == 0);
}

int main(void) {
    test_basic();
    test_two_calls_differ();
    test_zero_length();
    test_no_overrun();
    test_chunked();
    test_summary();
    return 0;
}
