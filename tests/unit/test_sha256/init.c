// Unit tests for src/crypto/sha256/init.S
//
// Tests for SHA-256 context initialization and layout verification.

#include "test_harness.h"

extern void sha256_init(void *ctx) __asm__("sha256_init");
extern const uint32_t sha256_h256[8] __asm__("sha256_h256");

// The context layout contract, mirrored from src/defs.S (SHA256_CTX_*).
// test_sha256_ctx_layout() verifies these against the real labels in
// src/crypto/data.S, so a drift in either place fails loudly.
#define SHA256_CTX_STATE   0
#define SHA256_CTX_BITLEN  32
#define SHA256_CTX_BUF     40
#define SHA256_CTX_BUFLEN  104
#define SHA256_CTX_SIZE    112

// Take the address of a pure-assembly symbol by name (mirrors
// test_tls.c): C names get an underscore prefix on Mach-O, so a plain
// extern declaration could not name these.
#define ASM_SYM_ADDR(sym) ({ \
	uintptr_t _addr; \
	asm volatile( \
		"adrp x0, " #sym "@PAGE\n\t" \
		"add  x0, x0, " #sym "@PAGEOFF\n\t" \
		"mov  %0, x0\n\t" \
		: "=r"(_addr) \
		: \
		: "x0"); \
	_addr; \
})

// offset of an asm field label from sha256_ctx
#define SHA256_OFFSET(sym) \
	((int64_t)ASM_SYM_ADDR(sym) - (int64_t)ASM_SYM_ADDR(sha256_ctx))

#define ASSERT_SHA256_OFFSET(label, sym, expected) \
	ASSERT_EQ(label, (int64_t)(expected), SHA256_OFFSET(sym))

static void test_sha256_iv(void) {
    TEST_SUITE("sha256_h256 initial state");
    static const uint32_t fips[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    for (int i = 0; i < 8; i++)
        ASSERT_EQ_HEX("H[i] == FIPS 180-4 IV", fips[i], sha256_h256[i]);
}

static void test_sha256_ctx_layout(void) {
    TEST_SUITE("sha256_ctx layout");
    ASSERT_SHA256_OFFSET("sha256_ctx_state", sha256_ctx_state,
                          SHA256_CTX_STATE);
    ASSERT_SHA256_OFFSET("sha256_ctx_bitlen", sha256_ctx_bitlen,
                          SHA256_CTX_BITLEN);
    ASSERT_SHA256_OFFSET("sha256_ctx_buf", sha256_ctx_buf,
                          SHA256_CTX_BUF);
    ASSERT_SHA256_OFFSET("sha256_ctx_buflen", sha256_ctx_buflen,
                          SHA256_CTX_BUFLEN);
    // storage extent: last field + its size == SHA256_CTX_SIZE. If
    // data.S's layout drifts from defs.S's size this catches it.
    ASSERT_EQ("storage extent == SHA256_CTX_SIZE", SHA256_CTX_SIZE,
              SHA256_OFFSET(sha256_ctx_buflen) + 8);
    // the context is 16-byte aligned so the state ld1/st1 stay aligned
    ASSERT_EQ("sha256_ctx 16-byte aligned", 0,
              (int64_t)ASM_SYM_ADDR(sha256_ctx) % 16);
}

// init must fully reset a context — even one pre-filled with garbage
// (so zeroing buf/bitlen/buflen is real, not luck of a zeroed global).
static void test_sha256_init(void) {
    TEST_SUITE("sha256_init");
    // one extra byte past the context as a canary against overruns
    static uint8_t ctx[SHA256_CTX_SIZE + 1];
    memset(ctx, 0xFF, sizeof(ctx));

    sha256_init(ctx);

    static const uint32_t fips[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    int iv_ok = 1;
    for (int i = 0; i < 8; i++)
        if (((const uint32_t *)(void *)ctx)[i] != fips[i])
            iv_ok = 0;
    ASSERT_EQ("state == FIPS 180-4 IV", 1, iv_ok);
    ASSERT_EQ("bitlen == 0", 0,
              *(uint64_t *)(void *)(ctx + SHA256_CTX_BITLEN));
    ASSERT_EQ("buflen == 0", 0,
              *(uint64_t *)(void *)(ctx + SHA256_CTX_BUFLEN));
    {
        static const uint8_t zeros[64] = {0};
        ASSERT_EQ("buf zeroed", 0,
                  memcmp(zeros, ctx + SHA256_CTX_BUF, 64));
    }
    // nothing outside the context may be written
    ASSERT_EQ("guards untouched", 0xFF, ctx[SHA256_CTX_SIZE]);
}

int main(void) {
    test_sha256_iv();
    test_sha256_ctx_layout();
    test_sha256_init();
    test_summary();
    return 0;
}
