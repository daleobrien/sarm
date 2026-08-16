// Unit tests for tls_transcript_init
#include "common.h"

// ── tests ────────────────────────────────────────────────────────────

static void test_transcript_ctx_layout(void) {
    TEST_SUITE("tls_transcript_ctx layout");
    ASSERT_TCTX_OFFSET("tls_transcript_ctx_state", tls_transcript_ctx_state,
                       SHA256_CTX_STATE);
    ASSERT_TCTX_OFFSET("tls_transcript_ctx_bitlen", tls_transcript_ctx_bitlen,
                       SHA256_CTX_BITLEN);
    ASSERT_TCTX_OFFSET("tls_transcript_ctx_buf", tls_transcript_ctx_buf,
                       SHA256_CTX_BUF);
    ASSERT_TCTX_OFFSET("tls_transcript_ctx_buflen", tls_transcript_ctx_buflen,
                       SHA256_CTX_BUFLEN);
    // storage extent: last field + its size == SHA256_CTX_SIZE. If
    // data.S's layout drifts from defs.S's size this catches it.
    ASSERT_EQ("storage extent == SHA256_CTX_SIZE", SHA256_CTX_SIZE,
              TCTX_OFFSET(tls_transcript_ctx_buflen) + 8);
    // the context is 16-byte aligned so the state ld1/st1 stay aligned
    ASSERT_EQ("tls_transcript_ctx 16-byte aligned", 0,
              (int64_t)ASM_SYM_ADDR(tls_transcript_ctx) % 16);
}

// init must fully reset the transcript context — including after a
// previous test has hashed a message into it — so a fresh handshake
// never inherits stale state.
static void test_transcript_init_seeds(void) {
    TEST_SUITE("tls_transcript_init seeds a fresh context");
    static const uint8_t body[] = "stale handshake message";
    uint8_t d[32];

    // dirty the context first (must survive the init below)
    tls_transcript_init();
    tls_transcript_add(1, body, sizeof(body) - 1);
    tls_transcript_hash(d);

    tls_transcript_init();
    const uint8_t *ctx = (const uint8_t *)ASM_SYM_ADDR(tls_transcript_ctx);
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
}

// init must discard everything hashed so far, returning the transcript
// to the empty-hash state.
static void test_transcript_init_resets(void) {
    TEST_SUITE("init discards a previous transcript");
    static const uint8_t body[] = "some handshake message";
    uint8_t h1[32], h2[32], empty[32];

    tls_transcript_init();
    tls_transcript_add(1, body, sizeof(body) - 1);
    tls_transcript_hash(h1);

    tls_transcript_init();
    tls_transcript_hash(h2);
    ref_digest((const uint8_t *)"", 0, empty);
    ASSERT_TRUE("after re-init the hash is SHA256(\"\")",
                digest_eq(empty, h2));
    ASSERT_FALSE("re-init changes the hash", digest_eq(h1, h2));
}

int main(void) {
    test_transcript_ctx_layout();
    test_transcript_init_seeds();
    test_transcript_init_resets();
    test_summary();
    return 0;
}
