// Unit tests for src/tls/transcript.S (PLAN.MD Phase 9)
//
// The TLS 1.3 handshake transcript (RFC 8446 §4.4.1) is the running
// SHA-256 over every handshake message in the exact order they are
// exchanged, each in its wire form:
//
//     transcript = SHA256(msg1 || msg2 || ... || msgN)
//     msg_i      = HandshakeType(1) || uint24 length(3) || body
//
// The handshake message headers are part of the transcript; the 5-byte
// TLS record header is not. The asm module operates on the
// per-connection global tls_transcript_ctx (src/tls/data.S) and exports
// three entry points:
//
//   tls_transcript_init  — fresh transcript (PLAN.MD §9.1)
//   tls_transcript_add   — feed one handshake message (type, body, len),
//                          synthesising the 4-byte header
//   tls_transcript_hash  — snapshot the current hash without destroying
//                          the running transcript (PLAN.MD §9.2)
//
// These tests:
//   1. pin tls_transcript_ctx against the SHA256_CTX_* offsets in
//      defs.S and verify init seeds the context (state IV, zeroed
//      counters) — the same contract test_sha256.c applies to
//      sha256_ctx;
//   2. check known TLS transcript sequences against externally computed
//      SHA-256 values (python3 hashlib), including a realistic
//      ClientHello → Finished server transcript and a 300-byte message
//      that exercises the uint24 length field (PLAN.MD §9 acceptance);
//   3. cross-check the transcript against an independent plain-C
//      SHA-256 reference over every padding boundary (0/1/3/55/56/
//      63/64/65/127/128/129/255/256/300) as single and multi-message
//      transcripts — this is what makes the header encoding, the
//      ordering, and the streaming boundaries fail loudly if wrong;
//   4. verify the snapshot semantics: tls_transcript_hash must be
//      repeatable and must not disturb the running transcript;
//   5. verify init discards a previous transcript.

#include "test_harness.h"

// ── asm entry points (bare labels, pinned via __asm__) ───────────────

extern void tls_transcript_init(void) __asm__("tls_transcript_init");
extern void tls_transcript_add(uint8_t type, const void *msg,
                               uint64_t len) __asm__("tls_transcript_add");
extern void tls_transcript_hash(void *out) __asm__("tls_transcript_hash");

// ── handshake types (mirrored from src/defs.S, RFC 8446 §4) ──────────

#define TLS_HS_CLIENT_HELLO          1
#define TLS_HS_SERVER_HELLO          2
#define TLS_HS_ENCRYPTED_EXTENSIONS  8
#define TLS_HS_CERTIFICATE           11
#define TLS_HS_CERTIFICATE_VERIFY    15
#define TLS_HS_FINISHED              20

// ── the SHA-256 context layout contract, mirrored from src/defs.S ────
// (SHA256_CTX_*). test_transcript_ctx_layout() verifies these against
// the real tls_transcript_ctx_* labels in src/tls/data.S.

#define SHA256_CTX_STATE   0
#define SHA256_CTX_BITLEN  32
#define SHA256_CTX_BUF     40
#define SHA256_CTX_BUFLEN  104
#define SHA256_CTX_SIZE    112

// Take the address of a pure-assembly symbol by name (mirrors
// test_sha256.c / test_tls.c): C names get an underscore prefix on
// Mach-O, so a plain extern declaration could not name these.
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

// offset of an asm field label from tls_transcript_ctx
#define TCTX_OFFSET(sym) \
	((int64_t)ASM_SYM_ADDR(sym) - (int64_t)ASM_SYM_ADDR(tls_transcript_ctx))

#define ASSERT_TCTX_OFFSET(label, sym, expected) \
	ASSERT_EQ(label, (int64_t)(expected), TCTX_OFFSET(sym))

// ── independent C reference SHA-256 (FIPS 180-4) ─────────────────────
// Same reference test_sha256.c uses; it is itself pinned by the NIST
// known-answer vectors there, so a mismatch here means the transcript
// (header synthesis, ordering, or feeding) is wrong, not the hash.

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
static uint32_t big_s0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t big_s1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// Compress one 64-byte block into h (FIPS 180-4 §6.2.2).
static void ref_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int t = 0; t < 16; t++)
        w[t] = ((uint32_t)block[4 * t] << 24) |
               ((uint32_t)block[4 * t + 1] << 16) |
               ((uint32_t)block[4 * t + 2] << 8) |
               (uint32_t)block[4 * t + 3];
    for (int t = 16; t < 64; t++)
        w[t] = sig1(w[t - 2]) + w[t - 7] + sig0(w[t - 15]) + w[t - 16];

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = hh + big_s1(e) + ch(e, f, g) + K256[t] + w[t];
        uint32_t t2 = big_s0(a) + maj(a, b, c);
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// Enough for the largest transcript under test (~900 bytes padded).
#define PAD_BUF_SIZE (1 << 20)

// Pad the tail of a message: msg[0..msg_len) followed by 0x80, zeros,
// and the total message length (in bits) as a big-endian 64-bit word.
// Writes into out and returns the number of 64-byte blocks produced.
static size_t pad_tail(const uint8_t *msg, size_t msg_len,
                       uint64_t total_bits, uint8_t *out) {
    size_t i;
    for (i = 0; i < msg_len; i++)
        out[i] = msg[i];
    out[msg_len] = 0x80;
    size_t padlen = ((msg_len + 9 + 63) / 64) * 64;
    for (i = msg_len + 1; i < padlen - 8; i++)
        out[i] = 0;
    for (i = 0; i < 8; i++)
        out[padlen - 8 + i] = (uint8_t)(total_bits >> (56 - 8 * i));
    return padlen / 64;
}

// Serialize the state as the 32 big-endian digest bytes.
static void digest_bytes(const uint32_t h[8], uint8_t out[32]) {
    for (int i = 0; i < 8; i++) {
        out[4 * i + 0] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)(h[i]);
    }
}

// Digest of a whole message through the plain-C reference.
static void ref_digest(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    static uint8_t padded[PAD_BUF_SIZE];
    size_t nblocks = pad_tail(msg, len, (uint64_t)len * 8, padded);
    static const uint32_t fips[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    uint32_t h[8];
    memcpy(h, fips, sizeof(h));
    for (size_t b = 0; b < nblocks; b++)
        ref_compress(h, padded + 64 * b);
    digest_bytes(h, digest);
}

static int digest_eq(const uint8_t a[32], const uint8_t b[32]) {
    return memcmp(a, b, 32) == 0;
}

// ── transcript helpers ───────────────────────────────────────────────

// One handshake message: type octet + body (len bytes).
typedef struct {
    uint8_t type;
    const uint8_t *body;
    size_t len;
} HsMsg;

// Build the wire form of a message sequence (header || body per
// message) into out; returns the total length.
static size_t build_wire(uint8_t *out, const HsMsg *msgs, size_t n) {
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        out[off] = msgs[i].type;
        out[off + 1] = (uint8_t)(msgs[i].len >> 16);
        out[off + 2] = (uint8_t)(msgs[i].len >> 8);
        out[off + 3] = (uint8_t)(msgs[i].len);
        memcpy(out + off + 4, msgs[i].body, msgs[i].len);
        off += 4 + msgs[i].len;
    }
    return off;
}

// Feed a sequence through the asm transcript and check the snapshot
// against the reference hash of the same wire bytes. This is the core
// check: it validates the 4-byte header synthesis (type octet + uint24
// big-endian length), the message ordering, and every streaming
// boundary the reference happens to cross.
static void check_transcript(const char *label, const HsMsg *msgs, size_t n) {
    static uint8_t wire[4096];
    uint8_t want[32], got[32];
    size_t wirelen = build_wire(wire, msgs, n);
    ref_digest(wire, wirelen, want);

    tls_transcript_init();
    for (size_t i = 0; i < n; i++)
        tls_transcript_add(msgs[i].type, msgs[i].body, msgs[i].len);
    tls_transcript_hash(got);

    if (digest_eq(want, got))
        _PASS(label);
    else
        _FAIL("%s — transcript hash mismatch", label);
}

// ── known-answer vectors (computed with python3 hashlib) ─────────────

// SHA256("") — empty transcript.
static const uint8_t KAT_EMPTY[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

// SHA256([01 00 00 03 "abc"]) — one ClientHello, body "abc".
static const uint8_t KAT_CH_ABC[32] = {
    0x6f, 0x50, 0xd0, 0x4e, 0xbc, 0xcf, 0xc9, 0x2f,
    0xab, 0x76, 0x2e, 0x6e, 0xce, 0x79, 0x7d, 0xe3,
    0xc0, 0xc6, 0xd6, 0x2e, 0x02, 0xfe, 0xb9, 0x88,
    0xd8, 0xdf, 0xfe, 0x69, 0xa8, 0x15, 0x66, 0xd4,
};

// SHA256([02 00 00 00]) — one ServerHello with an empty body.
static const uint8_t KAT_SH_EMPTY[32] = {
    0x26, 0xb2, 0x5d, 0x45, 0x75, 0x97, 0xa7, 0xb0,
    0x46, 0x3f, 0x96, 0x20, 0xf6, 0x66, 0xdd, 0x10,
    0xaa, 0x2c, 0x43, 0x73, 0xa5, 0x05, 0x96, 0x7c,
    0x7c, 0x8d, 0x70, 0x92, 0x2a, 0x2d, 0x6e, 0xce,
};

// SHA256([01 00 01 2C <300 bytes 0x00..0xFF,0x00..0x2B>]) — a single
// message long enough that the uint24 length field matters.
static const uint8_t KAT_LONG_300[32] = {
    0x3f, 0x61, 0x14, 0xbc, 0xbd, 0x70, 0x25, 0x63,
    0xf3, 0x1e, 0xc4, 0xea, 0x41, 0xa5, 0xe8, 0x25,
    0x82, 0x71, 0x0a, 0xbf, 0x0c, 0x64, 0x89, 0x58,
    0x53, 0x1b, 0x3c, 0x93, 0x09, 0x91, 0xec, 0x86,
};

// A realistic TLS 1.3 server transcript, ClientHello → Finished:
//   ClientHello (type 1, 32-byte body: 0x00..0x1F)
//   ServerHello (type 2, 36-byte body: 0x20..0x43)
//   EncryptedExtensions (type 8, 2-byte body: 0x00 0x00)
//   Certificate (type 11, 4-byte body: 0xAA 0xBB 0xCC 0xDD)
//   CertificateVerify (type 15, 5-byte body: 0x00..0x04)
//   Finished (type 20, 32-byte body: 0x20..0x3F)
static const uint8_t KAT_HANDSHAKE[32] = {
    0x9b, 0xc5, 0xd7, 0x6d, 0x69, 0x46, 0x23, 0xa8,
    0x25, 0xfc, 0xfe, 0xa5, 0x29, 0xac, 0xe3, 0x59,
    0x2b, 0x81, 0x54, 0xdb, 0x54, 0x3d, 0xc4, 0xfd,
    0x55, 0xaa, 0x98, 0x6c, 0xf6, 0x69, 0x4d, 0x36,
};

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

// PLAN.MD §9 acceptance: known TLS transcript sequences produce the
// expected SHA-256 values. All vectors computed independently (python3
// hashlib) over the wire bytes (header || body).
static void test_transcript_known_vectors(void) {
    TEST_SUITE("known TLS transcript sequences");
    static uint8_t long_body[300];
    static const uint8_t ch_body[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    static const uint8_t sh_body[36] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43,
    };
    static const uint8_t ee_body[2] = { 0x00, 0x00 };
    static const uint8_t cert_body[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    static const uint8_t cv_body[5] = { 0x00, 0x01, 0x02, 0x03, 0x04 };
    static const uint8_t fin_body[32] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    uint8_t got[32], body_only[32];

    // empty transcript
    tls_transcript_init();
    tls_transcript_hash(got);
    ASSERT_TRUE("empty transcript == SHA256(\"\")", digest_eq(KAT_EMPTY, got));

    // one ClientHello, body "abc" — and the hash must include the
    // 4-byte header, not just the body
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, (const uint8_t *)"abc", 3);
    tls_transcript_hash(got);
    ASSERT_TRUE("ClientHello(\"abc\") == KAT", digest_eq(KAT_CH_ABC, got));
    ref_digest((const uint8_t *)"abc", 3, body_only);
    ASSERT_FALSE("hash includes the 4-byte header (not body alone)",
                 digest_eq(body_only, got));

    // one ServerHello with an empty body (len == 0, NULL body)
    tls_transcript_init();
    tls_transcript_add(TLS_HS_SERVER_HELLO, NULL, 0);
    tls_transcript_hash(got);
    ASSERT_TRUE("ServerHello(empty) == KAT", digest_eq(KAT_SH_EMPTY, got));

    // a single 300-byte message — the uint24 length is 0x00012C
    for (int i = 0; i < 300; i++)
        long_body[i] = (uint8_t)i;
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, long_body, 300);
    tls_transcript_hash(got);
    ASSERT_TRUE("300-byte message (uint24 length) == KAT",
                digest_eq(KAT_LONG_300, got));

    // realistic ClientHello → Finished server transcript, one add per
    // message, in exchange order
    tls_transcript_init();
    tls_transcript_add(TLS_HS_CLIENT_HELLO, ch_body, 32);
    tls_transcript_add(TLS_HS_SERVER_HELLO, sh_body, 36);
    tls_transcript_add(TLS_HS_ENCRYPTED_EXTENSIONS, ee_body, 2);
    tls_transcript_add(TLS_HS_CERTIFICATE, cert_body, 4);
    tls_transcript_add(TLS_HS_CERTIFICATE_VERIFY, cv_body, 5);
    tls_transcript_add(TLS_HS_FINISHED, fin_body, 32);
    tls_transcript_hash(got);
    ASSERT_TRUE("ClientHello..Finished sequence == KAT",
                digest_eq(KAT_HANDSHAKE, got));
}

// Every length 0..300 at the SHA-256 padding boundaries, as single
// messages and as one multi-message transcript, cross-checked against
// the independent C reference.
static void test_transcript_matches_reference(void) {
    TEST_SUITE("transcript vs reference (boundary lengths)");
    static uint8_t body[300];
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (uint8_t)(i * 7 + 3);

    static const size_t lens[] = {
        0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 300,
    };
    for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        HsMsg m = { 1, body, lens[li] };
        char label[64];
        snprintf(label, sizeof(label), "single message, len %zu", lens[li]);
        check_transcript(label, &m, 1);
    }

    // many messages in one transcript, every length near the padding
    // boundaries — a single running hash, so the boundaries interact
    // across messages
    {
        HsMsg many[8];
        static const size_t mlens[] = { 55, 56, 63, 64, 65, 127, 129, 300 };
        for (size_t i = 0; i < 8; i++) {
            many[i].type = (uint8_t)(1 + i);
            many[i].body = body;
            many[i].len = mlens[i];
        }
        check_transcript("8 messages across padding boundaries", many, 8);
    }
}

// tls_transcript_hash must not destroy the transcript: it is a
// snapshot, so repeated calls agree, and feeding after a snapshot still
// extends the same transcript.
static void test_transcript_snapshot(void) {
    TEST_SUITE("tls_transcript_hash snapshot semantics");
    static const uint8_t bodyA[] = "first message body";
    static const uint8_t bodyB[] = "second message body";
    uint8_t h1[32], h1b[32], h2[32], want[32];
    HsMsg seq2[] = {
        { TLS_HS_CLIENT_HELLO, bodyA, sizeof(bodyA) - 1 },
        { TLS_HS_SERVER_HELLO, bodyB, sizeof(bodyB) - 1 },
    };
    static uint8_t wire[128];

    tls_transcript_init();
    tls_transcript_add(seq2[0].type, seq2[0].body, seq2[0].len);
    tls_transcript_hash(h1);
    tls_transcript_hash(h1b);
    ASSERT_TRUE("snapshot is repeatable", digest_eq(h1, h1b));

    // the transcript survives the snapshot: feeding B afterwards must
    // give SHA256(A || B) — not SHA256(B) or anything else
    tls_transcript_add(seq2[1].type, seq2[1].body, seq2[1].len);
    tls_transcript_hash(h2);
    {
        size_t wl = build_wire(wire, seq2, 2);
        ref_digest(wire, wl, want);
    }
    ASSERT_TRUE("hash after A+B == SHA256(A||B)", digest_eq(want, h2));
    ASSERT_FALSE("hash(A+B) differs from hash(A)", digest_eq(h1, h2));
}

// The transcript is order-sensitive: the same two messages in the
// opposite order must give a different hash (each still matching the
// reference of its own wire bytes).
static void test_transcript_ordering(void) {
    TEST_SUITE("message ordering matters");
    static const uint8_t bodyA[] = "abc";
    static const uint8_t bodyB[] = "xyz";
    uint8_t h_ab[32], h_ba[32];
    HsMsg ab[] = {
        { TLS_HS_CLIENT_HELLO, bodyA, 3 },
        { TLS_HS_SERVER_HELLO, bodyB, 3 },
    };
    HsMsg ba[] = {
        { TLS_HS_SERVER_HELLO, bodyB, 3 },
        { TLS_HS_CLIENT_HELLO, bodyA, 3 },
    };

    check_transcript("A then B matches reference", ab, 2);
    check_transcript("B then A matches reference", ba, 2);

    tls_transcript_init();
    tls_transcript_add(ab[0].type, ab[0].body, ab[0].len);
    tls_transcript_add(ab[1].type, ab[1].body, ab[1].len);
    tls_transcript_hash(h_ab);
    tls_transcript_init();
    tls_transcript_add(ba[0].type, ba[0].body, ba[0].len);
    tls_transcript_add(ba[1].type, ba[1].body, ba[1].len);
    tls_transcript_hash(h_ba);
    ASSERT_FALSE("SHA256(A||B) != SHA256(B||A)", digest_eq(h_ab, h_ba));
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

// ── main ─────────────────────────────────────────────────────────────

int main(void) {
    test_transcript_ctx_layout();
    test_transcript_init_seeds();
    test_transcript_known_vectors();
    test_transcript_matches_reference();
    test_transcript_snapshot();
    test_transcript_ordering();
    test_transcript_init_resets();
    test_summary();
    return 0;
}
