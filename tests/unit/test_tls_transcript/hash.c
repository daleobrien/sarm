// Unit tests for tls_transcript_hash — snapshot
// semantics and cross-reference correctness)
#include "common.h"

// ── tests ────────────────────────────────────────────────────────────

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

int main(void) {
    test_transcript_matches_reference();
    test_transcript_snapshot();
    test_summary();
    return 0;
}
