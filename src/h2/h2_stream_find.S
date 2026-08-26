#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_stream_find
//
// Description: Look a stream id up in the fixed stream table
//   (RFC 9113 §5.1). The scan runs over h2_stream_ids — the packed u32
//   index beside h2_streams — not over the entries themselves: 32 ids
//   are 128 bytes there against 1 KB of strided entry here, so the whole
//   search is two cache lines and the table itself is not touched until
//   a match is known. See the h2_stream_ids block in data.S.
//
//   Those two cache lines are now compared in one branchless pass: eight
//   128-bit loads cover all 32 ids, cmeq marks the matching lanes, and a
//   uminv over slot-index bytes reduces them to the lowest match. The
//   scalar loop this replaces cost one unpredictable compare per slot,
//   and the profile bore that out — under a client that keeps the table
//   full the wanted id rotates across all 32 slots, so the average
//   lookup walked half the table and paid a mispredict leaving the loop.
//   A hash table still would not pay for itself at 32 entries; what was
//   wrong was the branching, not the algorithm.
//
//   A zero id matches a free slot, exactly as it did when this scanned
//   the entries directly — wire ids are never zero (§5.1.1), so callers
//   that could hold a connection-level 0 must not reach here. The
//   reduction below picks the LOWEST matching slot, which is what the
//   scalar loop's first-match-wins exit did; that only shows on a zero
//   id, where every free slot matches at once.
//
// Input/Arguments:
//   x0 — stream id
//
// Output/Returns:
//   x0 — stream entry, or 0 if the stream is not in the table
//   carry clear = success (not found is a valid result, not an error)
//
// Clobbered Registers:
//   x0, x2, x3, x9, v0-v7, v16
//
//   The integer half is unchanged from the entry-scanning version on
//   purpose. Callers hold live values in the registers just outside that
//   set across the call — h2_handle_window_update keeps the frame's
//   stream id in x4 and compares it against the connection high-water
//   mark on the not-found path — so widening this list silently breaks
//   them rather than failing to build.
//
//   The vector registers are new with the NEON scan. Every one of them
//   is caller-saved under AAPCS64 (v0-v7, v16-v31); v8-v15 are avoided
//   because only their low 64 bits are, which is a trap rather than a
//   rule you can half-follow. No caller holds live vector state across
//   this call — h2_handle_headers is the only one that touches v regs at
//   all, and its own header already declares v0-v5 and v16-v18 clobbered
//   by the HPACK decode that runs after both of its lookups.
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

// The hit path turns a slot index straight into an entry pointer with a
// shift, so the entry stride has to stay a power of two.
.if H2S_SIZE != 32
.error "h2_stream_find: H2S_SIZE must be 32 for the lsl #5 index scaling"
.endif

// The pass below is exactly eight 128-bit loads wide, and the slot-index
// table it reduces against is exactly 32 bytes.
.if H2_MAX_STREAMS != 32
.error "h2_stream_find: the NEON scan is hard-wired to 32 slots"
.endif

// Slot index PLUS ONE, one byte per slot. Plus one because the reduction
// is a minimum and needs a sentinel above every real index: a lane that
// does not match contributes 0xff, so slot 0 cannot contribute 0 or a
// miss would be indistinguishable from a hit on the first slot.
.align 4
.Lh2_find_slot_ids:
    .byte  1,  2,  3,  4,  5,  6,  7,  8
    .byte  9, 10, 11, 12, 13, 14, 15, 16
    .byte 17, 18, 19, 20, 21, 22, 23, 24
    .byte 25, 26, 27, 28, 29, 30, 31, 32

.text
.align 2
FUNC h2_stream_find
    // Stored ids are 31-bit, so anything wider cannot be in the table.
    // Rejecting it here keeps the 32-bit comparisons below exactly as
    // faithful as the 64-bit ones they replace.
    lsr x2, x0, #31
    cbnz x2, .Lh2_find_miss
    adr_l x9, h2_stream_ids
    dup v0.4s, w0                   // wanted id in all four lanes
    // h2_stream_ids is .align 6, so every one of these is 16-B aligned
    ldp q1, q2, [x9]                // slots 0-7
    ldp q3, q4, [x9, #32]           // slots 8-15
    ldp q5, q6, [x9, #64]           // slots 16-23
    ldp q7, q16, [x9, #96]          // slots 24-31
    cmeq v1.4s, v1.4s, v0.4s
    cmeq v2.4s, v2.4s, v0.4s
    cmeq v3.4s, v3.4s, v0.4s
    cmeq v4.4s, v4.4s, v0.4s
    cmeq v5.4s, v5.4s, v0.4s
    cmeq v6.4s, v6.4s, v0.4s
    cmeq v7.4s, v7.4s, v0.4s
    cmeq v16.4s, v16.4s, v0.4s
    // Narrow 32 all-ones-or-zero lanes down to 32 bytes, in slot order.
    // Each source lane is uniform, so taking its even half is lossless.
    uzp1 v1.8h, v1.8h, v2.8h        // slots 0-7   as u16
    uzp1 v3.8h, v3.8h, v4.8h        // slots 8-15  as u16
    uzp1 v5.8h, v5.8h, v6.8h        // slots 16-23 as u16
    uzp1 v7.8h, v7.8h, v16.8h       // slots 24-31 as u16
    uzp1 v1.16b, v1.16b, v3.16b     // slots 0-15  as u8
    uzp1 v5.16b, v5.16b, v7.16b     // slots 16-31 as u8
    // Matching lane -> its slot index+1; non-matching lane -> 0xff.
    adr_l x2, .Lh2_find_slot_ids
    ldp q2, q4, [x2]
    orn v1.16b, v2.16b, v1.16b
    orn v5.16b, v4.16b, v5.16b
    umin v1.16b, v1.16b, v5.16b     // fold the halves, still lane-wise
    uminv b1, v1.16b                // lowest match over all 32 slots
    fmov w3, s1
    sub x3, x3, #1                  // slot index, or 0xfe on no match
    cmp x3, #H2_MAX_STREAMS
    b.hs .Lh2_find_miss
    adr_l x0, h2_streams
    add x0, x0, x3, lsl #5          // index * H2S_SIZE
    cmn xzr, xzr
    ret
.Lh2_find_miss:
    mov x0, #0                      // not found
    cmn xzr, xzr                    // success — carry clear
    ret
ENDFUNC h2_stream_find
