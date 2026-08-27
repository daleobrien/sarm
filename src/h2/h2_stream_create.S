#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_stream_create
//
// Description: Find-or-create a stream entry. Returns the existing entry
//   for the id, or fills the lowest free slot — or, Stage 12, recycles
//   the *oldest* CLOSED entry (the one with the smallest stream id) once
//   the connection outgrows its initial table — with a fresh
//   stream: state IDLE, no flags, and a send window of the peer's
//   advertised SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.9.2 — the
//   client's initial stream-level credit; the connection loop resets it
//   to the 65535 default before the client SETTINGS arrive). Creating a
//   stream records its id as the connection's new high-water mark for
//   client streams. Recycling overwrites the closed entry wholesale (id,
//   state, flags, window), so the old id stops answering immediately;
//   the new id always exceeds it (§5.1.1).
//
//   NO PASS OVER h2_streams, AND NO BRANCH PER SLOT. The only scan left
//   walks h2_stream_ids — the packed u32 index described in data.S —
//   looking for the id, out of two cache lines and without touching an
//   entry, and it walks it in one branchless NEON pass: eight 128-bit
//   loads, cmeq per lane, uzp1 down to 32 bytes in slot order, orn
//   against a slot-index table so a match contributes index+1 and a miss
//   contributes 0xff, and uminv for the lowest match. That is the same
//   pass h2_stream_find runs, and the reason for it here is stronger:
//   this scan's hot case is a NEW stream, so it is a full 32-slot MISS on
//   every request — it never exited early and never will. Lowest-match-
//   wins preserves the old loop's first-match exit, which only shows on a
//   zero id, where every free slot matches at once.
//
//   Everything else comes from the two bitmaps beside the index:
//
//     * the lowest free slot is the lowest clear bit of h2_stream_used,
//       which is rbit+clz rather than a loop;
//     * the recycle candidates are the set bits of h2_stream_closed, so
//       the CLOSED-LRU choice visits only entries that are actually
//       CLOSED — one per iteration, cleared with the classic x & (x-1) —
//       and reads each candidate's id from h2_stream_ids rather than from
//       the entry. Its body carries ONE data-dependent branch, not two:
//       the "first candidate seen" test is gone, absorbed into a sentinel.
//
//   The pass this replaced read H2S_STATE and H2S_STREAM_ID at a 32-byte
//   stride, so it touched all 16 cache lines of h2_streams every time it
//   ran — and it ran on every request as soon as the table filled, which
//   is the steady state for any client that asks for our full
//   MAX_CONCURRENT_STREAMS quota. See the h2_stream_used block in data.S
//   for the measurement, and for the list of writers that keep the
//   bitmaps true.
//
// Input/Arguments:
//   x0 — stream id
//   x1 — connection state
//
// Output/Returns:
//   x0 — stream entry (carry clear = success)
//   x0 = H2_ERR_REFUSED_STREAM, carry set = table is full of live or
//     idle streams
//
// Clobbered Registers:
//   x0, x2-x9, v0-v7, v16
//
//   The vector registers come with the NEON pass. Every one of them is
//   caller-saved under AAPCS64 (v0-v7, v16-v31); v8-v15 are avoided
//   because only their low 64 bits are, which is a trap rather than a
//   rule you can half-follow. h2_handle_headers is the sole caller and
//   already declares v0-v7 and v16-v18 clobbered — it reaches
//   h2_stream_find's identical pass through h2_validate_stream_id, and
//   runs the HPACK decode after both — so this adds nothing to its list.
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

// Slot indices become entry pointers by shifting, so the entry stride has
// to stay a power of two.
.if H2S_SIZE != 32
.error "h2_stream_create: H2S_SIZE must be 32 for the lsl #5 index scaling"
.endif

// h2_stream_used and h2_stream_closed are one u64 each, one bit per entry.
.if H2_MAX_STREAMS > 64
.error "h2_stream_create: H2_MAX_STREAMS must fit the u64 slot bitmaps"
.endif

// Pass 1 is exactly eight 128-bit loads wide, and the slot-index table it
// reduces against is exactly 32 bytes.
.if H2_MAX_STREAMS != 32
.error "h2_stream_create: the NEON id scan is hard-wired to 32 slots"
.endif

// Slot index PLUS ONE, one byte per slot — the same table h2_stream_find
// carries, duplicated because a .L local cannot be referenced across
// files. Plus one because the reduction is a minimum and needs a sentinel
// above every real index: a lane that does not match contributes 0xff, so
// slot 0 cannot contribute 0 or a miss would be indistinguishable from a
// hit on the first slot.
.align 4
.Lh2_create_slot_ids:
    .byte  1,  2,  3,  4,  5,  6,  7,  8
    .byte  9, 10, 11, 12, 13, 14, 15, 16
    .byte 17, 18, 19, 20, 21, 22, 23, 24
    .byte 25, 26, 27, 28, 29, 30, 31, 32

.text
.align 2
FUNC h2_stream_create
    mov x2, x0             // id
    mov x3, x1             // conn

    // ── pass 1: the packed id index — is this stream already here? ──
    // One branchless pass over both cache lines of h2_stream_ids, the
    // same shape h2_stream_find uses; see the comment there for why the
    // reduction is a minimum over index+1. x4 survives it and is still
    // h2_stream_ids for both exits below.
    adr_l x4, h2_stream_ids
    dup v0.4s, w2                     // wanted id in all four lanes
    // h2_stream_ids is .align 6, so every one of these is 16-B aligned
    ldp q1, q2, [x4]                  // slots 0-7
    ldp q3, q4, [x4, #32]             // slots 8-15
    ldp q5, q6, [x4, #64]             // slots 16-23
    ldp q7, q16, [x4, #96]            // slots 24-31
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
    uzp1 v1.8h, v1.8h, v2.8h          // slots 0-7   as u16
    uzp1 v3.8h, v3.8h, v4.8h          // slots 8-15  as u16
    uzp1 v5.8h, v5.8h, v6.8h          // slots 16-23 as u16
    uzp1 v7.8h, v7.8h, v16.8h         // slots 24-31 as u16
    uzp1 v1.16b, v1.16b, v3.16b       // slots 0-15  as u8
    uzp1 v5.16b, v5.16b, v7.16b       // slots 16-31 as u8
    // Matching lane -> its slot index+1; non-matching lane -> 0xff.
    adr_l x6, .Lh2_create_slot_ids
    ldp q2, q4, [x6]
    orn v1.16b, v2.16b, v1.16b
    orn v5.16b, v4.16b, v5.16b
    umin v1.16b, v1.16b, v5.16b       // fold the halves, still lane-wise
    uminv b1, v1.16b                  // lowest match over all 32 slots
    fmov w5, s1
    sub x5, x5, #1                    // slot index, or 0xfe on no match
    cmp x5, #H2_MAX_STREAMS
    b.lo .Lh2_create_exists

    // ── not present: the lowest free slot, straight out of the bitmap ──
    // The lowest CLEAR bit of h2_stream_used: complement, reverse, count
    // leading zeros. A full table complements to zero, whose rbit is zero,
    // whose clz is 64 — past the table either way, so the one compare that
    // range-checks the slot also detects "full".
    ldr_l x6, h2_stream_used, x7
    mvn x7, x6
    rbit x7, x7
    clz x7, x7
    cmp x7, #H2_MAX_STREAMS
    b.hs .Lh2_create_recycle
    mov x5, x7
    b .Lh2_create_init

    // ── table full — recycle the oldest CLOSED entry ──
    // h2_stream_closed names the candidates, so this visits only entries
    // that can actually be taken instead of all H2_MAX_STREAMS of them,
    // and x4 still points at h2_stream_ids — each candidate's id comes
    // from the packed index, so no entry is read here at all.
    //
    // THIS LOOP IS STILL THE MOST EXPENSIVE THING IN THE FUNCTION, at
    // ~104 cycles per request on N1 — roughly 2% of all h2c cycles, and
    // unchanged by every attempt made on it so far. Read the profile
    // carefully before trying again:
    //
    //   * Samples inside the loop skid. Two different instructions have
    //     now occupied the slot after the ldr across three runs, and each
    //     collected ~20% of the function. The pile is positional, from
    //     the load; it is not the cost of whatever sits there.
    //   * The csel change below cut the function 7.4%, and ALL of it came
    //     out of the .Lh2_create_init block, not out of here — 44.2 to
    //     30.6 cycles per request, while the loop stayed at 104.1/104.2.
    //     That was mispredict recovery being attributed downstream of the
    //     loop it belonged to. The loop's own 104 cycles never moved.
    //   * So what is left here is load latency: a serial walk whose next
    //     address comes from the previous rbit/clz, over an index that
    //     spans two cache lines. Three rewrites (a NEON O(1) reduction,
    //     the first-iteration-test removal in dfc1eae, and the csel here)
    //     all left it at ~104 cycles, because none of them touched that.
    //
    // The next real attempt has to shorten the load chain — prefetching
    // both h2_stream_ids lines ahead of the loop, or keeping a per-word
    // running minimum so the walk is not serial. Anything that only
    // reshuffles the compare will land where the other three did.
.Lh2_create_recycle:
    ldr_l x6, h2_stream_closed, x7
    cbz x6, .Lh2_create_full
    // The running best starts at a sentinel id rather than at "nothing
    // seen yet". Wire ids are 31-bit (RFC 9113 §5.1.1), so 0xffffffff is
    // above every real id and the first candidate always displaces it —
    // which is what removes the per-iteration "have I seen one yet?"
    // test. x8's +1 bias goes away with it, since 0 is now a real answer.
    mov w9, #-1            // best id so far
    mov x8, #0             // and its slot
.Lh2_create_rloop:
    rbit x7, x6
    clz x7, x7             // lowest set bit — the next CLOSED slot
    ldr w5, [x4, x7, lsl #2]          // its id, from the packed index
    // Strictly-lower wins, and the mask is walked low slot first, so a
    // tie keeps the lower slot exactly as the first-seen test did.
    //
    // This is branchless on purpose, and unlike most of what surrounds it
    // that is a measured claim rather than an argued one. "Is this
    // candidate older than the best so far?" is decided by the arrival
    // order of client stream ids in a slot table, which N1's predictor
    // does not learn: the running minimum updates about ln(N) times per
    // call, at positions that vary per request. Replacing the branch with
    // these two csel's took 1.81 branch-misses per request off h2c and
    // 2.35 off h2tls (ec2-20260827-203555 against -194908, h1 control
    // +0.50%), and this function's cost per request fell 7.4% on h2c and
    // 13.9% on h2tls.
    //
    // Do not read that as "the loop got faster" — see the block comment
    // above .Lh2_create_recycle. It did not.
    //
    // A local M3 A/B argues the opposite, loudly and reproducibly: csel
    // is ~28% WORSE on bench_h2_stream_create's recycle, recycle_eight
    // and recycle_one. Those three replay a fixed mask with fixed ids,
    // which M3 learns completely, leaving csel paying for the x8/w9
    // dependency and buying nothing. recycle_varying — 64 rotating masks,
    // permuted ids — has it 24% BETTER on the same machine. When a
    // branchless rewrite splits that way, the fixed-pattern cases are
    // measuring the predictor, not the code.
    cmp w5, w9
    csel x8, x7, x8, lo    // oldest CLOSED entry seen so far
    csel w9, w5, w9, lo    // and its id, for the next comparison
    sub x5, x6, #1
    and x6, x6, x5         // clear the lowest set bit and go again
    cbnz x6, .Lh2_create_rloop
    mov x5, x8             // the slot to recycle

.Lh2_create_init:
    // x5 — the slot to initialise, as an index into both tables.
    // x4 is already h2_stream_ids on both paths in.
    str w2, [x4, x5, lsl #2]          // the lookup index, first
    // ... and the bitmaps with it, or the slot stays invisible to the next
    // allocation (see the h2_stream_used block in data.S). A fresh stream
    // is IDLE, so it is emphatically not a recycle candidate — clearing
    // `closed` is what makes recycling a slot safe.
    mov x7, #1
    lsl x7, x7, x5
    ldr_l x6, h2_stream_used, x9
    orr x6, x6, x7
    str_l x6, h2_stream_used, x9
    ldr_l x6, h2_stream_closed, x9
    bic x6, x6, x7
    str_l x6, h2_stream_closed, x9
    adr_l x6, h2_streams
    add x6, x6, x5, lsl #5            // index * H2S_SIZE
    str x2, [x6, #H2S_STREAM_ID]
    mov x7, #H2_STREAM_IDLE
    str x7, [x6, #H2S_STATE]
    str xzr, [x6, #H2S_FLAGS]
    ldr x7, [x3, #H2C_SETTINGS_INITIAL_WINDOW_SIZE]
    str x7, [x6, #H2S_WINDOW]
    // this id is now the largest client stream the connection has seen
    str x2, [x3, #H2C_LAST_STREAM_ID]
    mov x0, x6
    cmn xzr, xzr
    ret
.Lh2_create_exists:
    // pass 1 matched at slot x5; x4 is the id index, not the entry
    adr_l x0, h2_streams
    add x0, x0, x5, lsl #5            // index * H2S_SIZE
    cmn xzr, xzr
    ret
.Lh2_create_full:
    cmp xzr, xzr
    mov x0, #H2_ERR_REFUSED_STREAM
    ret
ENDFUNC h2_stream_create
