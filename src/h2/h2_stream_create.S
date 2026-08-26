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
//   NO PASS OVER h2_streams. The only scan left walks h2_stream_ids — the
//   packed u32 index described in data.S — looking for the id, out of two
//   cache lines and without touching an entry. Everything else comes from
//   the two bitmaps beside it:
//
//     * the lowest free slot is the lowest clear bit of h2_stream_used,
//       which is rbit+clz rather than a loop;
//     * the recycle candidates are the set bits of h2_stream_closed, so
//       the CLOSED-LRU choice visits only entries that are actually
//       CLOSED — one per iteration, cleared with the classic x & (x-1) —
//       and reads each candidate's id from h2_stream_ids rather than from
//       the entry.
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
//   x0, x2-x9
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

.text
.align 2
FUNC h2_stream_create
    mov x2, x0             // id
    mov x3, x1             // conn

    // ── pass 1: the packed id index — is this stream already here? ──
    adr_l x4, h2_stream_ids
    mov x5, #0             // slot index
.Lh2_create_scan:
    ldr w7, [x4, x5, lsl #2]
    cmp w7, w2
    b.eq .Lh2_create_exists
    add x5, x5, #1
    cmp x5, #H2_MAX_STREAMS
    b.lo .Lh2_create_scan

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
.Lh2_create_recycle:
    ldr_l x6, h2_stream_closed, x7
    cbz x6, .Lh2_create_full
    mov x8, #0             // oldest CLOSED slot seen, biased +1 (0 = none)
    mov x9, #0             // its id
.Lh2_create_rloop:
    rbit x7, x6
    clz x7, x7             // lowest set bit — the next CLOSED slot
    ldr w5, [x4, x7, lsl #2]          // its id, from the packed index
    cbz x8, .Lh2_create_take_closed   // first CLOSED entry seen
    cmp w5, w9
    b.hs .Lh2_create_rnext            // not older — keep the current best
.Lh2_create_take_closed:
    add x8, x7, #1         // oldest CLOSED entry seen so far
    mov w9, w5             // and its id, for the next comparison
.Lh2_create_rnext:
    sub x5, x6, #1
    and x6, x6, x5         // clear the lowest set bit and go again
    cbnz x6, .Lh2_create_rloop
    sub x5, x8, #1         // unbias: the slot to recycle. x8 cannot be 0
                           //   here — the mask was non-empty, so the first
                           //   iteration always took a candidate.

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
