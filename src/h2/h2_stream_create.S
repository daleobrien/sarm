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
//   Two passes, because they want different memory. The first walks
//   h2_stream_ids — the packed u32 index described in data.S — which
//   answers "is this stream already here, and if not where is the lowest
//   free slot" out of two cache lines without touching an entry. That is
//   the whole job whenever the table has a free slot, which is the normal
//   case; it used to cost a 32-entry stride over 1 KB, reading a state
//   field per entry that only the recycling decision ever needed. The
//   second pass reads states and runs the CLOSED-LRU choice, and only
//   runs when the table is genuinely full.
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

.text
.align 2
FUNC h2_stream_create
    mov x2, x0             // id
    mov x3, x1             // conn

    // ── pass 1: the packed id index — hit, or the lowest free slot ──
    adr_l x4, h2_stream_ids
    mov x5, #0             // slot index
    mov x6, #0             // lowest free slot seen, biased +1 (0 = none)
.Lh2_create_scan:
    ldr w7, [x4, x5, lsl #2]
    cmp w7, w2
    b.eq .Lh2_create_exists
    cbnz w7, .Lh2_create_next
    cbnz x6, .Lh2_create_next   // keep the *lowest* free slot, so the table
    add x6, x5, #1              //   fills forwards and slot order tracks age
.Lh2_create_next:
    add x5, x5, #1
    cmp x5, #H2_MAX_STREAMS
    b.lo .Lh2_create_scan

    cbz x6, .Lh2_create_recycle
    sub x5, x6, #1         // unbias: the free slot's index
    b .Lh2_create_init

    // ── pass 2: table full — recycle the oldest CLOSED entry ──
    // Only reached when every slot holds a live or idle stream, so this
    // is the one path that has to read state out of the entries.
.Lh2_create_recycle:
    adr_l x4, h2_streams
    mov x5, #0
    mov x8, #0             // oldest CLOSED slot seen, biased +1 (0 = none)
    mov x9, #0             // its id
.Lh2_create_rloop:
    ldr x7, [x4, #H2S_STATE]
    cmp x7, #H2_STREAM_CLOSED
    b.ne .Lh2_create_rnext
    ldr x7, [x4, #H2S_STREAM_ID]
    cbz x8, .Lh2_create_take_closed   // first CLOSED entry seen
    cmp x7, x9
    b.hs .Lh2_create_rnext            // not older — keep the current best
.Lh2_create_take_closed:
    add x8, x5, #1         // oldest CLOSED entry seen so far
    mov x9, x7             // and its id, for the next comparison
.Lh2_create_rnext:
    add x4, x4, #H2S_SIZE
    add x5, x5, #1
    cmp x5, #H2_MAX_STREAMS
    b.lo .Lh2_create_rloop
    cbz x8, .Lh2_create_full
    sub x5, x8, #1         // unbias: the slot to recycle

.Lh2_create_init:
    // x5 — the slot to initialise, as an index into both tables
    adr_l x4, h2_stream_ids
    str w2, [x4, x5, lsl #2]          // the lookup index, first
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
