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
//   x0-x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_stream_create
h2_stream_create:
    mov x2, x0             // id
    mov x3, x1             // conn
    adr_l x4, h2_streams
    mov x5, #H2_MAX_STREAMS
    mov x6, #0             // free slot seen so far (0 = none)
    mov x8, #0             // first CLOSED slot seen (0 = none) — Stage 12
.Lh2_create_loop:
    ldr x7, [x4]           // this entry's stream id
    cmp x7, x2
    b.eq .Lh2_create_exists
    cbnz x7, .Lh2_create_check_closed
    cbnz x6, .Lh2_create_next   // keep the *lowest* free slot, so the table
    mov x6, x4                  //   fills forwards and slot order tracks age
    b .Lh2_create_next
.Lh2_create_check_closed:
    ldr x9, [x4, #H2S_STATE]
    cmp x9, #H2_STREAM_CLOSED
    b.ne .Lh2_create_next
    cbz x8, .Lh2_create_take_closed   // first CLOSED entry seen
    ldr x9, [x8, #H2S_STREAM_ID]      // best candidate so far
    cmp x7, x9
    b.hs .Lh2_create_next             // not older — keep the current best
.Lh2_create_take_closed:
    mov x8, x4             // oldest CLOSED entry seen so far
.Lh2_create_next:
    add x4, x4, #H2S_SIZE
    subs x5, x5, #1
    b.ne .Lh2_create_loop
    cbz x6, 1f
    b .Lh2_create_init
1:  // no free slot — recycle the oldest CLOSED entry, if any
    cbz x8, .Lh2_create_full
    mov x6, x8
.Lh2_create_init:
    // initialise the fresh entry
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
    mov x0, x4
    cmn xzr, xzr
    ret
.Lh2_create_full:
    cmp xzr, xzr
    mov x0, #H2_ERR_REFUSED_STREAM
    ret
