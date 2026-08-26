#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_stream_event
//
// Description: One step of the §5.1 receive-side state machine, driven
//   by the h2_stream_transitions table (state × event → new state, or
//   0xff = invalid). Valid transitions store the new state and succeed;
//   invalid ones leave the state untouched and fail: an idle-stream
//   violation is a PROTOCOL_ERROR connection error (§5.1), anything
//   else is a STREAM_CLOSED stream error. RST_STREAM on an
//   already-CLOSED stream is tolerated — a reset may race with our own
//   END_STREAM (§5.1 closed).
//
// Input/Arguments:
//   x0 — stream entry
//   x1 — event (H2_EVENT_*)
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 = H2_ERR_PROTOCOL_ERROR or H2_ERR_STREAM_CLOSED on failure
//     (carry set)
//
// Clobbered Registers:
//   x0, x2-x4, x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

// The bitmap update below turns an entry pointer back into a slot index.
.if H2S_SIZE != 32
.error "h2_stream_event: H2S_SIZE must be 32 for the lsr #5 index recovery"
.endif

rodata
// receive-side stream transitions (§5.1) — rows are states, columns are
// H2_EVENT_* in order [RECV_HEADERS, RECV_DATA, RECV_END_STREAM,
// RECV_RST_STREAM]. Each byte is the resulting state, or 0xff when the
// transition is invalid (h2_stream_event maps the error: an idle-stream
// violation is PROTOCOL_ERROR, anything else is STREAM_CLOSED).
.align 4
h2_stream_transitions:
    .byte H2_STREAM_OPEN, 0xff, 0xff, 0xff                               // IDLE
    .byte H2_STREAM_OPEN, H2_STREAM_OPEN, H2_STREAM_HALF_CLOSED_REMOTE, H2_STREAM_CLOSED  // OPEN
    .byte 0xff, 0xff, 0xff, H2_STREAM_CLOSED                             // HALF_CLOSED_REMOTE
    .byte 0xff, 0xff, H2_STREAM_CLOSED, H2_STREAM_CLOSED                 // HALF_CLOSED_LOCAL
    .byte 0xff, 0xff, 0xff, H2_STREAM_CLOSED                             // CLOSED (RST tolerated)
.align 4 // pad the 20-byte table to a 16-byte multiple

.text
.align 2
FUNC h2_stream_event
    ldr x2, [x0, #H2S_STATE]
    cmp x2, #H2_STREAM_CLOSED
    b.hi .Lh2_stream_bad_event   // defensive: unknown state
    cmp x1, #H2_EVENT_COUNT
    b.hs .Lh2_stream_bad_event   // defensive: unknown event
    // index = state * H2_EVENT_COUNT + event (H2_EVENT_COUNT == 4)
    lsl x3, x2, #2
    add x3, x3, x1
    adr_l x9, h2_stream_transitions
    ldrb w4, [x9, x3]
    cmp w4, #0xff
    b.eq .Lh2_stream_invalid
    str x4, [x0, #H2S_STATE]
    // h2_stream_closed mirrors this field (see the h2_stream_used block in
    // h2/data.S): a transition that left it stale would either hide a
    // finished stream from h2_stream_create's recycle pass — eventually
    // refusing streams on a table full of closed ones — or offer a LIVE
    // stream up for recycling, which would answer a later frame with
    // someone else's entry. The slot index is the entry's offset into
    // h2_streams; the update is branchless so the common non-CLOSED
    // transition costs no misprediction.
    adr_l x2, h2_streams
    sub x2, x0, x2
    lsr x2, x2, #5                    // offset / H2S_SIZE
    mov x3, #1
    lsl x3, x3, x2
    ldr_l x2, h2_stream_closed, x9
    cmp x4, #H2_STREAM_CLOSED
    orr x4, x2, x3                    // ... if it closed
    bic x2, x2, x3                    // ... if it did not
    csel x2, x4, x2, eq
    str_l x2, h2_stream_closed, x9
    cmn xzr, xzr
    mov x0, #0
    ret
.Lh2_stream_invalid:
    cmp x2, #H2_STREAM_IDLE
    b.eq .Lh2_stream_idle_violation
.Lh2_stream_bad_event:
    cmp xzr, xzr
    mov x0, #H2_ERR_STREAM_CLOSED
    ret
.Lh2_stream_idle_violation:
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
ENDFUNC h2_stream_event
