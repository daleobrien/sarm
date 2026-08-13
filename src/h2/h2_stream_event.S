// This file is part of ymawky.
// Copyright (C) 2026 imtomt
//
// ymawky is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// ymawky is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ymawky. If not, see <https://www.gnu.org/licenses/>.

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
//   x0-x4, x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
// receive-side stream transitions (§5.1) — rows are states, columns are
// H2_EVENT_* in order [RECV_HEADERS, RECV_DATA, RECV_END_STREAM,
// RECV_RST_STREAM]. Each byte is the resulting state, or 0xff when the
// transition is invalid (h2_stream_event maps the error: an idle-stream
// violation is PROTOCOL_ERROR, anything else is STREAM_CLOSED).
.align 1
h2_stream_transitions:
    .byte H2_STREAM_OPEN, 0xff, 0xff, 0xff                               // IDLE
    .byte H2_STREAM_OPEN, H2_STREAM_OPEN, H2_STREAM_HALF_CLOSED_REMOTE, H2_STREAM_CLOSED  // OPEN
    .byte 0xff, 0xff, 0xff, H2_STREAM_CLOSED                             // HALF_CLOSED_REMOTE
    .byte 0xff, 0xff, H2_STREAM_CLOSED, H2_STREAM_CLOSED                 // HALF_CLOSED_LOCAL
    .byte 0xff, 0xff, 0xff, H2_STREAM_CLOSED                             // CLOSED (RST tolerated)

.text
.align 2
.global h2_stream_event
h2_stream_event:
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
