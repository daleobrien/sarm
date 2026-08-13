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
// Function Name: h2_handle_headers
//
// Description: Open or update the stream named by the frame. A HEADERS
//   frame is the only thing that may open a new client stream (§5.1):
//   the id must pass h2_validate_stream_id, the stream is created in
//   IDLE and moved to OPEN, and the END_STREAM flag then moves it to
//   HALF_CLOSED_REMOTE. The frame's flags are recorded on the stream
//   entry (END_STREAM/END_HEADERS are extracted there), the
//   HPACK-encoded header block is decoded with h2_hpack_decode_block,
//   and the decoded fields are converted into the protocol-neutral
//   `request` struct by h2_build_request. An undecodable block is a
//   COMPRESSION_ERROR connection error (§4.3); a malformed request is a
//   PROTOCOL_ERROR stream error (§8.1.1). A HEADERS that opens a
//   brand-new stream beyond MAX_CONCURRENT_STREAMS (§5.1.2) is refused
//   with ENHANCE_YOUR_CALM — a connection error the loop answers with
//   GOAWAY; HEADERS on an existing stream (trailers) never counts again.
//
// NOTE: the dispatcher reaches us with br, so x30 is the return address
// of the dispatcher's caller — save it before our own bl calls.
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — payload
//   x2 — connection state
//
// Output/Returns:
//   x0 — 0 on success, error code on failure; carry set on error
//
// Clobbered Registers:
//   x0-x15, x19 (saved/restored), x30 (saved/restored)
//
// Stack Usage:
//   32 bytes: stp x19, x30, [sp, #-32]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_headers
h2_handle_headers:
    stp x19, x30, [sp, #-32]!
    mov x10, x0             // hdr — saved across the validate/create calls
    mov x11, x2             // conn — saved across the validate/create calls
    mov x12, x1             // payload — reaches the HPACK decoder later
    ldr w13, [x0, #H2F_FLAGS]
    str x13, [sp, #16]      // frame flags — saved across the decode/build
    mov x1, x2              // validate's second argument is the conn
    bl h2_validate_stream_id
    b.cs .Lh2_headers_err
    // ── Stage 12 — enforce MAX_CONCURRENT_STREAMS (§5.1.2) ──
    // Only a brand-new stream consumes a slot: an existing stream keeps
    // its entry, so trailers are never counted twice. Open means OPEN or
    // HALF_CLOSED_* — IDLE and CLOSED streams don't count (§5.1.2).
    ldr w0, [x10, #H2F_STREAM_ID]
    bl h2_stream_find
    cbnz x0, .Lh2_headers_count_done
    // ── Stage 13 — GOAWAY received: no brand-new streams (§6.8) ──
    // The connection is winding down; a HEADERS that would open a stream
    // that doesn't exist yet is refused with REFUSED_STREAM (a stream
    // error the loop answers with RST_STREAM). Streams already in the
    // table — accepted before the GOAWAY — run to completion.
    ldr x14, [x11, #H2C_GOAWAY_RECEIVED]
    cbnz x14, .Lh2_headers_refused
    adr_l x9, h2_streams
    mov x13, #H2_MAX_STREAMS
    mov x14, #0             // open-stream count
1:
    ldr x15, [x9, #H2S_STATE]
    cbz x15, 2f             // IDLE doesn't count
    cmp x15, #H2_STREAM_CLOSED
    b.eq 2f                 // CLOSED doesn't count
    add x14, x14, #1
2:
    add x9, x9, #H2S_SIZE
    subs x13, x13, #1
    b.ne 1b
    cmp x14, #MAX_CONCURRENT_STREAMS
    b.hs .Lh2_headers_too_many
.Lh2_headers_count_done:
    ldr w0, [x10, #H2F_STREAM_ID]
    mov x1, x11
    bl h2_stream_create
    b.cs .Lh2_headers_err
    mov x19, x0             // stream entry — survives the decode/build calls
    ldr x13, [sp, #16]
    str x13, [x19, #H2S_FLAGS]  // extract END_STREAM / END_HEADERS / ...
    mov x1, #H2_EVENT_RECV_HEADERS
    bl h2_stream_event
    b.cs .Lh2_headers_err
    // the HPACK-encoded header block reaches the decoder here
    mov x0, x12             // payload
    ldr w1, [x10, #H2F_LENGTH]
    bl h2_hpack_decode_block
    b.cs .Lh2_headers_err   // x0 = COMPRESSION_ERROR (connection error)
    // convert the decoded fields into the common request
    mov x1, x0              // decoded field count
    ldr w0, [x10, #H2F_STREAM_ID]
    bl h2_build_request
    b.cs .Lh2_headers_err   // x0 = PROTOCOL_ERROR (stream error)
    // END_STREAM closes the client's send side → HALF_CLOSED_REMOTE
    ldr x13, [sp, #16]
    tst w13, #H2_FLAG_END_STREAM
    b.eq .Lh2_headers_ok
    mov x0, x19
    mov x1, #H2_EVENT_RECV_END_STREAM
    bl h2_stream_event
    b.cs .Lh2_headers_err
.Lh2_headers_ok:
    ldp x19, x30, [sp], #32
    cmn xzr, xzr             // success — carry clear
    mov x0, #0
    ret
.Lh2_headers_too_many:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_ENHANCE_YOUR_CALM
    b .Lh2_headers_err       // don't fall through into the refused path
.Lh2_headers_refused:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_REFUSED_STREAM
.Lh2_headers_err:
    ldp x19, x30, [sp], #32
    ret                      // x0 = error, carry set
