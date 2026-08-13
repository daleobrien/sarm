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

#include "defs.S"

// HTTP/2 frame engine (RFC 9113 §3.4-§6.5).
//
// Stage 4 — the frame layer: 9-byte frame header decoding (§4.1), frame
// size validation (§4.2), frame dispatch (§5.5) and SETTINGS handling
// (§6.5). The connection preface and the connection read loop arrive in
// a later stage; these functions are the protocol-neutral heart of the
// engine and take a parsed frame header plus the h2_conn connection
// state, so they are testable in isolation.
//
// Stage 5 — the connection preface: h2_verify_preface reads exactly
// 24 bytes from a new connection and compares them with the HTTP/2
// connection preface (§3.4), recording the connection mode;
// h2_send_settings then emits the server's opening SETTINGS frame (§3.5),
// the first frame the server sends. The connection read loop that calls
// them in sequence arrives in a later stage.
//
// Stage 6 — stream management: the fixed stream table (h2_streams,
// H2_MAX_STREAMS entries, §5.1), stream id validation (nonzero, odd,
// increasing; §5.1.1), the receive-side stream state machine
// (h2_stream_event; IDLE/OPEN/HALF_CLOSED_*/CLOSED, §5.1) and the
// RST_STREAM handler (§6.4). HEADERS and DATA now drive the state
// machine instead of just acknowledging receipt; PRIORITY, PUSH_PROMISE,
// PING, GOAWAY, WINDOW_UPDATE and CONTINUATION remain stubs.
//
// Stage 7 — HPACK lands in its own file (h2_hpack.S). Here the opening
// SETTINGS frame now advertises SETTINGS_HEADER_TABLE_SIZE = 0 (§6.5.2),
// disabling the HPACK dynamic table so the static-table-only decoder in
// h2_hpack.S can reject every dynamic-table representation. Flow control
// arrives in a later stage.
//
// Error convention (shared with the rest of ymawky):
//   carry clear = success, x0 = 0
//   carry set   = failure, x0 = HTTP/2 error code (H2_ERR_*)
// A frame handler that reports a connection error (PROTOCOL_ERROR,
// FRAME_SIZE_ERROR, ...) poisons the connection — the connection loop
// must send GOAWAY and close. STREAM_CLOSED is a stream error: it
// should become an RST_STREAM on that stream rather than a GOAWAY once
// the connection loop stage separates the two.

.global h2_parse_frame_header
.global h2_validate_frame
.global h2_dispatch_frame
.global h2_handle_settings
.global h2_verify_preface
.global h2_send_settings
.global h2_conn
.global h2_frame_header
.global h2_settings_frame
.global h2_streams
.global h2_stream_find
.global h2_stream_create
.global h2_validate_stream_id
.global h2_stream_event

.data
.align 3
// h2_conn — HTTP/2 connection state (fixed layout; offsets in defs.S).
// One instance per connection; a fork-per-connection child starts with
// these RFC 9113 §6.5.2 initial values and updates them as SETTINGS
// frames arrive. h2_validate_frame reads H2C_MAX_RX_FRAME_SIZE, the
// frame size this endpoint is willing to receive.
h2_conn:
    .quad 0                               // H2C_LAST_FRAME_TYPE
    .quad H2_DEFAULT_MAX_FRAME_SIZE        // H2C_MAX_RX_FRAME_SIZE
    .quad H2_DEFAULT_HEADER_TABLE_SIZE     // H2C_SETTINGS_HEADER_TABLE_SIZE
    .quad 1                               // H2C_SETTINGS_ENABLE_PUSH
    .quad 0xffffffff                      // H2C_SETTINGS_MAX_CONCURRENT_STREAMS (unlimited)
    .quad H2_DEFAULT_INITIAL_WINDOW_SIZE   // H2C_SETTINGS_INITIAL_WINDOW_SIZE
    .quad H2_DEFAULT_MAX_FRAME_SIZE        // H2C_SETTINGS_MAX_FRAME_SIZE
    .quad 0xffffffff                      // H2C_SETTINGS_MAX_HEADER_LIST_SIZE (unlimited)
    .quad 0                               // H2C_ACK_RECEIVED
    .quad 0                               // H2C_LAST_STREAM_ID

// h2_settings_frame — the server's opening SETTINGS frame (RFC 9113
// §3.5, §6.5): a single SETTINGS_HEADER_TABLE_SIZE = 0 entry (§6.5.2),
// which tells the client its HPACK encoder may not use a dynamic table.
// Our decoder is static-table-only (h2_hpack.S) and rejects any
// dynamic-table representation, so advertising the limit up front lets
// conforming clients avoid the COMPRESSION_ERROR entirely.
h2_settings_frame:
    .byte 0x00, 0x00, 0x06            // payload length (24-bit) = 6
    .byte H2_FRAME_SETTINGS           // type = SETTINGS
    .byte 0x00                        // flags = 0
    .byte 0x00, 0x00, 0x00, 0x00      // stream id = 0
    .byte 0x00, H2_SETTINGS_HEADER_TABLE_SIZE // identifier (16-bit BE)
    .byte 0x00, 0x00, 0x00, 0x00      // value = 0 — dynamic table disabled
.equ h2_settings_frame_len, . - h2_settings_frame

// frame-type dispatch table, indexed by frame type (§6). The dispatcher
// tail-calls the selected handler, so the handler returns directly to
// the dispatcher's caller with the same x0/x1/x2 arguments.
.align 3
h2_frame_handlers:
    .quad h2_handle_data
    .quad h2_handle_headers
    .quad h2_handle_priority
    .quad h2_handle_rst_stream
    .quad h2_handle_settings
    .quad h2_handle_push_promise
    .quad h2_handle_ping
    .quad h2_handle_goaway
    .quad h2_handle_window_update
    .quad h2_handle_continuation

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

.bss
.align 3
// h2_frame_header — scratch for the parsed frame header. The connection
// loop parses the 9 wire bytes into this before validating/dispatching.
h2_frame_header:
    .skip H2F_SIZE

// h2_streams — the fixed stream table (§5.1). H2_MAX_STREAMS entries of
// H2S_SIZE bytes; a zero stream_id marks a free slot (wire ids are
// never zero). Zeroed at startup; stream entries are not recycled once
// CLOSED — a later stage decides when closed entries may be reused.
h2_streams:
    .skip H2_MAX_STREAMS * H2S_SIZE

.text
.align 2

// ── 4.1 — parse the 9-byte frame header ─────────────────────────────
// Decode a wire frame header (big-endian, RFC 9113 §4.1) into the
// h2_frame_header struct: 24-bit payload length, 8-bit type, 8-bit
// flags and 31-bit stream id (the reserved bit is masked off).
//
// input
// x0 -> 9-byte wire frame header
// x1 -> parsed frame header struct (H2F_SIZE bytes)
//
// output
// (none — the struct is filled; always succeeds given 9 bytes)
//
// clobbers x2, x3, x4, x5
h2_parse_frame_header:
    // payload length — 24-bit big-endian, bytes 0..2
    ldrb w2, [x0]
    ldrb w3, [x0, #1]
    ldrb w4, [x0, #2]
    lsl w2, w2, #16
    orr w2, w2, w3, lsl #8
    orr w2, w2, w4
    str w2, [x1, #H2F_LENGTH]

    // type and flags — single bytes, bytes 3 and 4
    ldrb w2, [x0, #3]
    str w2, [x1, #H2F_TYPE]
    ldrb w2, [x0, #4]
    str w2, [x1, #H2F_FLAGS]

    // stream id — 31-bit big-endian, bytes 5..8; mask off the R bit
    ldrb w2, [x0, #5]
    ldrb w3, [x0, #6]
    ldrb w4, [x0, #7]
    ldrb w5, [x0, #8]
    lsl w2, w2, #24
    orr w2, w2, w3, lsl #16
    orr w2, w2, w4, lsl #8
    orr w2, w2, w5
    and w2, w2, #0x7fffffff
    str w2, [x1, #H2F_STREAM_ID]
    ret

// ── 4.2 — frame size validation ─────────────────────────────────────
// Reject frames that violate RFC 9113 §4.2: a payload length above the
// 24-bit wire limit, or above the frame size this endpoint is willing
// to receive (H2C_MAX_RX_FRAME_SIZE, 2^14 by default). Both are
// FRAME_SIZE_ERROR connection errors.
//
// input
// x0 -> parsed frame header
// x1 -> connection state
//
// output
// x0 -> 0 on success, H2_ERR_FRAME_SIZE_ERROR on failure
// carry set on failure
//
// clobbers x2, x3, x4
h2_validate_frame:
    ldr w2, [x0, #H2F_LENGTH]

    // absolute wire limit: the 24-bit length field caps at 2^24 - 1
    mov w3, #H2_MAX_FRAME_SIZE
    cmp w2, w3
    b.hi .Lh2_frame_size_error

    // what we're willing to receive (our own SETTINGS_MAX_FRAME_SIZE)
    ldr w3, [x1, #H2C_MAX_RX_FRAME_SIZE]
    cmp w2, w3
    b.hi .Lh2_frame_size_error

    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret

.Lh2_frame_size_error:
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret

// ── 4.3 — frame dispatcher ──────────────────────────────────────────
// Switch on the frame type and tail-call the matching handler. Unknown
// frame types are ignored, not errors (RFC 9113 §5.5), so a future
// extension can be added without breaking the connection.
//
// input
// x0 -> parsed frame header
// x1 -> payload
// x2 -> connection state
//
// output
// x0 -> handler result: 0 on success, error code on failure
// carry set on connection error
//
// clobbers x3, x9 (handlers clobber their own)
h2_dispatch_frame:
    ldr w3, [x0, #H2F_TYPE]
    cmp w3, #H2_FRAME_CONTINUATION
    b.hi .Lh2_unknown_frame

    // remember the dispatched type — debug aid, observable in tests
    str w3, [x2, #H2C_LAST_FRAME_TYPE]

    adr_l x9, h2_frame_handlers
    ldr x9, [x9, w3, uxtw #3]
    br x9

.Lh2_unknown_frame:
    cmn xzr, xzr
    mov x0, #0
    ret

// ── frame handlers ──────────────────────────────────────────────────
// All handlers receive x0 -> frame header, x1 -> payload, x2 ->
// connection state and return via the dispatcher's tail call. Each must
// fully establish the return contract (x0 = 0, carry clear) — the
// dispatcher leaves the flags from its type compare, so a handler may
// not assume anything about them on entry.

// ── 6.3/6.2 — HEADERS ───────────────────────────────────────────────
// Open or update the stream named by the frame. A HEADERS frame is the
// only thing that may open a new client stream (§5.1): the id must pass
// h2_validate_stream_id, the stream is created in IDLE and moved to
// OPEN, and the END_STREAM flag then moves it to HALF_CLOSED_REMOTE.
// The HPACK payload is not decoded yet — that is the HPACK stage.
//
// NOTE: the dispatcher reaches us with br, so x30 is the return address
// of the dispatcher's caller — save it before our own bl calls.
//
// input/output: as h2_dispatch_frame
//
// clobbers x0-x11, x9, x30 (saved/restored)
h2_handle_headers:
    str x30, [sp, #-16]!   // save the return address
    // the id must be nonzero, odd and, for a brand-new stream, higher
    // than every client id seen on this connection (§5.1.1)
    mov x10, x0            // hdr — saved across the validate call
    mov x11, x2            // conn — saved across the validate call
    mov x1, x2             // validate's second argument is the conn
    bl h2_validate_stream_id
    b.cs .Lh2_stream_error
    ldr w0, [x10, #H2F_STREAM_ID]
    mov x1, x11
    bl h2_stream_create
    b.cs .Lh2_stream_error
    mov x8, x0             // stream entry — survives the event calls
    mov x1, #H2_EVENT_RECV_HEADERS
    bl h2_stream_event
    b.cs .Lh2_stream_error
    // END_STREAM closes the client's send side → HALF_CLOSED_REMOTE
    ldr w3, [x10, #H2F_FLAGS]
    tst w3, #H2_FLAG_END_STREAM
    b.eq .Lh2_headers_ok
    mov x0, x8
    mov x1, #H2_EVENT_RECV_END_STREAM
    bl h2_stream_event
    b.cs .Lh2_stream_error
.Lh2_headers_ok:
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret

// ── 6.3 — DATA ──────────────────────────────────────────────────────
// DATA frames carry request body bytes. Only an existing stream may
// receive them — an unknown stream is an idle-stream violation
// (PROTOCOL_ERROR, §5.1); any other invalid state is STREAM_CLOSED.
// END_STREAM on the frame closes the client's send side. The payload
// is not consumed yet (flow control/body handling arrive later).
//
// input/output: as h2_dispatch_frame
//
// clobbers x0-x8, x10, x11, x9, x30 (saved/restored)
h2_handle_data:
    str x30, [sp, #-16]!   // save the return address
    mov x10, x0            // hdr
    mov x11, x2            // conn — unused beyond this, kept for symmetry
    ldr w0, [x10, #H2F_STREAM_ID]
    bl h2_stream_find
    cbz x0, .Lh2_data_idle_error
    mov x8, x0             // stream entry
    mov x1, #H2_EVENT_RECV_DATA
    bl h2_stream_event
    b.cs .Lh2_stream_error
    // END_STREAM closes the client's send side → HALF_CLOSED_REMOTE
    ldr w3, [x10, #H2F_FLAGS]
    tst w3, #H2_FLAG_END_STREAM
    b.eq .Lh2_data_ok
    mov x0, x8
    mov x1, #H2_EVENT_RECV_END_STREAM
    bl h2_stream_event
    b.cs .Lh2_stream_error
.Lh2_data_ok:
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
.Lh2_data_idle_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret

// ── 6.4 — RST_STREAM ────────────────────────────────────────────────
// Abort a stream (§6.4). The payload is one 32-bit error code; the
// stream moves to CLOSED. RST_STREAM on an idle stream, on stream 0,
// or with an even (server-initiated) id is a PROTOCOL_ERROR connection
// error. The error code itself is not recorded anywhere yet.
//
// input/output: as h2_dispatch_frame
//
// clobbers x0-x4, x9, x30 (saved/restored)
h2_handle_rst_stream:
    str x30, [sp, #-16]!   // save the return address
    // exactly 4 payload bytes — one 32-bit error code (§6.4)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #4
    b.ne .Lh2_rst_size_error
    ldr w4, [x0, #H2F_STREAM_ID]
    cbz w4, .Lh2_rst_protocol_error
    tst w4, #1
    b.eq .Lh2_rst_protocol_error
    mov x0, x4
    bl h2_stream_find
    cbz x0, .Lh2_rst_protocol_error
    mov x1, #H2_EVENT_RECV_RST_STREAM
    bl h2_stream_event
    b.cs .Lh2_stream_error
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret
.Lh2_rst_protocol_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2_rst_size_error:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret

// Handlers not yet implemented — acknowledge receipt and do nothing:
// PRIORITY, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION.
h2_handle_priority:
h2_handle_push_promise:
h2_handle_ping:
h2_handle_goaway:
h2_handle_window_update:
h2_handle_continuation:
.Lh2_handler_ok:
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret

// Shared error exit for the stream handlers: every handler saved x30 at
// entry the same way, so pop it back and pass the error through
// (x0 holds the error, carry is set).
.Lh2_stream_error:
    ldr x30, [sp], #16
    ret

// ── stream engine ───────────────────────────────────────────────────
// Stage 6. The fixed stream table (h2_streams) plus the receive-side
// state machine (§5.1) and id validation (§5.1.1) that the HEADERS /
// DATA / RST_STREAM handlers drive.

// ── 6.1 — look up a stream by id ────────────────────────────────────
// Linear scan of the table; 32 entries is small and the scan is only
// run per frame, so a hash table is not worth it yet.
//
// input
// x0 -> stream id
//
// output
// x0 -> stream entry, or 0 if the stream is not in the table
// carry clear (not found is a valid result, not an error)
//
// clobbers x0, x2, x3, x9
h2_stream_find:
    adr_l x9, h2_streams
    mov x2, #H2_MAX_STREAMS
.Lh2_find_loop:
    ldr x3, [x9]           // this entry's stream id
    cmp x3, x0
    b.eq .Lh2_find_hit
    add x9, x9, #H2S_SIZE
    subs x2, x2, #1
    b.ne .Lh2_find_loop
    mov x0, #0             // not found
    cmn xzr, xzr           // success — carry clear
    ret
.Lh2_find_hit:
    mov x0, x9
    cmn xzr, xzr
    ret

// ── 6.1 — find-or-create a stream entry ─────────────────────────────
// Returns the existing entry for the id, or fills the first free slot
// (stream_id == 0) with a fresh stream: state IDLE, no flags, and the
// window we are willing to accept on new streams (RFC 9113 §5.2.1
// default; the flow-control stage will track our own advertised
// SETTINGS_INITIAL_WINDOW_SIZE instead). Creating a stream records its
// id as the connection's new high-water mark for client streams.
//
// input
// x0 -> stream id
// x1 -> connection state
//
// output
// success — carry clear, x0 -> stream entry
// failure — carry set, x0 = H2_ERR_REFUSED_STREAM (table is full)
//
// clobbers x0-x7, x9
h2_stream_create:
    mov x2, x0             // id
    mov x3, x1             // conn
    adr_l x4, h2_streams
    mov x5, #H2_MAX_STREAMS
    mov x6, #0             // free slot seen so far (0 = none)
.Lh2_create_loop:
    ldr x7, [x4]           // this entry's stream id
    cmp x7, x2
    b.eq .Lh2_create_exists
    cbnz x7, .Lh2_create_next
    mov x6, x4             // remember the free slot
.Lh2_create_next:
    add x4, x4, #H2S_SIZE
    subs x5, x5, #1
    b.ne .Lh2_create_loop
    cbz x6, .Lh2_create_full
    // initialise the fresh entry
    str x2, [x6, #H2S_STREAM_ID]
    mov x7, #H2_STREAM_IDLE
    str x7, [x6, #H2S_STATE]
    str xzr, [x6, #H2S_FLAGS]
    mov x7, #H2_DEFAULT_INITIAL_WINDOW_SIZE
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

// ── 6.2 — validate a stream-scoped frame's id ───────────────────────
// Reject the three classes of bad client stream id (RFC 9113 §5.1.1):
//   - zero, which is reserved for connection-level frames
//   - even numbers, which belong to server-initiated streams
//   - a brand-new stream id that does not exceed every client stream id
//     the connection has already seen
// All three are PROTOCOL_ERROR connection errors. Existing streams keep
// their id, so frames addressed to a live stream are unaffected by the
// high-water mark.
//
// input
// x0 -> parsed frame header
// x1 -> connection state
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = H2_ERR_PROTOCOL_ERROR
//
// clobbers x0-x5, x9, x30 (saved/restored)
h2_validate_stream_id:
    str x30, [sp, #-16]!   // save our return address — find clobbers x30
    ldr w4, [x0, #H2F_STREAM_ID]
    cbz w4, .Lh2_bad_stream_id
    tst w4, #1
    b.eq .Lh2_bad_stream_id
    ldr w5, [x1, #H2C_LAST_STREAM_ID]
    mov x0, x4
    bl h2_stream_find
    cbnz x0, .Lh2_ok_stream_id // exists — nothing to check
    cmp w4, w5                   // new stream must increase (§5.1.1)
    b.ls .Lh2_bad_stream_id
.Lh2_ok_stream_id:
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr
    mov x0, #0
    ret
.Lh2_bad_stream_id:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret

// ── 6.3 — apply a receive-side event to a stream ────────────────────
// One step of the §5.1 state machine, driven by the h2_stream_transitions
// table (state × event → new state, or 0xff = invalid). Valid
// transitions store the new state and succeed; invalid ones leave the
// state untouched and fail: an idle-stream violation is a PROTOCOL_ERROR
// connection error (§5.1), anything else is a STREAM_CLOSED stream
// error. RST_STREAM on an already-CLOSED stream is tolerated — a reset
// may race with our own END_STREAM (§5.1 closed).
//
// input
// x0 -> stream entry
// x1 -> event (H2_EVENT_*)
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = H2_ERR_PROTOCOL_ERROR or H2_ERR_STREAM_CLOSED
//
// clobbers x0-x4, x9
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

// ── 4.4 + 4.5 — SETTINGS ────────────────────────────────────────────
// Handle a SETTINGS frame (RFC 9113 §6.5):
//   - SETTINGS is connection-scoped: a stream id other than 0 is a
//     PROTOCOL_ERROR
//   - a non-ACK payload is a list of 6-byte entries; unknown
//     identifiers are ignored (§6.5.2); a length that is not a whole
//     number of entries is a FRAME_SIZE_ERROR
//   - a SETTINGS with the ACK flag must have an empty payload, else
//     FRAME_SIZE_ERROR (§6.5)
//
// input / output: as h2_dispatch_frame
//
// clobbers x3, x4, x5, x6, x7, x8, x9, x10
h2_handle_settings:
    // SETTINGS is a connection-level frame — stream id must be 0
    ldr w3, [x0, #H2F_STREAM_ID]
    cbnz w3, .Lh2_settings_protocol_error

    ldr w3, [x0, #H2F_FLAGS]
    ldr w4, [x0, #H2F_LENGTH]
    tst w3, #H2_FLAG_ACK
    b.ne .Lh2_settings_ack

    // payload must be a whole number of 6-byte entries
    mov w5, #H2_SETTINGS_ENTRY_LEN
    udiv w6, w4, w5
    msub w5, w6, w5, w4 // w5 = length % 6
    cbnz w5, .Lh2_settings_size_error

    cbz w4, .Lh2_settings_ok // an empty SETTINGS frame is valid

.Lh2_settings_loop:
    // id — 16-bit big-endian
    ldrb w6, [x1]
    ldrb w7, [x1, #1]
    lsl w6, w6, #8
    orr w6, w6, w7

    // value — 32-bit big-endian
    ldrb w7, [x1, #2]
    ldrb w8, [x1, #3]
    ldrb w9, [x1, #4]
    ldrb w10, [x1, #5]
    lsl w7, w7, #24
    orr w7, w7, w8, lsl #16
    orr w7, w7, w9, lsl #8
    orr w7, w7, w10

    // store by identifier; anything else is ignored (§6.5.2)
    cmp w6, #H2_SETTINGS_HEADER_TABLE_SIZE
    b.eq .Lh2_st_header_table_size
    cmp w6, #H2_SETTINGS_ENABLE_PUSH
    b.eq .Lh2_st_enable_push
    cmp w6, #H2_SETTINGS_MAX_CONCURRENT_STREAMS
    b.eq .Lh2_st_max_concurrent_streams
    cmp w6, #H2_SETTINGS_INITIAL_WINDOW_SIZE
    b.eq .Lh2_st_initial_window_size
    cmp w6, #H2_SETTINGS_MAX_FRAME_SIZE
    b.eq .Lh2_st_max_frame_size
    cmp w6, #H2_SETTINGS_MAX_HEADER_LIST_SIZE
    b.eq .Lh2_st_max_header_list_size
    b .Lh2_settings_next

.Lh2_st_header_table_size:
    str w7, [x2, #H2C_SETTINGS_HEADER_TABLE_SIZE]
    b .Lh2_settings_next

.Lh2_st_enable_push:
    str w7, [x2, #H2C_SETTINGS_ENABLE_PUSH]
    b .Lh2_settings_next

.Lh2_st_max_concurrent_streams:
    str w7, [x2, #H2C_SETTINGS_MAX_CONCURRENT_STREAMS]
    b .Lh2_settings_next

.Lh2_st_initial_window_size:
    // §6.5.2 — a value above 2^31-1 is a FLOW_CONTROL_ERROR
    tbnz w7, #31, .Lh2_settings_flow_control_error
    str w7, [x2, #H2C_SETTINGS_INITIAL_WINDOW_SIZE]
    b .Lh2_settings_next

.Lh2_st_max_frame_size:
    // §6.5.2 — must be within [2^14, 2^24-1], inclusive
    cmp w7, #H2_DEFAULT_MAX_FRAME_SIZE
    b.lo .Lh2_settings_protocol_error
    mov w8, #H2_MAX_FRAME_SIZE
    cmp w7, w8
    b.hi .Lh2_settings_protocol_error
    str w7, [x2, #H2C_SETTINGS_MAX_FRAME_SIZE]
    b .Lh2_settings_next

.Lh2_st_max_header_list_size:
    str w7, [x2, #H2C_SETTINGS_MAX_HEADER_LIST_SIZE]
    b .Lh2_settings_next

.Lh2_settings_next:
    sub w4, w4, #H2_SETTINGS_ENTRY_LEN
    add x1, x1, #H2_SETTINGS_ENTRY_LEN
    cbnz w4, .Lh2_settings_loop

.Lh2_settings_ok:
    cmn xzr, xzr
    mov x0, #0
    ret

// SETTINGS with ACK — acknowledges receipt of our SETTINGS frame.
// The payload must be empty (§6.5).
.Lh2_settings_ack:
    cbnz w4, .Lh2_settings_size_error
    mov w3, #1
    str w3, [x2, #H2C_ACK_RECEIVED]
    b .Lh2_settings_ok

.Lh2_settings_protocol_error:
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret

.Lh2_settings_size_error:
    cmp xzr, xzr
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret

.Lh2_settings_flow_control_error:
    cmp xzr, xzr
    mov x0, #H2_ERR_FLOW_CONTROL_ERROR
    ret

// ── 3.4/3.5 — the connection preface ────────────────────────────────
// Stage 5. An HTTP/2 client opens the connection by sending the 24-byte
// connection preface (RFC 9113 §3.4):
//
//     PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
//
// The server must read it byte-for-byte, then answer with its own
// connection preface: a SETTINGS frame, which must be the first frame
// the server sends (§3.5). h2_verify_preface performs the read+compare
// and records the connection mode; h2_send_settings emits the SETTINGS
// frame. The connection loop (a later stage) calls them in sequence:
//
//     bl h2_verify_preface   // (fd, buf) -> CONNECTION_HTTP2 on success
//     b.cs  reject_connection
//     bl h2_send_settings    // (fd) -> the opening SETTINGS frame
//     b.cs  reject_connection

// ── 3.4 — verify the client connection preface ──────────────────────
// Read exactly H2_PREFACE_LEN (24) bytes from the client and compare
// them against h2_preface. read() on a stream socket may return fewer
// bytes than requested, so the read loops until all 24 arrive; EINTR is
// retried. On success connection_mode is set to CONNECTION_HTTP2.
//
// input
// x0 -> client file descriptor
// x1 -> buffer of at least H2_PREFACE_LEN bytes to read into
//
// output
// success — carry clear, x0 = CONNECTION_HTTP2
// failure — carry set, x0 = reason:
//     H2_ERR_PROTOCOL_ERROR  the bytes aren't the preface (or EOF)
//     errno                  read() failed (ECONNRESET, ETIMEDOUT, ...)
// Either way the connection is rejected and must be closed.
//
// clobbers x0-x8, x9 (via str_l), x19, x20, x21, x29, x30
h2_verify_preface:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x19, x0            // fd
    mov x20, x1            // buffer
    mov x21, #0            // bytes read so far
.Lh2_preface_read:
    SCWINUM SYS_read
    mov x0, x19
    add x1, x20, x21       // append at the end of what we already have
    mov x2, #H2_PREFACE_LEN
    sub x2, x2, x21
    SCWISVC
    SCERR
    b.cs .Lh2_preface_read_failed
    cbz x0, .Lh2_preface_bad       // EOF before the full preface
    add x21, x21, x0
    cmp x21, #H2_PREFACE_LEN
    b.lo .Lh2_preface_read

    // 24 bytes = three 8-byte words; the buffer and the constant are
    // both read little-endian, so plain word compares are exact.
    adr_l x9, h2_preface
    ldr x2, [x20]
    ldr x3, [x9]
    cmp x2, x3
    b.ne .Lh2_preface_bad
    ldr x2, [x20, #8]
    ldr x3, [x9, #8]
    cmp x2, x3
    b.ne .Lh2_preface_bad
    ldr x2, [x20, #16]
    ldr x3, [x9, #16]
    cmp x2, x3
    b.ne .Lh2_preface_bad

    // preface confirmed — the connection speaks HTTP/2
    mov x0, #CONNECTION_HTTP2
    str_l x0, connection_mode
    cmn xzr, xzr           // success — carry clear
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

.Lh2_preface_read_failed:
    cmp x0, #EINTR
    b.eq .Lh2_preface_read  // interrupted — retry, nothing was read
    cmp xzr, xzr            // failure — carry set
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret                     // x0 = errno

.Lh2_preface_bad:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

// ── 3.5 — send the server's opening SETTINGS frame ──────────────────
// Emit h2_settings_frame — the opening SETTINGS frame with
// SETTINGS_HEADER_TABLE_SIZE = 0 (dynamic table disabled), valid as the
// first frame of the server connection preface (§3.5, §6.5). Delegates
// to write_all (util.S) so partial writes are completed.
//
// input
// x0 -> client file descriptor
//
// output
// success — carry clear, x0 = bytes written (h2_settings_frame_len)
// failure — carry set, x0 = errno (EPIPE, ECONNRESET, ...)
//
// clobbers x0, x1, x2, x8, x16 (syscall registers; see write_all)
h2_send_settings:
    adr_l x1, h2_settings_frame
    mov x2, #(H2_WIRE_HEADER_LEN + H2_SETTINGS_ENTRY_LEN) // header + 1 entry
    b write_all
