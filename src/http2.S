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

// HTTP/2 frame engine (RFC 9113 §4-§6.5).
//
// Stage 4 — the frame layer: 9-byte frame header decoding (§4.1), frame
// size validation (§4.2), frame dispatch (§5.5) and SETTINGS handling
// (§6.5). The connection preface and the connection read loop arrive in
// a later stage; these functions are the protocol-neutral heart of the
// engine and take a parsed frame header plus the h2_conn connection
// state, so they are testable in isolation.
//
// Error convention (shared with the rest of ymawky):
//   carry clear = success, x0 = 0
//   carry set   = failure, x0 = HTTP/2 error code (H2_ERR_*)
// A frame handler that reports an error means the connection is
// poisoned — the connection loop must send GOAWAY and close.

.global h2_parse_frame_header
.global h2_validate_frame
.global h2_dispatch_frame
.global h2_handle_settings
.global h2_conn
.global h2_frame_header

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

.bss
.align 3
// h2_frame_header — scratch for the parsed frame header. The connection
// loop parses the 9 wire bytes into this before validating/dispatching.
h2_frame_header:
    .skip H2F_SIZE

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
// Stage 4: every handler except SETTINGS acknowledges receipt and does
// nothing else; their real behaviour (streams, HPACK, flow control)
// arrives in later stages. All handlers receive x0 -> frame header,
// x1 -> payload, x2 -> connection state and return via the dispatcher's
// tail call. Each must fully establish the return contract (x0 = 0,
// carry clear) — the dispatcher leaves the flags from its type compare,
// so a handler may not assume anything about them on entry.

h2_handle_data:
h2_handle_headers:
h2_handle_priority:
h2_handle_rst_stream:
h2_handle_push_promise:
h2_handle_ping:
h2_handle_goaway:
h2_handle_window_update:
h2_handle_continuation:
.Lh2_handler_ok:
    cmn xzr, xzr // success — carry clear
    mov x0, #0
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
