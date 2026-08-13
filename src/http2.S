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
// PING, GOAWAY and CONTINUATION remain stubs (WINDOW_UPDATE arrives in
// Stage 11).
//
// Stage 7 — HPACK lands in its own file (h2_hpack.S). Here the opening
// SETTINGS frame now advertises SETTINGS_HEADER_TABLE_SIZE = 0 (§6.5.2),
// disabling the HPACK dynamic table so the static-table-only decoder in
// h2_hpack.S can reject every dynamic-table representation. Flow control
// arrives in a later stage.
//
// Stage 8 — the HEADERS frame becomes a request. h2_handle_headers now
// extracts the stream id, the header block and the END_STREAM/END_HEADERS
// flags, decodes the block with h2_hpack_decode_block and converts the
// decoded fields into the protocol-neutral `request` struct via
// h2_build_request (8.1). h2_build_request extracts the request
// pseudo-headers (:method, :path, :scheme, :authority; 8.2) and rejects
// malformed ones — a missing or empty :method, a missing :path for the
// methods we process, duplicate pseudo-headers, undefined
// pseudo-headers, or pseudo-headers after a regular header — with
// PROTOCOL_ERROR (8.3). The path is assembled through parse_h2_path in
// parse.S plus the shared decode_url/check_path_* safety checks, so an
// HTTP/2 request gets exactly the same internal representation as its
// HTTP/1 twin (8.4). CONTINUATION and trailers are still later stages.
//
// Stage 10 — complete static responses. HEAD already rides the common
// response machinery (headers only, END_STREAM on the HEADERS frame);
// 404 answers an unresolved resource; 403 answers a path the server
// refuses (check_path_safety / check_path_traversal rejection — recorded
// in REQ_FORBIDDEN so the request still decodes cleanly); MIME types come
// from the same create_response path HTTP/1 uses; and byte ranges are
// parsed (h2_parse_range) and resolved against the resource size
// (h2_resolve_range) into a 206 with content-range, or 416. GET serves
// ranges; HEAD ignores them, matching HTTP/1's head.
//
// Stage 11 — DATA flow control (RFC 9113 §5.2, §6.9). The server tracks
// the send-side credit the client has granted: the connection window
// (H2C_WINDOW, shared by all streams) and each stream's window
// (H2S_WINDOW, initialised from the peer's SETTINGS_INITIAL_WINDOW_SIZE).
// h2_write_body bounds every DATA chunk by min(connection window, stream
// window, remaining) and drains both windows as it sends; when the body
// outlives the credit it blocks reading frames and dispatching them
// until a WINDOW_UPDATE replenishes the window. h2_handle_window_update
// (§6.9) adds the 31-bit increment to the connection window (stream 0)
// or the stream window, rejecting bad lengths, zero increments, idle
// streams and over-2^31 windows, and ignoring updates on CLOSED streams.
// This makes files larger than the initial 65535-byte window deliver
// end-to-end without deadlock.
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
.global h2_build_request
.global h2_probe
.global h2_connection_loop
.global h2_process_request
.global h2_write_headers
.global h2_write_body
.global h2_reply_status
.global h2_parse_range
.global h2_resolve_range

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
    .quad H2_DEFAULT_INITIAL_WINDOW_SIZE   // H2C_WINDOW — connection window (§5.2)

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

// ── Stage 8 — request pseudo-header and method name constants ────────
// Byte-exact names h2_build_request compares decoded field names and
// values against. The pseudo-headers are the four a request may carry;
// the method strings mirror parse_request's case-sensitive detection.
.align 1
h2_pseudo_method:
    .asciz ":method"
.equ h2_pseudo_method_len, . - h2_pseudo_method - 1
h2_pseudo_path:
    .asciz ":path"
.equ h2_pseudo_path_len, . - h2_pseudo_path - 1
h2_pseudo_scheme:
    .asciz ":scheme"
.equ h2_pseudo_scheme_len, . - h2_pseudo_scheme - 1
h2_pseudo_authority:
    .asciz ":authority"
.equ h2_pseudo_authority_len, . - h2_pseudo_authority - 1
h2_method_get:
    .asciz "GET"
.equ h2_method_get_len, . - h2_method_get - 1
h2_method_head:
    .asciz "HEAD"
.equ h2_method_head_len, . - h2_method_head - 1
h2_method_options:
    .asciz "OPTIONS"
.equ h2_method_options_len, . - h2_method_options - 1
h2_method_brew:
    .asciz "BREW"
.equ h2_method_brew_len, . - h2_method_brew - 1

// the content-encoding value the response encoder appends for gzipped
// embedded assets (HTTP/1's encoder sends the same header)
h2_gzip_str:
    .ascii "gzip"
.equ h2_gzip_str_len, . - h2_gzip_str

// the request header name h2_build_request matches to feed the Range
// machinery, and the range-unit prefix h2_parse_range accepts (both
// matched case-insensitively, like HTTP/1's get_header_field/parse_range)
h2_range_name:
    .asciz "range"
.equ h2_range_name_len, 5
h2_bytes_name:
    .asciz "bytes"
.equ h2_bytes_name_len, 5

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

// h2_frame_buf — one outgoing frame: a 9-byte frame header followed by
// its payload (an HPACK header block or a DATA chunk). The response
// encoders build the whole frame here and write it in one write_all, so
// a partial write can't split a frame. Sized for the largest accepted
// frame (h2_validate_frame caps payloads at H2C_MAX_RX_FRAME_SIZE).
.equ h2_frame_buf_size, H2_WIRE_HEADER_LEN + H2_DEFAULT_MAX_FRAME_SIZE
.align 4
h2_frame_buf:
    .skip h2_frame_buf_size

// h2_range_buf — persistent copy of the request's Range header value
// ("bytes=0-99"). The decoded value points into h2_hpack_str_buf, which
// is per-block scratch, so it is copied here — like :authority into
// authority_buf — to survive until h2_process_request parses it.
.equ h2_range_buf_size, 64
.align 3
h2_range_buf:
    .skip h2_range_buf_size

// h2_cr_buf — scratch for assembling the content-range header value
// ("start-end/total") in h2_write_headers before it is appended to the
// HPACK block with its string length prefix.
.equ h2_cr_buf_size, 64
.align 3
h2_cr_buf:
    .skip h2_cr_buf_size

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

// ── 6.3/6.2 + 8.1 — HEADERS ─────────────────────────────────────────
// Open or update the stream named by the frame. A HEADERS frame is the
// only thing that may open a new client stream (§5.1): the id must pass
// h2_validate_stream_id, the stream is created in IDLE and moved to
// OPEN, and the END_STREAM flag then moves it to HALF_CLOSED_REMOTE.
// Since Stage 8 the frame's flags are recorded on the stream entry
// (END_STREAM/END_HEADERS are extracted there), the HPACK-encoded
// header block is decoded with h2_hpack_decode_block, and the decoded
// fields are converted into the protocol-neutral `request` struct by
// h2_build_request. An undecodable block is a COMPRESSION_ERROR
// connection error (§4.3); a malformed request is a PROTOCOL_ERROR
// stream error (§8.1.1).
//
// NOTE: the dispatcher reaches us with br, so x30 is the return address
// of the dispatcher's caller — save it before our own bl calls.
//
// input/output: as h2_dispatch_frame
//
// clobbers x0-x15, x19 (saved/restored), x30 (saved/restored)
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
.Lh2_headers_err:
    ldp x19, x30, [sp], #32
    ret                      // x0 = error, carry set

// ── 6.3 — DATA ──────────────────────────────────────────────────────
// DATA frames carry request body bytes. Only an existing stream may
// receive them — an unknown stream is an idle-stream violation
// (PROTOCOL_ERROR, §5.1); any other invalid state is STREAM_CLOSED.
// END_STREAM on the frame closes the client's send side. The payload
// is not consumed yet (receive-side flow control and body handling
// arrive later; Stage 11 tracks the send-side windows in h2_write_body
// and h2_handle_window_update).
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
// PRIORITY, PUSH_PROMISE, PING, GOAWAY, CONTINUATION (WINDOW_UPDATE
// landed in Stage 11, below).
h2_handle_priority:
h2_handle_push_promise:
h2_handle_ping:
h2_handle_goaway:
h2_handle_continuation:
.Lh2_handler_ok:
    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret

// ── 6.9 — WINDOW_UPDATE ─────────────────────────────────────────────
// Replenish flow-control credit (RFC 9113 §6.9). The payload is one
// 31-bit increment (big-endian; the reserved top bit is ignored).
// Stream 0 updates the connection window; a nonzero stream id updates
// that stream's window. A length other than 4 is a FRAME_SIZE_ERROR; an
// increment of 0 is a PROTOCOL_ERROR; an update that would push a
// window past 2^31-1 is a FLOW_CONTROL_ERROR; and an update for a
// stream that isn't in the table (an idle stream) is a PROTOCOL_ERROR.
// An update on a CLOSED stream is ignored, not an error — a peer may
// send WINDOW_UPDATE after END_STREAM (§5.1 closed).
//
// input/output: as h2_dispatch_frame
//
// clobbers x0-x6, x9, x30 (saved/restored)
h2_handle_window_update:
    str x30, [sp, #-16]!   // save the return address — find clobbers x30
    mov x7, #H2_MAX_FLOW_WINDOW   // 2^31 - 1 — the window ceiling (§5.2)
    // exactly 4 payload bytes — one 32-bit increment (§6.9)
    ldr w3, [x0, #H2F_LENGTH]
    cmp w3, #4
    b.ne .Lh2wu_size_error
    // increment — 31-bit big-endian
    ldrb w4, [x1]
    ldrb w5, [x1, #1]
    ldrb w6, [x1, #2]
    ldrb w3, [x1, #3]
    lsl w4, w4, #24
    orr w4, w4, w5, lsl #16
    orr w4, w4, w6, lsl #8
    orr w4, w4, w3
    and w4, w4, #0x7fffffff   // mask off the reserved bit
    cbz w4, .Lh2wu_zero_error
    mov x5, x4               // increment — x4 is reused for the stream id
    ldr w4, [x0, #H2F_STREAM_ID]
    cbnz w4, .Lh2wu_stream
    // ── connection-level — stream 0 → the connection window ──
    ldr x3, [x2, #H2C_WINDOW]
    add x3, x3, x5
    cmp x3, x7
    b.hi .Lh2wu_flow_error
    str x3, [x2, #H2C_WINDOW]
    b .Lh2wu_ok
.Lh2wu_stream:
    mov x0, x4
    bl h2_stream_find
    cbz x0, .Lh2wu_protocol_error  // idle stream — PROTOCOL_ERROR
    ldr x6, [x0, #H2S_STATE]
    cmp x6, #H2_STREAM_CLOSED
    b.eq .Lh2wu_ok                  // closed — ignore, not an error (§5.1)
    ldr x3, [x0, #H2S_WINDOW]
    add x3, x3, x5
    cmp x3, x7
    b.hi .Lh2wu_flow_error
    str x3, [x0, #H2S_WINDOW]
.Lh2wu_ok:
    ldr x30, [sp], #16
    cmn xzr, xzr             // success — carry clear
    mov x0, #0
    ret
.Lh2wu_protocol_error:
    ldr x30, [sp], #16
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
.Lh2wu_flow_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FLOW_CONTROL_ERROR
    ret
.Lh2wu_size_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret
.Lh2wu_zero_error:
    ldr x30, [sp], #16
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
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
// (stream_id == 0) with a fresh stream: state IDLE, no flags, and a
// send window of the peer's advertised SETTINGS_INITIAL_WINDOW_SIZE
// (RFC 9113 §6.9.2 — the client's initial stream-level credit; the
// connection loop resets it to the 65535 default before the client
// SETTINGS arrive). Creating a stream records its id as the connection's
// new high-water mark for client streams.
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

// ── 8.2/8.3 — the HEADERS block becomes the common request ──────────
// Convert a decoded HEADERS block (h2_hpack_fields[0..count)) into the
// protocol-neutral `request` struct. The request pseudo-headers are
// extracted and validated (RFC 9113 §8.3):
//
//   - every pseudo-header must precede the regular header fields
//   - a pseudo-header may appear at most once
//   - undefined pseudo-headers (e.g. :status in a request) are malformed
//   - :method is required and must not be empty
//   - :path is required for the methods we process (GET/HEAD/OPTIONS)
//     and must be origin-form or asterisk-form (§8.3.1)
//   - :scheme and :authority are carried but not otherwise validated
//
// Any violation is a PROTOCOL_ERROR stream error (RFC 9113 §8.1.1).
//
// The path is assembled exactly like HTTP/1's parse_request: parse_h2_path
// (parse.S) builds the docroot-prefixed filename and splits the query,
// then decode_url / check_path_safety / check_path_traversal (file.S)
// percent-decode and validate it, and the :authority value is copied
// into authority_buf — the same buffers and helpers HTTP/1 uses, so an
// HTTP/2 request and its HTTP/1 twin reach the handlers identically
// (8.4). BREW/unknown methods skip path handling entirely, matching
// HTTP/1 twin (8.4). BREW/unknown methods skip path handling entirely,
// matching parse_request; only REQ_METHOD and REQ_STREAM_ID are set for them.
//
// Stage 10 additions: a regular `range` header value is copied into
// h2_range_buf and recorded in REQ_RANGE_PTR/REQ_RANGE_LEN for the
// Range machinery, and a path rejected by check_path_safety /
// check_path_traversal is not a protocol error — the request decodes
// cleanly with REQ_FORBIDDEN set, so h2_process_request can answer 403.
//
// input
// x0 = stream id
// x1 = number of decoded header fields
//
// output
// success — carry clear, x0 = 0; the `request` struct is filled
// failure — carry set, x0 = H2_ERR_PROTOCOL_ERROR
//
// clobbers x0-x18, x19-x24 (saved/restored), x30
h2_build_request:
    stp x19, x20, [sp, #-160]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    str x30, [sp, #48]
    // zero the value slots: method, path, scheme, authority — each a
    // (ptr, len) pair — plus the range header (ptr, len) and the
    // forbidden flag, so requests that don't set them never inherit the
    // previous request's values
    stp xzr, xzr, [sp, #64]
    stp xzr, xzr, [sp, #80]
    stp xzr, xzr, [sp, #96]
    stp xzr, xzr, [sp, #112]
    stp xzr, xzr, [sp, #128]    // REQ_RANGE_PTR / REQ_RANGE_LEN
    str xzr, [sp, #144]         // REQ_FORBIDDEN

    mov x19, x0             // stream id
    mov x20, x1             // field count
    adr_l x21, h2_hpack_fields
    mov x22, #0             // field index
    mov x23, #0             // a regular header has been seen
    mov x24, #UNKNOWN_ID    // method id

.Lh2_req_loop:
    cmp x22, x20
    b.hs .Lh2_req_scan_done
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    ldr x4, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x5, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    ldrb w6, [x0]
    cmp w6, #':'
    b.ne .Lh2_req_normal
    // a pseudo-header — it must come before any regular header
    cbnz x23, .Lh2_req_pseudo_after_normal
    // classify the name with exact byte compares
    adr_l x2, h2_pseudo_method
    mov x3, h2_pseudo_method_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_method_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_path
    mov x3, h2_pseudo_path_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_path_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_scheme
    mov x3, h2_pseudo_scheme_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_scheme_hit
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    adr_l x2, h2_pseudo_authority
    mov x3, h2_pseudo_authority_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_authority_hit
    b .Lh2_req_unknown_pseudo
.Lh2_req_method_hit:
    ldr x6, [sp, #64]       // already seen — duplicate
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #64]
    str x7, [sp, #72]
    b .Lh2_req_next
.Lh2_req_path_hit:
    ldr x6, [sp, #80]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #80]
    str x7, [sp, #88]
    b .Lh2_req_next
.Lh2_req_scheme_hit:
    ldr x6, [sp, #96]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #96]
    str x7, [sp, #104]
    b .Lh2_req_next
.Lh2_req_authority_hit:
    ldr x6, [sp, #112]
    cbnz x6, .Lh2_req_dup
    ldr x6, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x7, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    str x6, [sp, #112]
    str x7, [sp, #120]
    b .Lh2_req_next
.Lh2_req_normal:
    mov x23, #1             // regular headers follow the pseudo-headers
    // ── Stage 10 — a regular `range` header feeds the Range machinery ──
    // Matched case-insensitively like HTTP/1's get_header_field; the
    // first occurrence wins (later duplicates are ignored).
    ldr x0, [x21, #H2_HPACK_FIELD_NAME_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_NAME_LEN]
    cmp x1, h2_range_name_len
    b.ne .Lh2_req_next
    adr_l x1, h2_range_name
    mov x2, h2_range_name_len
    bl streqn_i
    cbz x0, .Lh2_req_next
    ldr x6, [sp, #128]       // already seen — keep the first
    cbnz x6, .Lh2_req_next
    // copy the value into h2_range_buf so it outlives the per-block
    // HPACK string buffer (same reason :authority is copied)
    ldr x0, [x21, #H2_HPACK_FIELD_VALUE_PTR]
    ldr x1, [x21, #H2_HPACK_FIELD_VALUE_LEN]
    adr_l x7, h2_range_buf
    mov x8, #0              // bytes copied
1:  cbz x1, 2f
    cmp x8, h2_range_buf_size
    b.hs 2f                 // too long — truncate, like authority_buf
    ldrb w3, [x0, x8]
    strb w3, [x7, x8]
    add x8, x8, #1
    sub x1, x1, #1
    b 1b
2:  str x7, [sp, #128]
    str x8, [sp, #136]
    b .Lh2_req_next
.Lh2_req_next:
    add x21, x21, #H2_HPACK_FIELD_SIZE
    add x22, x22, #1
    b .Lh2_req_loop

.Lh2_req_scan_done:
    // :method must be present and non-empty (§8.3.1)
    ldr x0, [sp, #64]
    cbz x0, .Lh2_req_missing_method
    ldr x1, [sp, #72]
    cbz x1, .Lh2_req_missing_method
    // map the method string to a method id (case-sensitive, like HTTP/1)
    adr_l x2, h2_method_get
    mov x3, h2_method_get_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_get
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_head
    mov x3, h2_method_head_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_head
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_options
    mov x3, h2_method_options_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_options
    ldr x0, [sp, #64]
    ldr x1, [sp, #72]
    adr_l x2, h2_method_brew
    mov x3, h2_method_brew_len
    bl h2_name_eq
    cbnz x0, .Lh2_req_m_brew
    b .Lh2_req_method_done  // unknown method — x24 stays UNKNOWN_ID
.Lh2_req_m_get:
    mov x24, #GET_ID
    b .Lh2_req_method_done
.Lh2_req_m_head:
    mov x24, #HEAD_ID
    b .Lh2_req_method_done
.Lh2_req_m_options:
    mov x24, #OPTIONS_ID
    b .Lh2_req_method_done
.Lh2_req_m_brew:
    mov x24, #BREW_ID
.Lh2_req_method_done:
    // BREW/UNKNOWN get no path handling — mirroring parse_request, only
    // the method and stream id are recorded
    cmp x24, #OPTIONS_ID
    b.hi .Lh2_req_store_method_only
    // :path is required for the methods we process
    ldr x0, [sp, #80]
    cbz x0, .Lh2_req_missing_path
    ldr x1, [sp, #88]
    cbz x1, .Lh2_req_missing_path
    // assemble the docroot-prefixed path; the default file is for
    // GET/HEAD only, OPTIONS keeps the bare docroot
    mov x2, #1
    cmp x24, #OPTIONS_ID
    b.ne 1f
    mov x2, #0
1:
    bl parse_h2_path
    b.cs .Lh2_req_bad_path
    str x0, [sp, #80]       // assembled filename (filename_buf)
    str x1, [sp, #88]       // filename length
    str x2, [sp, #96]       // query string (query_buf), or 0
    str x3, [sp, #104]      // query length
    // percent-decode in place, then the same safety checks as HTTP/1
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl decode_url
    cbz x0, .Lh2_req_bad_path
    str x0, [sp, #80]
    str x1, [sp, #88]
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl check_path_safety
    cbz x0, .Lh2_req_forbidden
    ldr x0, [sp, #80]
    ldr x1, [sp, #88]
    bl check_path_traversal
    cbz x0, .Lh2_req_forbidden
    // copy :authority into authority_buf, NUL-terminated (bounded)
    ldr x0, [sp, #112]
    cbz x0, .Lh2_req_no_authority
    ldr x1, [sp, #120]
    adr_l x8, authority_buf
    mov x9, #0              // bytes copied
1:
    cbz x1, 2f
    cmp x9, AUTHORITY_BUF_SIZE
    b.hs 2f                 // too long — truncate
    ldrb w3, [x0, x9]
    strb w3, [x8, x9]
    add x9, x9, #1
    sub x1, x1, #1
    b 1b
2:
    strb wzr, [x8, x9]
    mov x7, x8
    b .Lh2_req_store
.Lh2_req_no_authority:
    mov x7, #0
.Lh2_req_store:
    adr_l x0, request
    str x24, [x0, #REQ_METHOD]
    str x19, [x0, #REQ_STREAM_ID]
    ldr x1, [sp, #80]
    str x1, [x0, #REQ_PATH]
    ldr x2, [sp, #88]
    str x2, [x0, #REQ_PATH_LENGTH]
    ldr x3, [sp, #96]
    str x3, [x0, #REQ_QUERY]
    ldr x4, [sp, #104]
    str x4, [x0, #REQ_QUERY_LENGTH]
    str x7, [x0, #REQ_AUTHORITY]
    ldr x5, [sp, #128]
    str x5, [x0, #REQ_RANGE_PTR]
    ldr x5, [sp, #136]
    str x5, [x0, #REQ_RANGE_LEN]
    ldr x5, [sp, #144]
    str x5, [x0, #REQ_FORBIDDEN]
    b .Lh2_req_ok
.Lh2_req_store_method_only:
    adr_l x0, request
    str x24, [x0, #REQ_METHOD]
    str x19, [x0, #REQ_STREAM_ID]
    ldr x5, [sp, #128]
    str x5, [x0, #REQ_RANGE_PTR]
    ldr x5, [sp, #136]
    str x5, [x0, #REQ_RANGE_LEN]
    ldr x5, [sp, #144]
    str x5, [x0, #REQ_FORBIDDEN]
.Lh2_req_ok:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2_req_epilogue
.Lh2_req_dup:
.Lh2_req_pseudo_after_normal:
.Lh2_req_unknown_pseudo:
.Lh2_req_missing_method:
.Lh2_req_missing_path:
.Lh2_req_bad_path:
.Lh2_req_bad:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
.Lh2_req_epilogue:
    ldr x30, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #160
    ret

// A path the server refuses to serve (unsafe bytes, traversal) is not a
// protocol violation — the request decodes, and h2_process_request
// answers 403. The decoded path is stored for completeness; the handler
// never looks at it.
.Lh2_req_forbidden:
    mov x7, #0              // no authority copy — the path is rejected
    mov x6, #1
    str x6, [sp, #144]
    b .Lh2_req_store

// h2_name_eq — byte-exact compare of (x0, len x1) with the string at
// x2 (of length x3). Returns x0 = 1 if equal, 0 otherwise. Reading is
// bounded by the lengths, so a decoded name or value that points into a
// header block (not NUL-terminated) is safe to compare.
//
// clobbers x0-x6
h2_name_eq:
    cmp x1, x3
    b.ne .Lh2_name_ne
    mov x4, #0
.Lh2_name_loop:
    cmp x4, x1
    b.hs .Lh2_name_eq_yes
    ldrb w5, [x0, x4]
    ldrb w6, [x2, x4]
    cmp w5, w6
    b.ne .Lh2_name_ne
    add x4, x4, #1
    b .Lh2_name_loop
.Lh2_name_eq_yes:
    mov x0, #1
    ret
.Lh2_name_ne:
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

// ═══════════════════════════════════════════════════════════════════
//  Stage 9 — the first working HTTP/2 GET
//
//  The connection loop (h2_connection_loop) turns a new connection into
//  an HTTP/2 conversation: finish the client connection preface (§3.4),
//  send our opening SETTINGS (§3.5), then loop over frames. Whenever a
//  stream's request is complete (the stream has reached
//  HALF_CLOSED_REMOTE), the request is served through the existing
//  static-file machinery — h2_process_request resolves the common
//  `request` struct with lookup_embedded and create_response, and the
//  HTTP/2 encoder (h2_write_headers + h2_write_body) sends HEADERS and
//  DATA frames.
//
//  Error convention stays the same as the rest of the file:
//    carry clear = success
//    carry set   = failure
//  The loop treats a dispatch error as a connection error (GOAWAY and
//  close), except STREAM_CLOSED, which is a stream error (RST_STREAM
//  and keep going).
// ═══════════════════════════════════════════════════════════════════

// ── read exactly len bytes from the fd into buf ─────────────────────
// Loops over short reads; EINTR is retried; EOF or any other error
// returns with carry set. The frame loop relies on this so a frame is
// never partially buffered.
//
// input
// x0 = fd, x1 -> buffer, x2 = length
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = errno (0 on EOF)
//
// clobbers x0-x4, x19-x21, x30 (x19-x21 saved/restored)
h2_read_exact:
    stp x19, x20, [sp, #-32]!
    stp x21, x30, [sp, #16]
    mov x19, x0             // fd
    mov x20, x1             // buffer
    mov x21, x2             // bytes remaining
.Lh2rex_loop:
    cbz x21, .Lh2rex_done
    SCWINUM SYS_read
    mov x0, x19
    mov x1, x20
    mov x2, x21
    SCWISVC
    SCERR
    b.cs .Lh2rex_fail
    cbz x0, .Lh2rex_eof
    add x20, x20, x0
    sub x21, x21, x0
    b .Lh2rex_loop
.Lh2rex_done:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.Lh2rex_fail:
    cmp x0, #EINTR
    b.eq .Lh2rex_loop       // interrupted — nothing was consumed, retry
    cmp xzr, xzr            // failure — carry set
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret                     // x0 = errno
.Lh2rex_eof:
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret

// ── protocol detection — is this an HTTP/2 client? (Phase 16, Option B)
// Compare buf[0..n) against the start of the 24-byte HTTP/2 connection
// preface. Returns 1 when the bytes are a (possibly partial) prefix of
// the preface — the connection loop then takes over, finishes reading
// the preface and verifies it in full — and 0 for anything else, in
// which case the caller keeps the bytes and parses HTTP/1. The buffer
// is never consumed, so both paths see the same data. An empty buffer
// is never the preface.
//
// input
// x0 -> buffer, x1 = bytes available
//
// output
// x0 = 1 (preface prefix) or 0
//
// clobbers x0-x5, x9
h2_probe:
    cbz x1, .Lh2probe_no
    mov x2, #H2_PREFACE_LEN
    cmp x1, x2
    csel x2, x1, x2, lo     // x2 = min(n, 24)
    adr_l x9, h2_preface
    mov x3, #0
1:
    cmp x3, x2
    b.hs .Lh2probe_yes
    ldrb w4, [x0, x3]
    ldrb w5, [x9, x3]
    cmp w4, w5
    b.ne .Lh2probe_no
    add x3, x3, #1
    b 1b
.Lh2probe_yes:
    mov x0, #1
    ret
.Lh2probe_no:
    mov x0, #0
    ret

// ── 9.4 — the HTTP/2 connection loop ────────────────────────────────
// The per-connection lifecycle for an HTTP/2 client (RFC 9113 §3.4-3.5):
// finish verifying the client connection preface against the bytes
// already buffered (reading more if needed), send our opening SETTINGS
// frame, then loop over frames — read a complete frame, dispatch it,
// and serve any stream whose request became complete (HALF_CLOSED_REMOTE)
// through h2_process_request. Connection errors send GOAWAY; STREAM_CLOSED
// stream errors send RST_STREAM; a timeout or EOF closes the connection.
//
// input
// x0 = client fd
// x1 -> buffer holding the first `n` bytes (a prefix of the preface)
// x2 = n
//
// output
// (none — returns when the connection ends; the caller closes the fd)
//
// clobbers x0-x8, x19-x23 (saved/restored), x30
h2_connection_loop:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x30, [sp, #32]
    mov x19, x0             // fd
    mov x20, x1             // buffer
    mov x21, x2             // bytes already buffered

    // record the request start for the timing log (child_end logs it)
    SCWINUM SYS_gettimeofday
    adr_l x0, req_start
    mov x1, #0
    SCWISVC
    SCERR

    // ── fresh per-connection state (RFC 9113 §6.5.2 defaults) ──
    // The server handles connections sequentially, so a new HTTP/2
    // connection must not inherit the previous one's settings, stream
    // high-water mark or stream table entries.
    adr_l x9, h2_conn
    str xzr, [x9, #H2C_LAST_FRAME_TYPE]
    mov x10, #H2_DEFAULT_MAX_FRAME_SIZE
    str x10, [x9, #H2C_MAX_RX_FRAME_SIZE]
    mov x10, #H2_DEFAULT_HEADER_TABLE_SIZE
    str x10, [x9, #H2C_SETTINGS_HEADER_TABLE_SIZE]
    mov x10, #1
    str x10, [x9, #H2C_SETTINGS_ENABLE_PUSH]
    mov x10, #-1            // 0xffffffff — unlimited
    str x10, [x9, #H2C_SETTINGS_MAX_CONCURRENT_STREAMS]
    mov x10, #H2_DEFAULT_INITIAL_WINDOW_SIZE
    str x10, [x9, #H2C_SETTINGS_INITIAL_WINDOW_SIZE]
    mov x10, #H2_DEFAULT_MAX_FRAME_SIZE
    str x10, [x9, #H2C_SETTINGS_MAX_FRAME_SIZE]
    mov x10, #-1
    str x10, [x9, #H2C_SETTINGS_MAX_HEADER_LIST_SIZE]
    str xzr, [x9, #H2C_ACK_RECEIVED]
    str xzr, [x9, #H2C_LAST_STREAM_ID]
    mov x10, #H2_DEFAULT_INITIAL_WINDOW_SIZE
    str x10, [x9, #H2C_WINDOW]
    adr_l x9, h2_streams
    mov x10, #(H2_MAX_STREAMS * H2S_SIZE) / 16
1:
    stp xzr, xzr, [x9], #16
    subs x10, x10, #1
    b.ne 1b

    // ── 3.4 — verify the client connection preface ──
    cmp x21, #H2_PREFACE_LEN
    b.hs 1f
    // the preface is not fully buffered yet — read the remainder
    mov x0, x19
    add x1, x20, x21
    mov x2, #H2_PREFACE_LEN
    sub x2, x2, x21
    bl h2_read_exact
    b.cs .Lh2cl_end          // EOF/error before the preface — just close
    mov x21, #H2_PREFACE_LEN
1:
    adr_l x9, h2_preface
    ldr x2, [x20]
    ldr x3, [x9]
    cmp x2, x3
    b.ne .Lh2cl_end
    ldr x2, [x20, #8]
    ldr x3, [x9, #8]
    cmp x2, x3
    b.ne .Lh2cl_end
    ldr x2, [x20, #16]
    ldr x3, [x9, #16]
    cmp x2, x3
    b.ne .Lh2cl_end
    // preface confirmed — the connection speaks HTTP/2
    mov x0, #CONNECTION_HTTP2
    str_l x0, connection_mode
    // any bytes beyond the preface are the first frames; compact them to
    // the front of the buffer (forward memcpy is safe: src > dst)
    sub x22, x21, #H2_PREFACE_LEN
    cbz x22, 1f
    mov x0, x20
    add x1, x20, #H2_PREFACE_LEN
    mov x2, x22
    bl memcpy
1:
    mov x21, x22            // leftover frame bytes
    mov x22, #0             // buffer cursor

    // ── 3.5 — our opening SETTINGS (the server connection preface) ──
    mov x0, x19
    bl h2_send_settings
    b.cs .Lh2cl_end

.Lh2cl_frame_loop:
    // ── ensure a full 9-byte frame header is buffered ──
    cmp x21, #H2_WIRE_HEADER_LEN
    b.hs .Lh2cl_have_header
    cbz x21, 1f
    mov x0, x20
    add x1, x20, x22
    mov x2, x21
    bl memcpy               // compact the leftover to the front
    mov x22, #0
1:
    mov x0, x19
    add x1, x20, x21
    mov x2, #H2_WIRE_HEADER_LEN
    sub x2, x2, x21
    bl h2_read_exact
    b.cs .Lh2cl_end          // timeout / EOF / error — close
    mov x21, #H2_WIRE_HEADER_LEN
    mov x22, #0
.Lh2cl_have_header:
    add x0, x20, x22
    adr_l x1, h2_frame_header
    bl h2_parse_frame_header
    add x22, x22, #H2_WIRE_HEADER_LEN
    sub x21, x21, #H2_WIRE_HEADER_LEN
    adr_l x0, h2_frame_header
    adr_l x1, h2_conn
    bl h2_validate_frame
    b.cs .Lh2cl_conn_error
    adr_l x0, h2_frame_header
    ldr w23, [x0, #H2F_LENGTH]

    // ── ensure the whole payload is buffered ──
    cmp x21, x23
    b.hs .Lh2cl_have_payload
    cbz x21, 1f
    mov x0, x20
    add x1, x20, x22
    mov x2, x21
    bl memcpy
    mov x22, #0
1:
    mov x0, x19
    add x1, x20, x21
    sub x2, x23, x21
    bl h2_read_exact
    b.cs .Lh2cl_end
    mov x21, x23
    mov x22, #0
.Lh2cl_have_payload:
    adr_l x0, h2_frame_header
    add x1, x20, x22
    adr_l x2, h2_conn
    bl h2_dispatch_frame
    b.cs .Lh2cl_dispatch_error
    // the frame is fully consumed
    add x22, x22, x23
    sub x21, x21, x23

    // ── request processing hook ──
    // A stream whose request is complete (HALF_CLOSED_REMOTE) is served
    // immediately through the common request → resource handler. The
    // stream is never left in HALF_CLOSED_REMOTE: h2_process_request
    // moves it to CLOSED once the response is on the wire.
    adr_l x0, h2_frame_header
    ldr w0, [x0, #H2F_STREAM_ID]
    cbz w0, .Lh2cl_frame_loop
    bl h2_stream_find
    cbz x0, .Lh2cl_frame_loop
    ldr x1, [x0, #H2S_STATE]
    cmp x1, #H2_STREAM_HALF_CLOSED_REMOTE
    b.ne .Lh2cl_frame_loop
    adr_l x0, h2_frame_header
    ldr w0, [x0, #H2F_STREAM_ID]
    mov x1, x19
    bl h2_process_request
    b .Lh2cl_frame_loop

.Lh2cl_dispatch_error:
    // consume the frame regardless, so the connection stays in sync
    add x22, x22, x23
    sub x21, x21, x23
    // STREAM_CLOSED is a stream error — RST_STREAM and keep serving;
    // anything else poisons the connection — GOAWAY and close
    cmp x0, #H2_ERR_STREAM_CLOSED
    b.eq .Lh2cl_rst_stream
    mov x1, x0
    mov x0, x19
    bl h2_send_goaway
    b .Lh2cl_end
.Lh2cl_rst_stream:
    adr_l x9, h2_frame_header
    ldr w1, [x9, #H2F_STREAM_ID]
    cbz w1, .Lh2cl_end
    mov x2, x0
    mov x0, x19
    bl h2_send_rst_stream
    b .Lh2cl_frame_loop

.Lh2cl_conn_error:
    // frame validation failed — GOAWAY with the reason, then close
    mov x1, x0
    mov x0, x19
    bl h2_send_goaway
    b .Lh2cl_end

.Lh2cl_end:
    ldp x23, x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

// ── 9.1 — serve a completed request through the existing handlers ───
// The glue between the HTTP/2 HEADERS decoder and the static-file
// machinery: read the protocol-neutral `request` struct (filled by
// h2_build_request) and serve it the way HTTP/1 does — lookup_embedded
// resolves the path, the embedded_* globals are stored exactly as
// get_setup stores them, create_response fills the protocol-neutral
// response struct, and the HTTP/2 encoder (h2_write_headers +
// h2_write_body) sends it. GET sends headers + body; HEAD sends headers
// only (END_STREAM on the HEADERS frame); OPTIONS is 204 when the path
// resolves and 404 otherwise; BREW is 418; any unknown method is 501.
// A failed resource lookup is a 404. Stage 10: a path the server refuses
// (REQ_FORBIDDEN) is a 403; a satisfiable Range on a GET is a 206 with
// content-range (HEAD ignores ranges, like HTTP/1's head); an
// unsatisfiable range is a 416. The stream is moved to CLOSED once the
// response is on the wire.
//
// input
// x0 = stream id
// x1 = client fd
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = errno
//
// clobbers x0-x9, x19-x26 (saved/restored), x30
h2_process_request:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    str x30, [sp, #64]
    // [sp, #72] = response range start, [sp, #80] = range end — the
    // response window is built on the stack because it must survive the
    // create_response / h2_write_headers calls
    mov x19, x0             // stream id
    mov x20, x1             // fd
    adr_l x9, request
    // ── Stage 10 — a path the server refuses to serve is a 403 ──
    ldr x10, [x9, #REQ_FORBIDDEN]
    cbz x10, 1f
    mov x0, #403
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
1:
    ldr x21, [x9, #REQ_METHOD]

    cmp x21, #GET_ID
    b.eq .Lh2pr_resolve
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_resolve
    cmp x21, #OPTIONS_ID
    b.eq .Lh2pr_options
    cmp x21, #BREW_ID
    b.eq .Lh2pr_brew
    // unknown method — 501 (headers only)
    mov x0, #501
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_brew:
    mov x0, #418
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_options:
    // like options.S: 204 when the path resolves, 404 otherwise
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cc 1f
    mov x0, #404
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
1:
    mov x0, #204
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_resolve:
    // GET/HEAD — resolve the resource through the same lookup the HTTP/1
    // path uses; a miss returns here with carry (no reply_status side
    // effects), so the HTTP/2 encoder answers with the 404
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cs .Lh2pr_404
    // x0=content, x1=size, x2=ct, x3=ct_len, x4=gzip, x5=etag, x6=etag_len
    mov x22, x0             // content
    mov x23, x1             // size
    mov x24, x2             // ct
    mov x25, x3             // ct_len
    mov x26, x4             // gzip flag
    	// the response builders read the embedded_* globals. NOTE: str_l with
    	// x9 as the source needs an explicit scratch register — the default
    	// (x9) would be clobbered by adrp before the store.
    	str_l x0, embedded_content
    	str_l x2, embedded_ct
    	str_l x3, embedded_ct_len
    	str_l x4, embedded_gzip
    	str_l x5, embedded_etag
    	str_l x6, embedded_etag_len
    	mov x9, #1
    	str_l x9, resource_type, x10
    	mov x9, #-1
    	str_l x9, file_des, x10  // nothing is open — child_end must not close
    // ── Stage 10 — Range: resolve a request range against the size ──
    // GET serves ranges; HEAD ignores them (HTTP/1's head never parses
    // the Range header). The response window defaults to -1/-1 (none)
    // in the [sp, #72]/[sp, #80] slots. x9/x10 are caller-saved scratch
    // — x27/x28 are callee-saved (x28 is Darwin's frame base) and must
    // not be clobbered here.
    mov x9, #-1
    str x9, [sp, #72]
    mov x10, #-1
    str x10, [sp, #80]
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_create
    adr_l x9, request
    ldr x0, [x9, #REQ_RANGE_PTR]
    cbz x0, .Lh2pr_create
    ldr x1, [x9, #REQ_RANGE_LEN]
    bl h2_parse_range
    b.cs .Lh2pr_create      // unparsable — ignore the range
    mov x2, x23             // resource size
    bl h2_resolve_range     // x0=start, x1=end, x2=200/206/416
    cmp x2, #416
    b.eq .Lh2pr_416
    cmp x2, #200
    b.eq .Lh2pr_create      // range covers the whole file — no range
    str x0, [sp, #72]       // range start
    str x1, [sp, #80]       // range end
.Lh2pr_create:
    // resolve resource → create response (GET: full body, HEAD: none;
    // ranged GET: status 206, windowed body)
    adr_l x0, response
    mov x1, #200
    ldr x3, [sp, #72]
    cmn x3, #1
    b.eq 1f
    mov x1, #206
1:
    mov x2, x23             // content_length (total resource size)
    ldr x4, [sp, #80]       // range end
    mov x5, x22             // body ptr
    mov x6, x23             // body length
    ldr x3, [sp, #72]       // range start
    cmn x3, #1
    b.eq 2f
    // a ranged body is content[start .. end]
    add x5, x5, x3
    ldr x4, [sp, #80]
    sub x6, x4, x3
    add x6, x6, #1
2:
    cmp x21, #HEAD_ID
    b.ne 3f
    mov x6, #0              // HEAD — headers only
3:
    bl create_response
    // encode — GET finishes the stream with DATA frames; HEAD puts
    // END_STREAM on the HEADERS frame
    mov x0, x20
    adr_l x1, response
    mov x2, x19
    mov x3, #0
    cmp x21, #HEAD_ID
    b.ne 1f
    mov x3, #H2_FLAG_END_STREAM
1:
    bl h2_write_headers
    b.cs .Lh2pr_500
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_done
    mov x0, x20
    adr_l x1, response
    mov x2, x19
    bl h2_write_body
    b.cs .Lh2pr_500
    b .Lh2pr_done

.Lh2pr_416:
    mov x0, #416
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_404:
    mov x0, #404
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
.Lh2pr_500:
    mov x0, #500
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
.Lh2pr_done:
    // the response is fully sent — the stream is closed on our side
    mov x0, x19
    bl h2_stream_find
    cbz x0, 1f
    mov x1, #H2_STREAM_CLOSED
    str x1, [x0, #H2S_STATE]
1:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ldr x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret

// ── 10.5 — h2_parse_range: parse a Range header value ──────────────
// Parse the decoded value of a `range` request header ("bytes=0-99",
// "bytes=100-", "bytes=-50") into a (start, end) pair — the same shape
// HTTP/1's parse_range produces. -1 means the part is absent: a -1
// start is a suffix range, a -1 end is open-ended. The value scan
// mirrors parse_range's value half (case-insensitive "bytes" prefix,
// digits up to '-', 19-digit cap, end < start rejected), but works on
// the bare value rather than the whole HTTP/1 header buffer, so it
// terminates on the value length instead of a CRLF.
//
// input
// x0 -> range value (e.g. "bytes=0-99")
// x1 -> value length
//
// output
// x0 -> start (-1 = suffix range)
// x1 -> end   (-1 = open-ended)
// carry clear = usable single range; carry set = no usable range
//
// clobbers x0-x17, x30 (saved/restored)
h2_parse_range:
    str x30, [sp, #-16]!
    mov x6, x0              // value ptr — survives streqn_i / atoi_n
    mov x7, x1              // value length
    // must be at least "bytes=" (6 bytes) with the right prefix
    cmp x7, #6
    b.lo .Lh2pr_no_range
    mov x0, x6
    adr_l x1, h2_bytes_name
    mov x2, #h2_bytes_name_len
    bl streqn_i
    cbz x0, .Lh2pr_no_range
    ldrb w4, [x6, #5]
    cmp w4, #'='
    b.ne .Lh2pr_no_range
    // ── the start: digits up to '-' ──
    mov x8, #6              // cursor
    mov x4, #0              // start digit count
.Lh2pr_start_digits:
    cmp x8, x7
    b.ge .Lh2pr_no_range    // ran off the value before '-' — invalid
    ldrb w5, [x6, x8]
    cmp w5, #'-'
    b.eq .Lh2pr_start_done
    cmp w5, #'0'
    b.lo .Lh2pr_no_range
    cmp w5, #'9'
    b.hi .Lh2pr_no_range
    add x4, x4, #1
    cmp x4, #19
    b.ge .Lh2pr_no_range    // atoi_n's overflow guard (like parse_range)
    add x8, x8, #1
    b .Lh2pr_start_digits
.Lh2pr_start_done:
    // empty start is a suffix range
    cbz x4, .Lh2pr_suffix
    mov x0, x6
    add x0, x0, #6
    mov x1, x4
    bl atoi_n
    b.cs .Lh2pr_no_range
    mov x9, x0              // start
    b .Lh2pr_scan_end
.Lh2pr_suffix:
    mov x9, #-1             // start = -1 → bytes=-N
.Lh2pr_scan_end:
    // ── the end: digits after '-', up to the value end / CR / LF ──
    add x8, x8, #1          // cursor past '-'
    mov x4, #0              // end digit count
.Lh2pr_end_digits:
    cmp x8, x7
    b.ge .Lh2pr_end_done
    ldrb w5, [x6, x8]
    cmp w5, #'\r'
    b.eq .Lh2pr_end_done
    cmp w5, #'\n'
    b.eq .Lh2pr_end_done
    cmp w5, #'0'
    b.lo .Lh2pr_no_range
    cmp w5, #'9'
    b.hi .Lh2pr_no_range
    add x4, x4, #1
    cmp x4, #19
    b.ge .Lh2pr_no_range
    add x8, x8, #1
    b .Lh2pr_end_digits
.Lh2pr_end_done:
    // empty end is an open-ended range
    cbz x4, .Lh2pr_open
    mov x0, x6
    add x0, x0, x8
    sub x0, x0, x4          // pointer to the end digits
    mov x1, x4
    bl atoi_n
    b.cs .Lh2pr_no_range
    mov x10, x0             // end
    b .Lh2pr_check
.Lh2pr_open:
    mov x10, #-1            // end = -1 → bytes=N-
.Lh2pr_check:
    // "bytes=-" (both -1) is invalid
    cmn x9, #1
    b.ne 1f
    cmn x10, #1
    b.eq .Lh2pr_no_range
1:
    // a concrete end below the start is invalid
    cmn x9, #1
    b.eq 2f
    cmn x10, #1
    b.eq 2f
    cmp x9, x10
    b.gt .Lh2pr_no_range
2:
    mov x0, x9
    mov x1, x10
    ldr x30, [sp], #16
    cmn xzr, xzr            // success — carry clear
    ret
.Lh2pr_no_range:
    ldr x30, [sp], #16
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    mov x1, #0
    ret

// ── 10.5 — h2_resolve_range: resolve a range against a resource size ─
// Mirror of get.S's range-resolution logic: given a parsed (start, end)
// pair and the resource size, decide the response. Returns the resolved
// inclusive window and the status to send — 206 with the window, 200 to
// ignore the range (serve the whole file), or 416 when no part of the
// file lies in the range.
//
// input
// x0 = range start (-1 = suffix range)
// x1 = range end   (-1 = open-ended)
// x2 = resource size
//
// output
// x0 = resolved start, x1 = resolved end, x2 = status (200/206/416)
//
// clobbers x0-x5
h2_resolve_range:
    cmn x0, #1
    b.ne 1f
    // ── suffix range — bytes=-N ──
    cbz x1, .Lh2rr_416       // bytes=-0 is unsatisfiable
    cbz x2, .Lh2rr_200       // empty file — serve the whole (empty) file
    cmp x1, x2
    b.lo 2f
    // N >= size — the whole file is the last N bytes
    mov x0, #0
    sub x1, x2, #1
    b .Lh2rr_206
2:
    // start = size - N, end = size - 1 (inclusive)
    sub x0, x2, x1
    sub x1, x2, #1
    b .Lh2rr_206
1:
    // ── non-suffix range ──
    cbz x2, .Lh2rr_416       // an empty file has no satisfiable range
    cmp x0, x2
    b.hs .Lh2rr_416          // start at or beyond the end of the file
    cmn x1, #1
    b.ne 3f
    sub x1, x2, #1           // open-ended — end = size - 1
    b .Lh2rr_206
3:
    // both concrete — clamp the end to size - 1
    sub x3, x2, #1
    cmp x1, x3
    csel x1, x3, x1, hi
    b .Lh2rr_206
.Lh2rr_416:
    mov x0, #-1
    mov x1, #-1
    mov x2, #416
    ret
.Lh2rr_200:
    mov x0, #-1
    mov x1, #-1
    mov x2, #200
    ret
.Lh2rr_206:
    mov x2, #206
    ret

// ── 9 — h2_reply_status: a headers-only HTTP/2 status response ─────
// Mirrors reply_status's fallback path: with no embedded error pages in
// the current build, the body is empty. create_response → h2_write_headers
// with END_STREAM, so the stream ends on the HEADERS frame. When error
// pages are embedded, this can serve them like reply_status does.
//
// input
// x0 = status code, x1 = client fd, x2 = stream id
//
// output
// (none — write failures are ignored; the caller closes the stream)
//
// clobbers x0-x6, x9-x14, x19-x22 (saved/restored), x30
h2_reply_status:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    str x30, [sp, #32]
    mov x19, x0             // status
    mov x20, x1             // fd
    mov x21, x2             // stream id
    str_l x0, response_code
    str_l xzr, resource_type
    adr_l x0, response
    mov x1, x19
    mov x2, #0              // content_length
    mov x3, #-1             // range start
    mov x4, #-1             // range end
    mov x5, #0              // body ptr
    mov x6, #0              // body length
    bl create_response
    mov x0, x20
    adr_l x1, response
    mov x2, x21
    mov x3, #H2_FLAG_END_STREAM
    bl h2_write_headers
    ldr x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret

// ── 9.2 — h2_write_headers: encode the response struct as a HEADERS ─
// frame. The HPACK block carries :status, content-type and
// content-length — plus content-range for a ranged (206) response and
// content-encoding: gzip when the embedded asset is gzipped (the
// HTTP/1 encoder sends the same headers). The block is built into
// h2_frame_buf right after the 9-byte frame header and the whole frame
// is written in one write_all, so a partial write can't split the frame.
//
// HPACK notes: :status 200 is a static-table index (0x88); any other
// status is a literal with the indexed name ":status" (static 8).
// content-type / content-length / content-range / content-encoding use
// the literal-with-indexed-name form (static 31 / 28 / 30 / 26) with a
// plain 7-bit-prefix string length. Status 204 carries no content-type
// or content-length, matching the HTTP/1 encoder.
//
// input
// x0 = client fd
// x1 -> response struct
// x2 = stream id
// x3 = extra frame flags (H2_FLAG_END_STREAM for a bodyless response)
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = errno (or H2_ERR_INTERNAL_ERROR if the
//           header block doesn't fit the frame buffer)
//
// clobbers x0-x8, x19-x24 (saved/restored), x30
h2_write_headers:
    stp x19, x20, [sp, #-64]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    str x30, [sp, #48]
    mov x19, x0             // fd
    mov x20, x1             // response
    mov x21, x2             // stream id
    mov x22, x3             // extra flags
    adr_l x24, h2_frame_buf
    add x24, x24, #H2_WIRE_HEADER_LEN  // block base
    mov x23, #0             // block length

    // ── :status ──
    ldr x0, [x20, #RESP_STATUS]
    cmp x0, #200
    b.ne 1f
    mov w3, #0x88           // indexed header field — :status: 200 (§6.1)
    strb w3, [x24, x23]
    add x23, x23, #1
    b 2f
1:  // any other status — literal with the indexed name ":status" (8)
    mov w3, #0x08
    strb w3, [x24, x23]
    add x23, x23, #1
    ldr x0, [x20, #RESP_STATUS]
    bl itoa                // x0 -> digits, x1 = length
    mov x2, x1
    mov x1, x0
    bl .Lh2wh_append_str
2:
    	// ── content-type / content-length (skipped for 204, like HTTP/1) ──
    	ldr x0, [x20, #RESP_STATUS]
    	cmp x0, #204
    	b.eq .Lh2wh_encoding
    	// content-type — skipped for empty resources (matches HTTP/1). The
    	// static index is 31, which needs the two-octet 4-bit-prefix form:
    	// 0x0f (prefix max) then 31 - 15 = 16
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    	cbz x0, .Lh2wh_length
    	mov w3, #0x0f           // literal without indexing, 4-bit index max
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x10           // 31 - 15 = 16 → content-type
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	ldr x1, [x20, #RESP_CONTENT_TYPE]
    	ldr x2, [x20, #RESP_CONTENT_TYPE_LEN]
    	bl .Lh2wh_append_str
    .Lh2wh_length:
    	// content-length — static index 28: 0x0f then 28 - 15 = 13
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0d           // 28 - 15 = 13 → content-length
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	// the value is end - start + 1 for a ranged response, else the
    	// total resource length — mirroring the HTTP/1 encoder
    	ldr x0, [x20, #RESP_RANGE_START]
    	cmn x0, #1
    	b.eq .Lh2wh_cl_total
    	ldr x1, [x20, #RESP_RANGE_END]
    	sub x0, x1, x0
    	add x0, x0, #1
    	b .Lh2wh_cl_done
    .Lh2wh_cl_total:
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    .Lh2wh_cl_done:
    	bl itoa
    	mov x2, x1
    	mov x1, x0
    	bl .Lh2wh_append_str
    	// ── content-range — only for ranged (206) responses ──
    	// The name is static-table index 30, which needs the two-octet
    	// 4-bit-prefix form: 0x0f then 30 - 15 = 15
    	ldr x0, [x20, #RESP_RANGE_START]
    	cmn x0, #1
    	b.eq .Lh2wh_encoding
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0f           // 30 - 15 = 15 → content-range
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	// the value "start-end/total" is assembled in h2_cr_buf first so
    	// the HPACK string length prefix can be written before the data.
    	// x10 = value base, x11 = cursor — neither is clobbered by itoa
    	// (x0-x5), memcpy (x0-x4) or the ldr_l/str_l macros (x9)
    	adr_l x10, h2_cr_buf
    	mov x11, x10
    	ldr x0, [x20, #RESP_RANGE_START]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov w3, #'-'
    	strb w3, [x11]
    	add x11, x11, #1
    	ldr x0, [x20, #RESP_RANGE_END]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov w3, #'/'
    	strb w3, [x11]
    	add x11, x11, #1
    	ldr x0, [x20, #RESP_CONTENT_LENGTH]
    	bl itoa
    	mov x5, x1
    	mov x1, x0
    	mov x0, x11
    	mov x2, x5
    	bl memcpy
    	add x11, x11, x5
    	mov x1, x10
    	sub x2, x11, x10
    	bl .Lh2wh_append_str
    .Lh2wh_encoding:
    	// ── content-encoding: gzip — only for gzipped embedded assets. The
    	// static index is 26: 0x0f then 26 - 15 = 11
    	ldr_l x9, resource_type
    	cmp x9, #1              // RES_EMBEDDED
    	b.ne .Lh2wh_build_done
    	ldr_l x9, embedded_gzip
    	cbz x9, .Lh2wh_build_done
    	mov w3, #0x0f
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	mov w3, #0x0b           // 26 - 15 = 11 → content-encoding
    	strb w3, [x24, x23]
    	add x23, x23, #1
    	adr_l x1, h2_gzip_str
    	mov x2, #h2_gzip_str_len
    	bl .Lh2wh_append_str
.Lh2wh_build_done:
    // the fixed frame buffer must hold the block behind the 9-byte
    // header — the known content types are far below this
    cmp x23, #(h2_frame_buf_size - H2_WIRE_HEADER_LEN)
    b.hi .Lh2wh_too_big

    // ── frame header (RFC 9113 §4.1) ──
    adr_l x13, h2_frame_buf
    mov w3, w23             // payload length — 24-bit big-endian
    lsr w4, w3, #16
    strb w4, [x13, #0]
    lsr w4, w3, #8
    strb w4, [x13, #1]
    strb w3, [x13, #2]
    mov w3, #H2_FRAME_HEADERS
    strb w3, [x13, #3]
    mov w3, #H2_FLAG_END_HEADERS
    orr w3, w3, w22         // + END_STREAM when the caller asked for it
    strb w3, [x13, #4]
    mov w3, w21             // stream id — 31-bit big-endian
    lsr w4, w3, #24
    strb w4, [x13, #5]
    lsr w4, w3, #16
    strb w4, [x13, #6]
    lsr w4, w3, #8
    strb w4, [x13, #7]
    strb w3, [x13, #8]

    // ── one write — header + block can't be split by a partial write ──
    mov x0, x19
    adr_l x1, h2_frame_buf
    mov x2, #H2_WIRE_HEADER_LEN
    add x2, x2, x23
    bl write_all
    b.cs .Lh2wh_err
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2wh_done
.Lh2wh_too_big:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_INTERNAL_ERROR
    b .Lh2wh_done
.Lh2wh_err:
    // x0 = errno, carry set (write_all failed)
.Lh2wh_done:
    ldr x30, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret

// Append the RFC 7541 §5.2 string representation of (x1, length x2) to
// the block at x24+x23, advancing x23. Handles the 7-bit-prefix long
// form, so content types longer than 127 bytes still encode correctly.
// The return address is saved on entry: the memcpy below clobbers x30,
// and this helper is entered via bl and must ret to its caller. Named
// labels only — numeric labels here would hijack the b.cond/b 1f,2f
// branches in h2_write_headers.
//
// clobbers x0-x5, x30 (saved/restored)
.Lh2wh_append_str:
    str x30, [sp, #-16]!
    cmp x2, #127
    b.hi .Lh2wh_str_long
    strb w2, [x24, x23]
    add x23, x23, #1
    b .Lh2wh_str_data
.Lh2wh_str_long:
    mov w3, #127
    strb w3, [x24, x23]
    add x23, x23, #1
    sub x3, x2, #127
.Lh2wh_str_long_loop:
    cmp x3, #128
    b.lo .Lh2wh_str_long_done
    and w4, w3, #0x7f
    orr w4, w4, #0x80       // continuation bit
    strb w4, [x24, x23]
    add x23, x23, #1
    lsr x3, x3, #7
    b .Lh2wh_str_long_loop
.Lh2wh_str_long_done:
    strb w3, [x24, x23]
    add x23, x23, #1
.Lh2wh_str_data:
    mov x0, x24
    add x0, x0, x23
    // x1 -> string, x2 = length — memcpy clobbers x0-x4 (and x30), so
    // save the length in x5 (untouched) across the copy
    mov x5, x2
    bl memcpy
    add x23, x23, x5
    ldr x30, [sp], #16
    ret

// ── 9.3 — h2_write_body: send the response body as DATA frames ─────
// The body is split into H2_DEFAULT_MAX_FRAME_SIZE (2^14) chunks; the
// last chunk carries END_STREAM. An empty body sends a single empty
// DATA frame with END_STREAM.
//
// Stage 11 — flow control (§5.2): every DATA chunk is bounded by
// min(connection window, stream window, remaining), and both windows
// are drained by the octets sent. When the body still has data but a
// window is exhausted, the writer blocks reading frames from the client
// and dispatching them — a WINDOW_UPDATE replenishes the credit and
// transmission resumes. This keeps the per-connection loop simple: the
// whole response is written inline, pausing only for the credit the
// peer hasn't granted yet.
//
// input
// x0 = client fd
// x1 -> response struct
// x2 = stream id
//
// output
// success — carry clear, x0 = 0
// failure — carry set, x0 = errno (or H2_ERR_* from a frame dispatched
//           while waiting for credit)
//
// clobbers x0-x8, x13, x19-x27 (saved/restored), x30
h2_write_body:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x30, [sp, #64]
    mov x19, x0             // fd
    mov x20, x1             // response
    mov x21, x2             // stream id
    ldr x22, [x20, #RESP_BODY]
    ldr x23, [x20, #RESP_BODY_LENGTH]
    adr_l x26, h2_conn
    mov x0, x21
    bl h2_stream_find
    mov x27, x0             // stream entry, or 0 (no stream-level credit)
.Lh2wb_loop:
    // this chunk = min(max frame size, connection window, stream window,
    //                  remaining) — §5.2
    mov x24, #H2_DEFAULT_MAX_FRAME_SIZE
    ldr x8, [x26, #H2C_WINDOW]
    cmp x24, x8
    csel x24, x8, x24, hi
    cbnz x27, .Lh2wb_have_stream
    b .Lh2wb_min_remaining
.Lh2wb_have_stream:
    ldr x8, [x27, #H2S_WINDOW]
    cmp x24, x8
    csel x24, x8, x24, hi
.Lh2wb_min_remaining:
    cmp x24, x23
    csel x24, x23, x24, hi
    // a zero chunk with body remaining means the windows are exhausted —
    // read frames (WINDOW_UPDATE) until credit opens up; a zero chunk
    // with an empty body is the terminal empty DATA frame, which carries
    // no octets and consumes no credit (§5.2)
    cbnz x24, .Lh2wb_send
    cbnz x23, .Lh2wb_wait
.Lh2wb_send:
    // END_STREAM rides on the final chunk
    mov w25, #0
    cmp x24, x23
    b.ne 1f
    mov w25, #H2_FLAG_END_STREAM
1:
    // frame header at h2_frame_buf
    adr_l x13, h2_frame_buf
    mov w3, w24
    lsr w4, w3, #16
    strb w4, [x13, #0]
    lsr w4, w3, #8
    strb w4, [x13, #1]
    strb w3, [x13, #2]
    mov w3, #H2_FRAME_DATA
    strb w3, [x13, #3]
    strb w25, [x13, #4]
    mov w3, w21
    lsr w4, w3, #24
    strb w4, [x13, #5]
    lsr w4, w3, #16
    strb w4, [x13, #6]
    lsr w4, w3, #8
    strb w4, [x13, #7]
    strb w3, [x13, #8]
    // copy the chunk behind the header (zero-copy DATA is a later stage)
    add x0, x13, #H2_WIRE_HEADER_LEN
    mov x1, x22
    mov x2, x24
    bl memcpy
    // one write per frame
    mov x0, x19
    adr_l x1, h2_frame_buf
    mov x2, #H2_WIRE_HEADER_LEN
    add x2, x2, x24
    bl write_all
    b.cs .Lh2wb_err
    // the DATA octets drain both windows (§5.2)
    ldr x8, [x26, #H2C_WINDOW]
    sub x8, x8, x24
    str x8, [x26, #H2C_WINDOW]
    cbnz x27, .Lh2wb_dec_stream
    b .Lh2wb_advance
.Lh2wb_dec_stream:
    ldr x8, [x27, #H2S_WINDOW]
    sub x8, x8, x24
    str x8, [x27, #H2S_WINDOW]
.Lh2wb_advance:
    add x22, x22, x24
    sub x23, x23, x24
    cbnz x23, .Lh2wb_loop
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    b .Lh2wb_done
.Lh2wb_wait:
    // ── out of credit, body remaining — read a frame and dispatch it ──
    // The 9-byte wire header lands at buf[0..8] and is parsed before the
    // payload read overwrites it; the payload (≤ H2C_MAX_RX_FRAME_SIZE)
    // fits buf. WINDOW_UPDATE replenishes the credit; anything else is
    // still dispatched normally (SETTINGS, PING, ...). A dispatch error
    // aborts the response.
    mov x0, x19
    adr_l x1, buf
    mov x2, #H2_WIRE_HEADER_LEN
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, buf
    adr_l x1, h2_frame_header
    bl h2_parse_frame_header
    adr_l x0, h2_frame_header
    mov x1, x26
    bl h2_validate_frame
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    ldr w8, [x0, #H2F_LENGTH]
    mov x0, x19
    adr_l x1, buf
    mov x2, x8
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    adr_l x1, buf
    mov x2, x26
    bl h2_dispatch_frame
    b.cs .Lh2wb_err
    b .Lh2wb_loop
.Lh2wb_err:
    // x0 = errno (or H2_ERR_*), carry set
.Lh2wb_done:
    ldp x27, x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret

// ── 6.8 — h2_send_goaway: send a GOAWAY frame and let the caller ───
// close the connection. Carries the connection's high-water stream id
// and the given error code (RFC 9113 §6.8).
//
// input
// x0 = fd, x1 = error code
//
// output
// (none — write failures are ignored; the connection is closing anyway)
//
// clobbers x0-x4, x9, x30 (saved/restored)
h2_send_goaway:
    str x30, [sp, #-16]!
    sub sp, sp, #32
    // payload length = 8
    mov w3, #8
    strb wzr, [sp, #0]
    strb wzr, [sp, #1]
    strb w3, [sp, #2]
    // type = GOAWAY, flags = 0, stream id = 0
    mov w3, #H2_FRAME_GOAWAY
    strb w3, [sp, #3]
    strb wzr, [sp, #4]
    strb wzr, [sp, #5]
    strb wzr, [sp, #6]
    strb wzr, [sp, #7]
    strb wzr, [sp, #8]
    // payload: last client-initiated stream id (4 bytes, big-endian)
    adr_l x9, h2_conn
    ldr w3, [x9, #H2C_LAST_STREAM_ID]
    lsr w4, w3, #24
    strb w4, [sp, #9]
    lsr w4, w3, #16
    strb w4, [sp, #10]
    lsr w4, w3, #8
    strb w4, [sp, #11]
    strb w3, [sp, #12]
    // payload: error code (4 bytes, big-endian)
    lsr w4, w1, #24
    strb w4, [sp, #13]
    lsr w4, w1, #16
    strb w4, [sp, #14]
    lsr w4, w1, #8
    strb w4, [sp, #15]
    strb w1, [sp, #16]
    mov x1, sp
    mov x2, #17
    bl write_all
    add sp, sp, #32
    ldr x30, [sp], #16
    ret

// ── 6.4 — h2_send_rst_stream: send an RST_STREAM frame for a stream ─
// error, so the connection can keep serving other streams.
//
// input
// x0 = fd, x1 = stream id, x2 = error code
//
// output
// (none — write failures are ignored)
//
// clobbers x0-x4, x30 (saved/restored)
h2_send_rst_stream:
    str x30, [sp, #-16]!
    sub sp, sp, #32
    // payload length = 4
    mov w3, #4
    strb wzr, [sp, #0]
    strb wzr, [sp, #1]
    strb w3, [sp, #2]
    // type = RST_STREAM, flags = 0
    mov w3, #H2_FRAME_RST_STREAM
    strb w3, [sp, #3]
    strb wzr, [sp, #4]
    // stream id (4 bytes, big-endian)
    lsr w4, w1, #24
    strb w4, [sp, #5]
    lsr w4, w1, #16
    strb w4, [sp, #6]
    lsr w4, w1, #8
    strb w4, [sp, #7]
    strb w1, [sp, #8]
    // error code (4 bytes, big-endian)
    lsr w4, w2, #24
    strb w4, [sp, #9]
    lsr w4, w2, #16
    strb w4, [sp, #10]
    lsr w4, w2, #8
    strb w4, [sp, #11]
    strb w2, [sp, #12]
    mov x1, sp
    mov x2, #13
    bl write_all
    add sp, sp, #32
    ldr x30, [sp], #16
    ret
