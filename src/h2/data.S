#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared HTTP/2 frame-engine state
//
// Description: Global state shared across the h2 functions. The frame
//   constants (h2_settings_frame), dispatch table (h2_frame_handlers),
//   stream transition table (h2_stream_transitions) and pseudo-header /
//   method strings live in the function files that consume them.
//   h2_frame_buf_size is defined in defs.S (it is needed as an
//   immediate by h2_write_headers).
//
// Exported Symbols:
//   h2_conn        — per-connection state (RFC 9113 §6.5.2 defaults)
//   h2_frame_header — scratch for the parsed 9-byte frame header
//   h2_streams     — the fixed stream table (§5.1)
//   h2_frame_buf   — one outgoing frame (header + payload)
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
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
    .quad -1                              // H2C_FD — no connection yet (Stage 13)
    .quad 0                               // H2C_GOAWAY_RECEIVED (Stage 13)
    .quad 0                               // H2C_GOAWAY_LAST_STREAM_ID (Stage 13)

.bss
.align 4
// h2_frame_header — scratch for the parsed frame header. The connection
// loop parses the 9 wire bytes into this before validating/dispatching.
h2_frame_header:
    .skip H2F_SIZE

// h2_streams — the fixed stream table (§5.1). H2_MAX_STREAMS entries of
// H2S_SIZE bytes; a zero stream_id marks a free slot (wire ids are
// never zero). Zeroed at startup. Entries are reused: h2_stream_create
// takes a free slot first, then — Stage 12 — recycles a CLOSED entry so
// a long-lived connection can serve more than H2_MAX_STREAMS requests.
.align 4
h2_streams:
    .skip H2_MAX_STREAMS * H2S_SIZE

// h2_frame_buf — one outgoing frame: a 9-byte frame header followed by
// its payload (an HPACK header block or a DATA chunk). The response
// encoders build the whole frame here and write it in one write_all, so
// a partial write can't split a frame. Sized for the largest accepted
// frame (h2_validate_frame caps payloads at H2C_MAX_RX_FRAME_SIZE).
// h2_frame_buf_size is defined in defs.S (needed as an immediate by
// h2_write_headers too).
.align 4
h2_frame_buf:
    .skip h2_frame_buf_size

.global h2_conn
.global h2_frame_header
.global h2_streams
.global h2_frame_buf
