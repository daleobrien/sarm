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
OBJECT h2_conn
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
ENDOBJ h2_conn

.bss
.align 4
// h2_frame_header — scratch for the parsed frame header. The connection
// loop parses the 9 wire bytes into this before validating/dispatching.
OBJECT h2_frame_header
    .skip H2F_SIZE
ENDOBJ h2_frame_header

// h2_streams — the fixed stream table (§5.1). H2_MAX_STREAMS entries of
// H2S_SIZE bytes; a zero stream_id marks a free slot (wire ids are
// never zero). Zeroed at startup. Entries are reused: h2_stream_create
// takes a free slot first, then — Stage 12 — recycles a CLOSED entry so
// a long-lived connection can serve more than H2_MAX_STREAMS requests.
.align 4
OBJECT h2_streams
    .skip H2_MAX_STREAMS * H2S_SIZE
ENDOBJ h2_streams

// h2_stream_ids — a packed lookup index over h2_streams: entry i's stream
// id, as a u32, at h2_stream_ids + i*4. Slot i here and entry i there are
// the same stream; a zero means the same free slot it means in the table.
//
// It exists because looking a stream up is the hottest thing the HTTP/2
// path does and the table is the wrong shape for it. h2_stream_find and
// h2_stream_create only ever compare the *id*, but an entry is H2S_SIZE
// (32) bytes, so scanning ids in place strides across 16 cache lines to
// read 32 useful quadwords — and on an h2c profile that scan was the top
// two functions in the whole server (3.86% + 2.92% of cycles), nearly all
// of it stalled on those loads rather than doing work. Packed as u32 the
// same 32 ids are 128 bytes: two cache lines, one stride, and no entry
// touched until a match is known.
//
// Wire ids are 31-bit (RFC 9113 §5.1.1, masked in h2_parse_frame_header),
// so u32 holds every legal id with the top bit to spare.
//
// The duplication is the cost. Exactly two places write a stream id —
// h2_stream_create's initialisation and h2_connection_loop's per-connection
// reset — and both must write here too or a stream becomes invisible to
// every later lookup. tests/unit/test_h2_streams.c asserts the two stay in
// step; keep it that way if a third writer ever appears.
.align 6                                  // 64 B — exactly two cache lines
OBJECT h2_stream_ids
    .skip H2_MAX_STREAMS * 4
ENDOBJ h2_stream_ids

// h2_frame_buf — one outgoing frame: a 9-byte frame header followed by
// its payload (an HPACK header block or a DATA chunk). The response
// encoders build the whole frame here and write it in one write_all, so
// a partial write can't split a frame. Sized for the largest accepted
// frame (h2_validate_frame caps payloads at H2C_MAX_RX_FRAME_SIZE).
// h2_frame_buf_size is defined in defs.S (needed as an immediate by
// h2_write_headers too).
.align 4
OBJECT h2_frame_buf
    .skip h2_frame_buf_size
ENDOBJ h2_frame_buf

// h2_wait_buf — one *incoming* frame, for h2_write_body's flow-control
// wait loop only. It cannot share `buf` with the connection loop: a
// single read can deliver several frames, so h2_connection_loop routinely
// holds bytes it has read but not yet parsed in `buf`, tracked by a
// cursor and a count held in callee-saved registers across
// h2_process_request. A wait loop reading into `buf` overwrites exactly
// those bytes, and the connection loop then parses whatever landed there
// as its next frame header — a desynchronised connection, not a lost
// request. Reproduced over h2c by sending the preface, SETTINGS and two
// HEADERS in one segment, the first for a body larger than the 65535-byte
// connection window: serving it enters the wait loop, and the second
// request is destroyed where it sits. Latent over TLS only because the
// unparsed bytes live in the TLS stage buffer there instead.
.align 4
OBJECT h2_wait_buf
    .skip h2_wait_buf_size
ENDOBJ h2_wait_buf

