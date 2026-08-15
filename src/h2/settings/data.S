#include "../../defs.S"

// h2_settings_frame — the server's opening SETTINGS frame (RFC 9113
// §3.5, §6.5): SETTINGS_HEADER_TABLE_SIZE = 0 (§6.5.2) tells the client
// its HPACK encoder may not use a dynamic table, and (Stage 12)
// SETTINGS_MAX_CONCURRENT_STREAMS = 32 advertises how many concurrent
// streams this endpoint permits (§5.1.2). Our decoder is
// static-table-only (hpack module) and rejects any dynamic-table
// representation, so advertising the table-size limit up front lets
// conforming clients avoid the COMPRESSION_ERROR entirely.

.data
.align 4
.global h2_settings_frame
h2_settings_frame:
    .byte 0x00, 0x00, 0x0c            // payload length (24-bit) = 12
    .byte H2_FRAME_SETTINGS           // type = SETTINGS
    .byte 0x00                        // flags = 0
    .byte 0x00, 0x00, 0x00, 0x00      // stream id = 0
    .byte 0x00, H2_SETTINGS_HEADER_TABLE_SIZE // identifier (16-bit BE)
    .byte 0x00, 0x00, 0x00, 0x00      // value = 0 — dynamic table disabled
    .byte 0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS
    .byte 0x00, 0x00, 0x00, MAX_CONCURRENT_STREAMS  // value = 32
.equ h2_settings_frame_len, . - h2_settings_frame
    .align 4 // pad the 21-byte frame to a 16-byte multiple
