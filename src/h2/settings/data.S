#include "../../defs.S"

// h2_settings_frame — the server's opening SETTINGS frame (RFC 9113
// §3.5, §6.5): SETTINGS_HEADER_TABLE_SIZE = H2_HPACK_HEADER_TABLE_SIZE
// (4096, the RFC 9113 §6.5.2 protocol default — see hpack/dynamic_table/
// for why this must match the default a client's encoder already
// assumes before it has processed our SETTINGS, not some smaller value
// we'd prefer), and (Stage 12) SETTINGS_MAX_CONCURRENT_STREAMS = 32
// advertises how many concurrent streams this endpoint permits (§5.1.2).

.data
.align 4
.global h2_settings_frame
h2_settings_frame:
    .byte 0x00, 0x00, 0x0c            // payload length (24-bit) = 12
    .byte H2_FRAME_SETTINGS           // type = SETTINGS
    .byte 0x00                        // flags = 0
    .byte 0x00, 0x00, 0x00, 0x00      // stream id = 0
    .byte 0x00, H2_SETTINGS_HEADER_TABLE_SIZE // identifier (16-bit BE)
    .byte (H2_HPACK_HEADER_TABLE_SIZE >> 24) & 0xff
    .byte (H2_HPACK_HEADER_TABLE_SIZE >> 16) & 0xff
    .byte (H2_HPACK_HEADER_TABLE_SIZE >> 8) & 0xff
    .byte H2_HPACK_HEADER_TABLE_SIZE & 0xff  // value = 4096
    .byte 0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS
    .byte 0x00, 0x00, 0x00, MAX_CONCURRENT_STREAMS  // value = 32
.equ h2_settings_frame_len, . - h2_settings_frame
    .align 4 // pad the 21-byte frame to a 16-byte multiple
