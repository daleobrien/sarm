#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_parse_frame_header
//
// Description: Decode a 9-byte wire frame header (RFC 9113 §4.1) into
//   the h2_frame_header struct: 24-bit payload length, 8-bit type,
//   8-bit flags and 31-bit stream id (the reserved bit is masked off).
//
// Input/Arguments:
//   x0 — 9-byte wire frame header
//   x1 — parsed frame header struct (H2F_SIZE bytes)
//
// Output/Returns:
//   (none — the struct is filled; always succeeds given 9 bytes)
//
// Clobbered Registers:
//   x2, x3, x4, x5
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_parse_frame_header
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
