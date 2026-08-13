#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_settings
//
// Description: Handle a SETTINGS frame (RFC 9113 §6.5):
//   - SETTINGS is connection-scoped: a stream id other than 0 is a
//     PROTOCOL_ERROR
//   - a non-ACK payload is a list of 6-byte entries; unknown
//     identifiers are ignored (§6.5.2); a length that is not a whole
//     number of entries is a FRAME_SIZE_ERROR
//   - a SETTINGS with the ACK flag must have an empty payload, else
//     FRAME_SIZE_ERROR (§6.5)
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
//   x3, x4, x5, x6, x7, x8, x9, x10
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_handle_settings
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
