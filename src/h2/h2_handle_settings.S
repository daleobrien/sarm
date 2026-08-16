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
//   - a new SETTINGS_INITIAL_WINDOW_SIZE applies retroactively: the send
//     window of every stream still in the table shifts by the difference
//     (§6.9.2), not just that of streams opened afterwards
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
    mov w9, w7             // zero-extend — the field is 8 bytes wide
    str x9, [x2, #H2C_SETTINGS_HEADER_TABLE_SIZE]
    b .Lh2_settings_next

.Lh2_st_enable_push:
    mov w9, w7             // zero-extend — the field is 8 bytes wide
    str x9, [x2, #H2C_SETTINGS_ENABLE_PUSH]
    b .Lh2_settings_next

.Lh2_st_max_concurrent_streams:
    mov w9, w7             // zero-extend — the field is 8 bytes wide
    str x9, [x2, #H2C_SETTINGS_MAX_CONCURRENT_STREAMS]
    b .Lh2_settings_next

.Lh2_st_initial_window_size:
    // §6.5.2 — a value above 2^31-1 is a FLOW_CONTROL_ERROR
    tbnz w7, #31, .Lh2_settings_flow_control_error
    mov w9, w7                                       // new value, zero-extended
    ldr x8, [x2, #H2C_SETTINGS_INITIAL_WINDOW_SIZE]  // value it replaces
    str x9, [x2, #H2C_SETTINGS_INITIAL_WINDOW_SIZE]
    // §6.9.2 — the change is retroactive: every stream the connection is
    // still tracking has its send window shifted by the difference, not
    // just streams opened from here on. The shift can drive a window
    // negative (a reduced setting, with octets already in flight), which
    // is legal — the stream simply sends nothing until WINDOW_UPDATEs
    // bring it back above zero.
    subs x8, x9, x8            // delta — signed
    b.eq .Lh2_settings_next
    adr_l x10, h2_streams
    mov x5, #H2_MAX_STREAMS
.Lh2_st_iws_loop:
    ldr x9, [x10, #H2S_STREAM_ID]
    cbz x9, .Lh2_st_iws_next        // free slot
    ldr x9, [x10, #H2S_STATE]
    cmp x9, #H2_STREAM_CLOSED
    b.eq .Lh2_st_iws_next           // finished — no window left to resize
    ldr x9, [x10, #H2S_WINDOW]
    add x9, x9, x8
    mov x3, #H2_MAX_FLOW_WINDOW
    cmp x9, x3                      // signed — a shifted window may be < 0
    b.gt .Lh2_settings_flow_control_error
    str x9, [x10, #H2S_WINDOW]
.Lh2_st_iws_next:
    add x10, x10, #H2S_SIZE
    subs x5, x5, #1
    b.ne .Lh2_st_iws_loop
    b .Lh2_settings_next

.Lh2_st_max_frame_size:
    // §6.5.2 — must be within [2^14, 2^24-1], inclusive
    cmp w7, #H2_DEFAULT_MAX_FRAME_SIZE
    b.lo .Lh2_settings_protocol_error
    mov w8, #H2_MAX_FRAME_SIZE
    cmp w7, w8
    b.hi .Lh2_settings_protocol_error
    mov w9, w7             // zero-extend — the field is 8 bytes wide
    str x9, [x2, #H2C_SETTINGS_MAX_FRAME_SIZE]
    b .Lh2_settings_next

.Lh2_st_max_header_list_size:
    mov w9, w7             // zero-extend — the field is 8 bytes wide
    str x9, [x2, #H2C_SETTINGS_MAX_HEADER_LIST_SIZE]
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
