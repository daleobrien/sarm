#include "../defs.S"

.extern h2_hpack_dyn_reset

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_connection_loop
//
// Description: The per-connection lifecycle for an HTTP/2 client (RFC
//   9113 §3.4-3.5): finish verifying the client connection preface
//   against the bytes already buffered (reading more if needed), send
//   our opening SETTINGS frame, then loop over frames — read a complete
//   frame, dispatch it, and serve any stream whose request became
//   complete (HALF_CLOSED_REMOTE) through h2_process_request.
//   Connection errors send GOAWAY; STREAM_CLOSED stream errors send
//   RST_STREAM; a timeout or EOF closes the connection.
//
// Input/Arguments:
//   x0 — client fd
//   x1 — buffer holding the first `n` bytes (a prefix of the preface)
//   x2 — n
//
// Output/Returns:
//   (none — returns when the connection ends; the caller closes the fd)
//
// Clobbered Registers:
//   x0-x8, x19-x23 (saved/restored), x30
//
// Stack Usage:
//   64 bytes: stp x19, x20, [sp, #-64]!; stp x21, x22, [sp, #16];
//   stp x23, x30, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_connection_loop
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
    // Stage 13 — the fd the PING ACK / GOAWAY reply writers use, and a
    // clean going-away state (a new connection is not going away)
    str x19, [x9, #H2C_FD]
    str xzr, [x9, #H2C_GOAWAY_RECEIVED]
    str xzr, [x9, #H2C_GOAWAY_LAST_STREAM_ID]
    adr_l x9, h2_streams
    mov x10, #(H2_MAX_STREAMS * H2S_SIZE) / 16
1:
    stp xzr, xzr, [x9], #16
    subs x10, x10, #1
    b.ne 1b
    // the HPACK dynamic table is also per-connection state — a previous
    // connection's entries must not leak into this one's decode
    bl h2_hpack_dyn_reset

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
    // A stream whose request is complete (HALF_CLOSED_REMOTE, and not
    // already mid-response — H2S_FLAG_SERVING) is served immediately
    // through the common request → resource handler. h2_process_request
    // moves it to CLOSED once the response is on the wire.
    //
    // "Immediately" is load-bearing, not just tidy: the decoded request
    // lives in the singleton `request` struct and the shared path /
    // authority / range buffers h2_build_request fills, so the next
    // HEADERS block overwrites it. A request that is not served before
    // the following one decodes cannot be recovered. h2_write_body's
    // flow-control wait loop dispatches frames too, and carries the same
    // hook for exactly this reason.
    adr_l x0, h2_frame_header
    ldr w0, [x0, #H2F_STREAM_ID]
    cbz w0, .Lh2cl_frame_loop
    bl h2_stream_find
    cbz x0, .Lh2cl_frame_loop
    ldr x1, [x0, #H2S_STATE]
    cmp x1, #H2_STREAM_HALF_CLOSED_REMOTE
    b.ne .Lh2cl_frame_loop
    ldr x1, [x0, #H2S_FLAGS]
    tst x1, #H2S_FLAG_SERVING
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
    // STREAM_CLOSED and REFUSED_STREAM are stream errors — RST_STREAM
    // that stream and keep serving; anything else poisons the
    // connection — GOAWAY and close (REFUSED_STREAM is how the HEADERS
    // handler answers a brand-new stream after GOAWAY, §6.8)
    cmp x0, #H2_ERR_STREAM_CLOSED
    b.eq .Lh2cl_rst_stream
    cmp x0, #H2_ERR_REFUSED_STREAM
    b.eq .Lh2cl_rst_stream
    mov x1, x0
    mov x0, x19
    adr_l x2, h2_conn
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
    adr_l x2, h2_conn
    bl h2_send_goaway
    b .Lh2cl_end

.Lh2cl_end:
    ldp x23, x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #64
    ret
