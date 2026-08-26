#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_write_body
//
// Description: Send the response body as DATA frames. The body is split
//   into H2_DEFAULT_MAX_FRAME_SIZE (2^14) chunks; the last chunk
//   carries END_STREAM. An empty body sends a single empty DATA frame
//   with END_STREAM.
//
// Staged HEADERS (x3): when the caller used h2_stage_headers instead of
//   h2_write_headers, the encoded HEADERS frame is still sitting at the
//   front of h2_frame_buf and x3 is its length. The first DATA frame
//   header is then built *behind* it, and the one writev sends HEADERS +
//   DATA header + body chunk together — the whole response in a single
//   write syscall rather than two. x3 = 0 is the old behaviour and the
//   only thing every other caller has to pass.
//
//   The staged bytes must reach the wire before anything else touches
//   h2_frame_buf, so the wait-for-credit path below flushes them first:
//   it dispatches client frames, and a nested request would re-encode
//   into the same buffer. After the first chunk goes out the staged
//   length is cleared, so later chunks build their header at offset 0.
//
// Stage 11 — flow control (§5.2): every DATA chunk is bounded by
//   min(connection window, stream window, remaining), and both windows
//   are drained by the octets sent. When the body still has data but a
//   window is exhausted, the writer blocks reading frames from the
//   client and dispatching them — a WINDOW_UPDATE replenishes the
//   credit and transmission resumes. This keeps the per-connection loop
//   simple: the whole response is written inline, pausing only for the
//   credit the peer hasn't granted yet.
//
//   A frame dispatched while waiting can itself complete a request — a
//   browser's parallel page-load requests arrive exactly that way, behind
//   a large response — so the wait loop carries the connection loop's
//   request-processing hook and serves it right there, recursively.
//
//   Frames read while waiting land in h2_wait_buf, never in `buf`: the
//   connection loop parks bytes it has read but not yet parsed in `buf`,
//   and overwriting them desynchronises the connection as soon as this
//   response finishes. See src/h2/data.S for the reproducer.
//
// Input/Arguments:
//   x0 — client fd
//   x1 — response struct
//   x2 — stream id
//   x3 — bytes of a staged HEADERS frame at the front of h2_frame_buf to
//        send ahead of the first DATA frame, or 0 for none
//   x4 — the stream's table entry, or 0 if it has none (no stream-level
//     credit applies). The caller has it: h2_process_request was handed
//     it in turn by whichever dispatch site decided this stream was ready
//     to serve, so the lookup this used to do here was the fifth of six
//     h2_stream_find calls per request that all returned the same
//     pointer. Holding the entry across the write loop is not new — x27
//     did that before and still does, including across the flow-control
//     wait's re-entrant dispatch; only the lookup moved.
//
// Output/Returns:
//   x0 — 0 on success (carry clear); errno on failure (carry set), or
//     H2_ERR_* from a frame dispatched while waiting for credit
//
// Clobbered Registers:
//   x0-x13, x16, x19-x27 (saved/restored)
//
// Stack Usage:
//   96 bytes: stp x19, x20, [sp, #-96]!; ...; stp x27, x30, [sp, #64]
//   ([sp, #80] holds x27 across the nested h2_process_request call;
//   [sp, #88] holds the staged HEADERS length, which the send path
//   clears once those bytes are on the wire)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_write_body
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x30, [sp, #64]
    mov x19, x0             // fd
    mov x20, x1             // response
    mov x21, x2             // stream id
    mov x27, x4             // stream entry, or 0 (no stream-level credit)
    str x3, [sp, #88]       // staged HEADERS bytes at h2_frame_buf[0]
    ldr x22, [x20, #RESP_BODY]
    ldr x23, [x20, #RESP_BODY_LENGTH]
    adr_l x26, h2_conn
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
    // a stream window can be negative — §6.9.2 shifts it by the change in
    // SETTINGS_INITIAL_WINDOW_SIZE, which can land below zero when octets
    // are already in flight. That is no credit at all, not a huge amount.
    ldr x8, [x27, #H2S_WINDOW]
    cmp x8, #0
    csel x8, xzr, x8, lt
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
    // frame header at h2_frame_buf, behind any staged HEADERS frame
    ldr x12, [sp, #88]      // staged HEADERS length (0 when none)
    adr_l x13, h2_frame_buf
    add x13, x13, x12
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
    // header + body chunk in one real writev, no copy of the chunk
    // itself (Plan.md Phase 2, Step 11 — zero-copy DATA): the chunk
    // already lives in the response body, so there's nothing to gain by
    // copying it next to the header first, the way http1_write_response
    // already avoids copying the body for HTTP/1.
    // x12 (staged HEADERS length) is still live from the frame header
    // above — adr_l only writes its destination register, and nothing
    // between here and the call touches x12.
    mov x0, x19
    adr_l x1, h2_frame_buf
    add x2, x12, #H2_WIRE_HEADER_LEN
    mov x3, x22
    mov x4, x24
    bl transport_writev
    b.cs .Lh2wb_err
    str xzr, [sp, #88]      // staged HEADERS are on the wire now
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
    // Flush any staged HEADERS first. Everything below re-encodes into
    // h2_frame_buf (and a nested h2_process_request encodes a whole
    // response into it), so bytes still staged here would be destroyed —
    // and the peer needs our HEADERS anyway before it can sensibly
    // decide to grant more credit.
    ldr x12, [sp, #88]
    cbz x12, .Lh2wb_wait_read
    mov x0, x19
    adr_l x1, h2_frame_buf
    mov x2, x12
    bl write_all
    b.cs .Lh2wb_err
    str xzr, [sp, #88]
.Lh2wb_wait_read:
    // The 9-byte wire header lands at h2_wait_buf[0..8] and is parsed
    // before the payload read overwrites it; the payload (≤
    // H2C_MAX_RX_FRAME_SIZE) fits h2_wait_buf. WINDOW_UPDATE replenishes
    // the credit; anything else is still dispatched normally (SETTINGS,
    // PING, ...). A dispatch error aborts the response.
    //
    // h2_wait_buf, not `buf`: the connection loop holds bytes it has read
    // but not yet parsed in `buf`, and reading over them desynchronises
    // the connection once this response finishes — see src/h2/data.S.
    // Nesting is safe on one buffer: after the dispatch and the request
    // hook below, this frame is finished with, and .Lh2wb_loop reads a
    // fresh one, so nothing of ours is live across the recursion.
    mov x0, x19
    adr_l x1, h2_wait_buf
    mov x2, #H2_WIRE_HEADER_LEN
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, h2_wait_buf
    adr_l x1, h2_frame_header
    bl h2_parse_frame_header
    adr_l x0, h2_frame_header
    mov x1, x26
    bl h2_validate_frame
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    ldr w8, [x0, #H2F_LENGTH]
    mov x0, x19
    adr_l x1, h2_wait_buf
    mov x2, x8
    bl h2_read_exact
    b.cs .Lh2wb_err
    adr_l x0, h2_frame_header
    adr_l x1, h2_wait_buf
    mov x2, x26
    bl h2_dispatch_frame
    b.cs .Lh2wb_dispatch_error
    // ── request processing hook ──
    // The connection loop's hook can't see the frames we dispatch here,
    // so a HEADERS block that completed a request while we waited for
    // credit would sit decoded and unanswered until the connection timed
    // out — a browser's parallel page-load requests arrive exactly this
    // way, behind a large response. Serving it here also has to happen
    // *now* rather than being deferred: the decoded request lives in the
    // singleton `request` struct and its shared buffers, so the next
    // HEADERS block overwrites it.
    //
    // The resulting recursion (process_request → write_body → wait →
    // process_request) is bounded by the stream table — h2_stream_create
    // refuses a new stream once all H2_MAX_STREAMS entries are live — and
    // cannot re-enter a stream already being served, which is what
    // H2S_FLAG_SERVING guards: our own stream, and every stream further
    // out in the recursion, is still HALF_CLOSED_REMOTE right now.
    adr_l x0, h2_frame_header
    ldr w0, [x0, #H2F_STREAM_ID]
    cbz w0, .Lh2wb_loop
    bl h2_stream_find
    cbz x0, .Lh2wb_loop
    ldr x1, [x0, #H2S_STATE]
    cmp x1, #H2_STREAM_HALF_CLOSED_REMOTE
    b.ne .Lh2wb_loop
    ldr x1, [x0, #H2S_FLAGS]
    tst x1, #H2S_FLAG_SERVING
    b.ne .Lh2wb_loop
    mov x2, x0              // the entry we just found — process_request
                            // used to look this same stream up again
    adr_l x0, h2_frame_header
    ldr w0, [x0, #H2F_STREAM_ID]
    mov x1, x19
    str x27, [sp, #80]      // h2_process_request preserves only x19-x26
    bl h2_process_request
    ldr x27, [sp, #80]
    b .Lh2wb_loop
.Lh2wb_dispatch_error:
    // stream errors (STREAM_CLOSED, and the REFUSED_STREAM a HEADERS
    // after GOAWAY answers with) — RST_STREAM that stream and keep
    // waiting for credit; anything else poisons the connection and
    // aborts the response
    cmp x0, #H2_ERR_STREAM_CLOSED
    b.eq .Lh2wb_rst_stream
    cmp x0, #H2_ERR_REFUSED_STREAM
    b.eq .Lh2wb_rst_stream
    b .Lh2wb_err
.Lh2wb_rst_stream:
    adr_l x9, h2_frame_header
    ldr w1, [x9, #H2F_STREAM_ID]
    cbz w1, .Lh2wb_loop       // stream 0 is never RST_STREAM'd — keep waiting
    mov x2, x0
    mov x0, x19
    bl h2_send_rst_stream
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
ENDFUNC h2_write_body
