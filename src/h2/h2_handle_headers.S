#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_handle_headers
//
// Description: Open or update the stream named by the frame. A HEADERS
//   frame is the only thing that may open a new client stream (§5.1):
//   the id must pass h2_validate_stream_id, the stream is created in
//   IDLE and moved to OPEN, and the END_STREAM flag then moves it to
//   HALF_CLOSED_REMOTE. The frame's flags are recorded on the stream
//   entry (END_STREAM/END_HEADERS are extracted there), the
//   PADDED and PRIORITY fields are stripped off the front of the payload
//   (§6.2) so that what is left is the header block fragment alone; the
//   HPACK-encoded header block is decoded with h2_hpack_decode_block,
//   and the decoded fields are converted into the protocol-neutral
//   `request` struct by h2_build_request. An undecodable block is a
//   COMPRESSION_ERROR connection error (§4.3); a malformed request is a
//   PROTOCOL_ERROR stream error (§8.1.1). A HEADERS that opens a
//   brand-new stream beyond MAX_CONCURRENT_STREAMS (§5.1.2) is refused
//   with ENHANCE_YOUR_CALM — a connection error the loop answers with
//   GOAWAY; HEADERS on an existing stream (trailers) never counts again.
//
// NOTE: the dispatcher reaches us with br, so x30 is the return address
// of the dispatcher's caller — save it before our own bl calls.
//
// hdr/conn/payload live in x20-x22 (callee-saved), not the x10-x13
// caller-saved range: this function holds them across several nested
// bl calls, including into h2_hpack_decode_block, which loops over
// h2_hpack_decode_field — and that now calls into the HPACK dynamic
// table (h2_hpack_table_lookup / h2_hpack_dyn_insert / _resize), which
// uses x9-x16 as genuine scratch. A caller-saved register is never
// guaranteed to survive a call by any callee at any depth; only x19-x28
// carry that guarantee, which is why it has to be one of those.
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
//   x0-x12, x14-x16, v0-v5, v16-v18, x19-x22 (saved/restored),
//   x30 (saved/restored)
//
// Stack Usage:
//   48 bytes: stp x19, x20, [sp, #-48]!; stp x21, x22, [sp, #16];
//   str x30, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_handle_headers
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    str x30, [sp, #32]
    mov x20, x0              // hdr — saved across the validate/create calls
    mov x21, x2              // conn — saved across the validate/create calls
    mov x22, x1              // payload — reaches the HPACK decoder later
    ldr w13, [x0, #H2F_FLAGS]
    str x13, [sp, #40]       // frame flags — saved across the decode/build
    mov x1, x2              // validate's second argument is the conn
    bl h2_validate_stream_id
    b.cs .Lh2_headers_err
    // ── Stage 12 — enforce MAX_CONCURRENT_STREAMS (§5.1.2) ──
    // Only a brand-new stream consumes a slot: an existing stream keeps
    // its entry, so trailers are never counted twice. Open means OPEN or
    // HALF_CLOSED_* — IDLE and CLOSED streams don't count (§5.1.2).
    //
    // x0 is validate's lookup of this same id — it had to do it to apply
    // the §5.1.1 ordering rule, and nothing since could have changed the
    // table. A second h2_stream_find here was one of six per request.
    cbnz x0, .Lh2_headers_count_done
    // ── Stage 13 — GOAWAY received: no brand-new streams (§6.8) ──
    // The connection is winding down; a HEADERS that would open a stream
    // that doesn't exist yet is refused with REFUSED_STREAM (a stream
    // error the loop answers with RST_STREAM). Streams already in the
    // table — accepted before the GOAWAY — run to completion.
    ldr x14, [x21, #H2C_GOAWAY_RECEIVED]
    cbnz x14, .Lh2_headers_refused
    adr_l x9, h2_streams
    mov x13, #H2_MAX_STREAMS
    mov x14, #0             // open-stream count
1:
    ldr x15, [x9, #H2S_STATE]
    cbz x15, 2f             // IDLE doesn't count
    cmp x15, #H2_STREAM_CLOSED
    b.eq 2f                 // CLOSED doesn't count
    add x14, x14, #1
2:
    add x9, x9, #H2S_SIZE
    subs x13, x13, #1
    b.ne 1b
    cmp x14, #MAX_CONCURRENT_STREAMS
    b.hs .Lh2_headers_too_many
.Lh2_headers_count_done:
    ldr w0, [x20, #H2F_STREAM_ID]
    mov x1, x21
    bl h2_stream_create
    b.cs .Lh2_headers_err
    mov x19, x0             // stream entry — survives the decode/build calls
    mov x1, #H2_EVENT_RECV_HEADERS
    bl h2_stream_event
    b.cs .Lh2_headers_err
    // record the frame's flags only once the transition is accepted — a
    // HEADERS frame the state machine rejects must not overwrite what the
    // entry already holds, which includes H2S_FLAG_SERVING
    ldr x13, [sp, #40]
    str x13, [x19, #H2S_FLAGS]  // extract END_STREAM / END_HEADERS / ...
    // ── §6.2 — the header block fragment is not the whole payload ──
    // Two optional fields sit in front of it, and both have to come off
    // before a single byte reaches HPACK. Chrome sets PRIORITY on its
    // request HEADERS, so its block starts five octets in; feeding those
    // five (80 00 00 00 ff — exclusive, dependency 0, weight 255) to the
    // decoder reads 0x80 as an indexed field with index 0, which is
    // exactly the "decoder error" HPACK reserves (RFC 7541 §6.1), and
    // the connection dies with GOAWAY(COMPRESSION_ERROR) on the very
    // first request. Safari sends neither field, which is why it never
    // showed this.
    //
    // The priority fields themselves are deprecated (§5.3) and carry no
    // meaning here — they are skipped, not parsed.
    mov x0, x22             // payload
    ldr w1, [x20, #H2F_LENGTH]  // bytes left in it
    ldr x13, [sp, #40]
    tst w13, #H2_FLAG_PADDED
    b.eq .Lh2_headers_no_pad
    cbz w1, .Lh2_headers_size_error  // no room for the Pad Length octet
    ldrb w14, [x0]                   // Pad Length
    add x0, x0, #1
    sub w1, w1, #1
    cmp w14, w1
    b.hi .Lh2_headers_protocol_error // padding runs past the payload (§6.1)
    sub w1, w1, w14
.Lh2_headers_no_pad:
    tst w13, #H2_FLAG_PRIORITY
    b.eq .Lh2_headers_block
    cmp w1, #H2_PRIORITY_FIELD_LEN
    b.lo .Lh2_headers_size_error
    add x0, x0, #H2_PRIORITY_FIELD_LEN  // stream dependency (4) + weight (1)
    sub w1, w1, #H2_PRIORITY_FIELD_LEN
.Lh2_headers_block:
    // the HPACK-encoded header block reaches the decoder here
    bl h2_hpack_decode_block
    b.cs .Lh2_headers_err   // x0 = COMPRESSION_ERROR (connection error)
    // convert the decoded fields into the common request
    mov x1, x0              // decoded field count
    ldr w0, [x20, #H2F_STREAM_ID]
    bl h2_build_request
    b.cs .Lh2_headers_err   // x0 = PROTOCOL_ERROR (stream error)
    // END_STREAM closes the client's send side → HALF_CLOSED_REMOTE
    ldr x13, [sp, #40]
    tst w13, #H2_FLAG_END_STREAM
    b.eq .Lh2_headers_ok
    mov x0, x19
    mov x1, #H2_EVENT_RECV_END_STREAM
    bl h2_stream_event
    b.cs .Lh2_headers_err
.Lh2_headers_ok:
    ldr x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    cmn xzr, xzr             // success — carry clear
    mov x0, #0
    ret
.Lh2_headers_size_error:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    b .Lh2_headers_err
.Lh2_headers_protocol_error:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    b .Lh2_headers_err
.Lh2_headers_too_many:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_ENHANCE_YOUR_CALM
    b .Lh2_headers_err       // don't fall through into the refused path
.Lh2_headers_refused:
    cmp xzr, xzr             // failure — carry set
    mov x0, #H2_ERR_REFUSED_STREAM
.Lh2_headers_err:
    ldr x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret                      // x0 = error, carry set
ENDFUNC h2_handle_headers
