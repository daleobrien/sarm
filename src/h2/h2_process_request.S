#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_process_request
//
// Description: Serve a completed request through the existing handlers.
//   The glue between the HTTP/2 HEADERS decoder and the static-file
//   machinery: read the protocol-neutral `request` struct (filled by
//   h2_build_request) and serve it the way HTTP/1 does — lookup_embedded
//   resolves the path, the embedded_* globals are stored exactly as
//   get_setup stores them, create_response fills the protocol-neutral
//   response struct, and the HTTP/2 encoder sends it. GET stages the
//   HEADERS frame (h2_stage_headers) and lets h2_write_body put it in
//   front of the first DATA frame, so the whole response leaves in one
//   write syscall; HEAD sends headers only, written on their own
//   (END_STREAM on the HEADERS frame); OPTIONS is 204 when
//   the path resolves and 404 otherwise; any unknown
//   method is 501. A failed resource lookup is a 404. A path the server
//   refuses (REQ_FORBIDDEN) is a 403; a satisfiable Range on a GET is a
//   206 with content-range (HEAD ignores ranges, like HTTP/1's head);
//   an unsatisfiable range is a 416. The stream carries H2S_FLAG_SERVING
//   for the duration and is moved to CLOSED once the response is sent.
//
// Input/Arguments:
//   x0 — stream id
//   x1 — client fd
//
// Output/Returns:
//   x0 — 0 on success (carry clear); errno on failure (carry set)
//
// Clobbered Registers:
//   x0-x6, x9-x10, x19-x26 (saved/restored)
//
// Stack Usage:
//   96 bytes: stp x19, x20, [sp, #-96]!; ...; str x30, [sp, #64]
//   ([sp, #72]/[sp, #80] hold the response range window; [sp, #88] holds
//   the staged HEADERS length across the h2_write_body call)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_process_request
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    str x30, [sp, #64]
    // [sp, #72] = response range start, [sp, #80] = range end — the
    // response window is built on the stack because it must survive the
    // create_response / h2_write_headers calls
    mov x19, x0             // stream id
    mov x20, x1             // fd
    // ── mark the stream as being served, for the whole response ──
    // The stream stays HALF_CLOSED_REMOTE while we write (that is the
    // truth on the wire — we have not sent END_STREAM yet, and a
    // WINDOW_UPDATE for it is perfectly legal), so the "ready to serve"
    // test alone cannot distinguish it from a request still waiting. The
    // flag makes that distinction; see H2S_FLAG_SERVING in defs.S for why
    // it matters.
    bl h2_stream_find
    cbz x0, 1f
    ldr x1, [x0, #H2S_FLAGS]
    orr x1, x1, #H2S_FLAG_SERVING
    str x1, [x0, #H2S_FLAGS]
1:
    adr_l x9, request
    // ── Stage 10 — a path the server refuses to serve is a 403 ──
    ldr x10, [x9, #REQ_FORBIDDEN]
    cbz x10, 1f
    mov x0, #403
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
1:
    ldr x21, [x9, #REQ_METHOD]

    cmp x21, #GET_ID
    b.eq .Lh2pr_resolve
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_resolve
    cmp x21, #OPTIONS_ID
    b.eq .Lh2pr_options
    // unknown method — 501 (headers only)
    mov x0, #501
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_options:
    // like options.S: 204 when the path resolves, 404 otherwise
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cc 1f
    mov x0, #404
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
1:
    mov x0, #204
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_resolve:
    // GET/HEAD — resolve the resource through the same lookup the HTTP/1
    // path uses; a miss returns here with carry (no reply_status side
    // effects), so the HTTP/2 encoder answers with the 404
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cs .Lh2pr_404
    // x0=content, x1=size, x2=ct, x3=ct_len, x4=gzip, x5=etag, x6=etag_len
    mov x22, x0             // content
    mov x23, x1             // size
    mov x24, x2             // ct
    mov x25, x3             // ct_len
    mov x26, x4             // gzip flag
    	// the response builders read the embedded_* globals. NOTE: str_l with
    	// x9 as the source needs an explicit scratch register — the default
    	// (x9) would be clobbered by adrp before the store.
    	str_l x0, embedded_content
    	str_l x2, embedded_ct
    	str_l x3, embedded_ct_len
    	str_l x4, embedded_gzip
    	str_l x5, embedded_etag
    	str_l x6, embedded_etag_len
    	mov x9, #1
    	str_l x9, resource_type, x10
    	mov x9, #-1
    	str_l x9, file_des, x10  // nothing is open — child_end must not close
    // ── Stage 10 — Range: resolve a request range against the size ──
    // GET serves ranges; HEAD ignores them (HTTP/1's head never parses
    // the Range header). The response window defaults to -1/-1 (none)
    // in the [sp, #72]/[sp, #80] slots. x9/x10 are caller-saved scratch
    // — x27/x28 are callee-saved (x28 is Darwin's frame base) and must
    // not be clobbered here.
    mov x9, #-1
    str x9, [sp, #72]
    mov x10, #-1
    str x10, [sp, #80]
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_create
    adr_l x9, request
    ldr x0, [x9, #REQ_RANGE_PTR]
    cbz x0, .Lh2pr_create
    ldr x1, [x9, #REQ_RANGE_LEN]
    bl h2_parse_range
    b.cs .Lh2pr_create      // unparsable — ignore the range
    mov x2, x23             // resource size
    bl h2_resolve_range     // x0=start, x1=end, x2=200/206/416
    cmp x2, #416
    b.eq .Lh2pr_416
    cmp x2, #200
    b.eq .Lh2pr_create      // range covers the whole file — no range
    str x0, [sp, #72]       // range start
    str x1, [sp, #80]       // range end
.Lh2pr_create:
    // resolve resource → create response (GET: full body, HEAD: none;
    // ranged GET: status 206, windowed body)
    adr_l x0, response
    mov x1, #200
    ldr x3, [sp, #72]
    cmn x3, #1
    b.eq 1f
    mov x1, #206
1:
    mov x2, x23             // content_length (total resource size)
    ldr x4, [sp, #80]       // range end
    mov x5, x22             // body ptr
    mov x6, x23             // body length
    ldr x3, [sp, #72]       // range start
    cmn x3, #1
    b.eq 2f
    // a ranged body is content[start .. end]
    add x5, x5, x3
    ldr x4, [sp, #80]
    sub x6, x4, x3
    add x6, x6, #1
2:
    cmp x21, #HEAD_ID
    b.ne 3f
    mov x6, #0              // HEAD — headers only
3:
    bl create_response
    // encode — GET finishes the stream with DATA frames; HEAD puts
    // END_STREAM on the HEADERS frame
    mov x0, x20
    adr_l x1, response
    mov x2, x19
    mov x3, #0
    cmp x21, #HEAD_ID
    b.eq .Lh2pr_head
    // GET — stage the HEADERS frame instead of writing it, so
    // h2_write_body can send it in front of the first DATA frame in one
    // writev. x0 comes back as the staged length (0 if it was written
    // after all) and is handed straight to h2_write_body.
    bl h2_stage_headers
    b.cs .Lh2pr_500
    str x0, [sp, #88]
    mov x0, x20
    adr_l x1, response
    mov x2, x19
    ldr x3, [sp, #88]
    bl h2_write_body
    b.cs .Lh2pr_500
    b .Lh2pr_done
.Lh2pr_head:
    // HEAD — END_STREAM rides on the HEADERS frame, there is no body to
    // fold it into, so it is written on its own.
    mov x3, #H2_FLAG_END_STREAM
    bl h2_write_headers
    b.cs .Lh2pr_500
    b .Lh2pr_done

.Lh2pr_416:
    mov x0, #416
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done

.Lh2pr_404:
    mov x0, #404
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
    b .Lh2pr_done
.Lh2pr_500:
    mov x0, #500
    mov x1, x20
    mov x2, x19
    bl h2_reply_status
.Lh2pr_done:
    // the response is fully sent — the stream is closed on our side, and
    // is no longer being served
    mov x0, x19
    bl h2_stream_find
    cbz x0, 1f
    mov x1, #H2_STREAM_CLOSED
    str x1, [x0, #H2S_STATE]
    // and the CLOSED bitmap with it — this is the transition that makes
    // the slot recyclable, so h2_stream_create never sees it otherwise.
    // See the h2_stream_used block in h2/data.S.
    adr_l x2, h2_streams
    sub x2, x0, x2
    lsr x2, x2, #5                    // offset / H2S_SIZE
    mov x3, #1
    lsl x3, x3, x2
    ldr_l x2, h2_stream_closed, x9
    orr x2, x2, x3
    str_l x2, h2_stream_closed, x9
    ldr x1, [x0, #H2S_FLAGS]
    and x1, x1, #~H2S_FLAG_SERVING
    str x1, [x0, #H2S_FLAGS]
1:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ldr x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
ENDFUNC h2_process_request
