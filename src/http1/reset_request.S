#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: http1_reset_request
//
// Description: Clear every piece of per-request state so a kept-alive
//   HTTP/1 connection can serve its next request with no leftover state
//   from the one just finished (Plan.md Phase 1, Step 4). One routine,
//   one place to audit, rather than resets scattered through the
//   request path.
//
//   Zeroed: `request` (REQUEST_SIZE), `response` (RESPONSE_SIZE),
//   `filename_buf`, `query_buf`, `authority_buf`, `range_buf`,
//   `header_buf`, `header_len`, `embedded_content`/`_ct`/`_ct_len`/
//   `_etag`/`_etag_len`/`_gzip`, `resource_type`.
//
//   `filename_buf` and `query_buf` are zeroed only as far as they were
//   used — see Lhrr_zero_dirty below for why that is the same thing as
//   zeroing them whole, and http1_scrub_path_buffers for the once-per-
//   connection pass that gives it its starting point. The rest are small
//   enough that finding out how much of them is dirty would cost more
//   than clearing them.
//
//   Set to their documented initial value rather than zero:
//   `file_des` (-1, "not open"), `connection_mode` (CONNECTION_HTTP1 —
//   harmless to reset since Step 6 only loops HTTP/1 connections, which
//   never change protocol mid-connection).
//
//   Deliberately NOT touched:
//   - `clientfd` — it names the connection, not the request.
//   - formatting scratch — there is none to reset: `itoa` formats into
//     a buffer its caller owns (src/util/itoa.S), not a global.
//   - `buf`, `request_header_len` — the raw I/O buffer and the header
//     length within it are managed by the read loop itself (Step 5's
//     leftover-pipelined-bytes handling, and child.S's Lheader_found),
//     not by this per-request reset.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x9
//
//   x3/x4 are new: Lhrr_zero_dirty reads each 16-byte pair before clearing
//   it, to find where the used part ends. The only caller,
//   http1_keepalive_continue, already declares x0-x4 clobbered and holds
//   nothing live across this call.
//
// Stack Usage:
//   16 bytes: stp x29, x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

// mirrors the padded .bss sizes computed in parse/data.S and
// parse_range.S -- kept local since nothing else needs them as constants.
.equ reset_filename_buf_size,  (filename_buf_size + 1 + 15) & ~15
.equ reset_authority_buf_size, (AUTHORITY_BUF_SIZE + 1 + 15) & ~15
.equ reset_range_buf_size,     (19 + 15) & ~15

.text
.align 2
FUNC http1_reset_request
    stp x29, x30, [sp, #-16]!

    adr_l x0, request
    mov x1, #(REQUEST_SIZE / 16)
    bl Lhrr_zero16

    adr_l x0, response
    mov x1, #(RESPONSE_SIZE / 16)
    bl Lhrr_zero16

    // filename_buf and query_buf are 4 KB each and hold a path of a few
    // dozen bytes, so zeroing them whole was ~8 KB of stores per request —
    // at the measured HTTP/1 rate, several GB/s of writes to leave two
    // buffers in the state they were already almost entirely in. Zero only
    // the part that was actually used. Lhrr_zero_dirty stops where that
    // ends; the invariant it relies on is stated there.
    adr_l x0, filename_buf
    mov x1, #(reset_filename_buf_size / 16)
    bl Lhrr_zero_dirty

    adr_l x0, query_buf
    mov x1, #(query_buf_size / 16)
    bl Lhrr_zero_dirty

    adr_l x0, authority_buf
    mov x1, #(reset_authority_buf_size / 16)
    bl Lhrr_zero16

    adr_l x0, range_buf
    mov x1, #(reset_range_buf_size / 16)
    bl Lhrr_zero16

    adr_l x0, header_buf
    mov x1, #(RESPONSE_HEADER_SIZE / 16) // header_buf_size, in http1/data.S
    bl Lhrr_zero16

    // ── scalar fields (single quad in a 16-byte-padded slot) ──
    str_l xzr, header_len, x9
    str_l xzr, resource_type, x9
    str_l xzr, embedded_content, x9
    str_l xzr, embedded_ct, x9
    str_l xzr, embedded_ct_len, x9
    str_l xzr, embedded_etag, x9
    str_l xzr, embedded_etag_len, x9
    str_l xzr, embedded_gzip, x9

    mov x0, #-1
    str_l x0, file_des, x9

    mov x0, #CONNECTION_HTTP1
    str_l x0, connection_mode, x9

    ldp x29, x30, [sp], #16
    ret

// zero x1 16-byte chunks starting at x0. leaf helper, no frame of its own.
Lhrr_zero16:
    cbz x1, 2f
1:
    stp xzr, xzr, [x0], #16
    subs x1, x1, #1
    b.ne 1b
2:
    ret

// ── Lhrr_zero_dirty — zero only the used part of a path buffer ──
//
// Zeroes 16-byte chunks of [x0, x0 + x1*16) up to, but not including, the
// first chunk that is already entirely zero.
//
// The invariant that makes this equivalent to zeroing the whole buffer: a
// path buffer is only ever left as [bytes written][NUL][untouched zeros].
// It starts zero (.bss), http1_scrub_path_buffers restores that at the
// start of every connection, this restores it after every request, and the
// two writers — parse_path for HTTP/1 and parse_h2_path for HTTP/2 — copy
// a run of non-NUL bytes and then terminate. So the first all-zero chunk
// has nothing written past it.
//
// It stops on the first all-*chunk*-zero rather than the first zero byte.
// A single NUL is the terminator and would be correct today too, but
// sixteen consecutive zeros cannot come out of copying a path at all, so
// this stays right even if a writer someday leaves an embedded NUL with
// more bytes behind it. A writer that fills the buffer and never
// terminates finds no zero chunk and gets the whole thing zeroed, which is
// the old behaviour — every way this can be wrong costs work rather than
// skipping it.
//
// Testing the chunk and clearing it are one pass, not a scan followed by a
// zeroing pass. Two passes read the buffer and then wrote it, so a request
// that genuinely filled 4 KB — which a long URI can do on purpose — paid
// more than the unconditional clear it replaced. Fused, the load and the
// store hit the same line while it is already in L1.
//
// Leaf: no frame, and no bl. Clobbers x0, x1, x3, x4.
Lhrr_zero_dirty:
1:
    cbz x1, 2f
    ldp x3, x4, [x0]
    orr x3, x3, x4
    cbz x3, 2f             // untouched from here on — nothing left to clear
    stp xzr, xzr, [x0], #16
    sub x1, x1, #1
    b 1b
2:
    ret
ENDFUNC http1_reset_request

// ─────────────────────────────────────────────────────────────────────
// Function Name: http1_scrub_path_buffers
//
// Description: Zero filename_buf and query_buf in full. Called once per
//   connection, from child.S's Lchild_common, to establish the invariant
//   Lhrr_zero_dirty depends on before the connection's first request.
//
//   Under `no_fork` the same process serves connection after connection,
//   and nothing used to zero these buffers at connection start — only
//   http1_reset_request did, between requests on one keep-alive
//   connection. An HTTP/2 connection writes the same two globals via
//   parse_h2_path and never calls that reset, so a long h2 path could
//   outlive its connection. Scrubbing here costs one pass per connection
//   instead of one per request and closes that window rather than
//   inheriting it.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0, x1, x30
//
// Stack Usage:
//   16 bytes: stp x29, x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────
.text
.align 2
FUNC http1_scrub_path_buffers
    stp x29, x30, [sp, #-16]!
    adr_l x0, filename_buf
    mov x1, #(reset_filename_buf_size / 16)
    bl Lhrr_zero16
    adr_l x0, query_buf
    mov x1, #(query_buf_size / 16)
    bl Lhrr_zero16
    ldp x29, x30, [sp], #16
    ret
ENDFUNC http1_scrub_path_buffers
