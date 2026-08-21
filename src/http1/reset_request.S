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
//   x0, x1, x2, x9
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
.global http1_reset_request
http1_reset_request:
    stp x29, x30, [sp, #-16]!

    adr_l x0, request
    mov x1, #(REQUEST_SIZE / 16)
    bl Lhrr_zero16

    adr_l x0, response
    mov x1, #(RESPONSE_SIZE / 16)
    bl Lhrr_zero16

    adr_l x0, filename_buf
    mov x1, #(reset_filename_buf_size / 16)
    bl Lhrr_zero16

    adr_l x0, query_buf
    mov x1, #(query_buf_size / 16)
    bl Lhrr_zero16

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
