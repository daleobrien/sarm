#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_reply_status
//
// Description: A headers-only HTTP/2 status response. Mirrors
//   reply_status's fallback path: with no embedded error pages in the
//   current build, the body is empty. create_response → h2_write_headers
//   with END_STREAM, so the stream ends on the HEADERS frame. When error
//   pages are embedded, this can serve them like reply_status does.
//
// Input/Arguments:
//   x0 — status code, x1 — client fd, x2 — stream id
//
// Output/Returns:
//   (none — write failures are ignored; the caller closes the stream)
//
// Clobbered Registers:
//   x0-x6, x9-x14, x19-x22 (saved/restored), x30
//
// Stack Usage:
//   48 bytes: stp x19, x20, [sp, #-48]!; stp x21, x22, [sp, #16];
//   str x30, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_reply_status
h2_reply_status:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    str x30, [sp, #32]
    mov x19, x0             // status
    mov x20, x1             // fd
    mov x21, x2             // stream id
    str_l xzr, resource_type
    adr_l x0, response
    mov x1, x19
    mov x2, #0              // content_length
    mov x3, #-1             // range start
    mov x4, #-1             // range end
    mov x5, #0              // body ptr
    mov x6, #0              // body length
    bl create_response
    mov x0, x20
    adr_l x1, response
    mov x2, x21
    mov x3, #H2_FLAG_END_STREAM
    bl h2_write_headers
    ldr x30, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret
