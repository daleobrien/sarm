#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: head
//
// Description: Handle HEAD — reply with just the header, pretty short
//   n sweet. HEAD sends headers only: body_length = 0. Content-Length
//   still reflects the full resource (what GET would send).
//
// Input/Arguments:
//   none (uses the parsed `request` struct)
//
// Output/Returns:
//   none
//
// Clobbered Registers:
//   x0–x6, x9, x19, x30
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// for HEAD, reply with just the header. pretty short n sweet.
FUNC head
    bl get_setup // this does basically everything we want.

    // HEAD sends headers only: body_length = 0. Content-Length still
    // reflects the full resource (what GET would send).
    mov x19, x0 // content_size
    adr_l x0, response
    mov x1, #200 // 200 OK
    mov x2, x19 // content_length
    mov x3, #-1 // range start — no range
    mov x4, #-1 // range end
    ldr_l x5, embedded_content // body ptr (not sent)
    mov x6, #0  // body length — headers only
    bl create_response
    bl http1_write_response
    b.cs L500

    // on close, child_end will close the file descriptor
    b http1_keepalive_continue

// local trampoline: b.cond/cbz can't reach reply_status across files
L500:
    mov x0, #500
    mov x1, #0
    b reply_status
ENDFUNC head
