#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: create_response
//
// Description: Fill a protocol-neutral response struct from the resolved
//   resource globals (embedded_content, embedded_ct, ...) and explicit
//   arguments. This is the "create response" step: resolve resource →
//   create response → HTTP/1 encoder. The encoder
//   (http1_write_response) — and a future HTTP/2 encoder — consume the
//   same struct.
//
// Input/Arguments:
//   x0 — response struct pointer
//   x1 — status code
//   x2 — content_length (total resource length)
//   x3 — range_start (-1 = no range)
//   x4 — range_end (-1 = no range)
//   x5 — body pointer
//   x6 — body length
//
// Output/Returns:
//   x0 — response struct pointer (unchanged)
//
// Clobbered Registers:
//   x0–x1, x9 (x19 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x29, x30, [sp, #-32]! + str x19, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// fill a protocol-neutral response struct from the resolved resource
// globals (embedded_content, embedded_ct, ...) and explicit arguments.
//
// This is the "create response" step: resolve resource → create response
// → HTTP/1 encoder. The encoder (http1_write_response in header.S) — and
// a future HTTP/2 encoder — consume the same struct.
//
// input
// x0 -> response struct ptr
// x1 -> status code
// x2 -> content_length (total resource length)
// x3 -> range_start (-1 = no range)
// x4 -> range_end   (-1 = no range)
// x5 -> body ptr
// x6 -> body length
//
// output
// x0 -> response struct ptr (unchanged)
//
// clobbers x0–x6, x9–x14
.global create_response
create_response:
    stp x29, x30, [sp, #-32]!
    str x19, [sp, #16]
    mov x19, x0

    str x1, [x19, #RESP_STATUS]
    str x2, [x19, #RESP_CONTENT_LENGTH]
    str x3, [x19, #RESP_RANGE_START]
    str x4, [x19, #RESP_RANGE_END]
    str x5, [x19, #RESP_BODY]
    str x6, [x19, #RESP_BODY_LENGTH]

    // content type: embedded_ct if the resource provides one, else derive
    // it from the request path (filesystem fallback).
    ldr_l x0, embedded_ct
    cbz x0, 1f
    ldr_l x1, embedded_ct_len
    b 2f
1:
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl get_filetype
2:
    str x0, [x19, #RESP_CONTENT_TYPE]
    str x1, [x19, #RESP_CONTENT_TYPE_LEN]

    mov x0, x19
    ldr x19, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
