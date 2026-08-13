#include "defs.S"

.global options

.text
options:
    // the request was already parsed into the `request` struct by
    // parse_request (ymawky.S dispatch) — read the path from there.
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]

    ldrb w1, [x0]
    cmp w1, #'*'
    b.eq L204

    // Look up the path in the embedded table — no filesystem stat().
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cc L204    // found in embedded table → 204

    // Not found in embedded content → 404
    b L404

L204:
    mov x0, #204
    mov x1, #0
    b reply_status
L403:
    mov x0, #403
    mov x1, #0
    b reply_status
L404:
    mov x0, #404
    mov x1, #0
    b reply_status
