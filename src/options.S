#include "defs.S"

.global options

.text
options:
    // do not default to index.html
    mov x0, #0
    bl do_path_checks

    ldr_l x0, filename_str
    ldrb w1, [x0]
    cmp w1, #'*'
    b.eq L204

    // Look up the path in the embedded table — no filesystem stat().
    ldr_l x0, filename_str
    ldr_l x1, filename_len
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
