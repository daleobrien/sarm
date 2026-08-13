#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: get_header_field
//
// Description: Find a header field in an HTTP header and return the
//   contents that follow it. Walks the header line by line, so a field
//   name that only appears inside another field's value never matches.
//
// Input/Arguments:
//   x0 -> HTTP header from client
//   x1 -> length of header
//   x2 -> field to search for
//   x3 -> length of x2
//
// Output/Returns:
//   x0 -> pointer to the beginning of the header contents
//   x1 -> remaining length in the header
//   carry set = field not found
//
// Clobbered Registers:
//   x0, x1, x2, x3, x19, x20, x21, x23, x24, x29, x30
//   (x19/x20/x21/x23/x24 saved and restored)
//
// Stack Usage:
//   64 bytes: stp x29, x30, [sp, #-64]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global get_header_field
get_header_field:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x23, [sp, #32]
    str x24, [sp, #48]

    mov x19, x0  // headers
    mov x20, x1  // length
    mov x21, #0  // index
    mov x23, x2  // field string
    mov x24, x3  // field string length

ghf_scan:
    cmp x21, x20
    b.ge ghf_not_found

    ldrb w2, [x19, x21]
    cmp w2, #'\r'
    b.ne ghf_scan_again

    add x21, x21, #1
    cmp x21, x20
    b.ge ghf_not_found

    ldrb w2, [x19, x21]
    cmp w2, #'\n'
    b.ne ghf_scan // x21 already advanced. lone \r, so keep scanning.

    // we're at \r\n, next line begins at x21+1
    add x21, x21, #1
    cmp x21, x20
    b.ge ghf_not_found

    // lines can't begin with whitespace
    ldrb w2, [x19, x21]
    cmp w2, #' '
    b.eq L400
    cmp w2, #'\t'
    b.eq L400

    // if (length - index) < strlen(field), end of header is too
    // soon.
    sub x3, x20, x21
    cmp x3, x24
    b.lt ghf_not_found

    add x0, x19, x21
    mov x1, x23
    mov x2, x24
    bl streqn_i

    cmp x0, #0
    b.eq ghf_scan_again

    // if we're here, it was a match!
    add x21, x21, x24
    // but if the header ends here, before even the :, it's malformed.
    cmp x21, x20
    b.ge L400

    // make sure the field is followed immediately by a ":", otherwise reject
    // it.
    ldrb w2, [x19, x21]
    cmp w2, #':'
    b.ne L400

ghf_skip_ws:
    // gotta bounds check on every byte. got i hate string parsing!
    add x21, x21, #1
    cmp x21, x20
    b.ge L400

    ldrb w2, [x19, x21]
    cmp w2, #' '
    b.eq ghf_skip_ws
    cmp w2, #'\t'
    b.eq ghf_skip_ws
    // got past the whitespace

    // return x0 -> header+offset, start of content
    mov x0, x19
    add x0, x0, x21

    // return x1 -> length-x21 = remaining length
    sub x1, x20, x21
    cmn xzr, xzr
    b ghf_epilogue

ghf_scan_again:
    add x21, x21, #1
    b ghf_scan

ghf_not_found:
    cmp xzr, xzr
    mov x0, #0
    mov x1, #0
    b ghf_epilogue

ghf_epilogue:
    ldr x24, [sp, #48]
    ldp x21, x23, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

// trampolines for conditional branches to reply_* in errors.S (which is too
// far for b.cond / cbz to reach directly).
L400:
    mov x0, #400
    mov x1, #0
    b reply_status
