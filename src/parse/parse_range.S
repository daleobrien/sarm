#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: parse_range
//
// Description: Parse the "Range: bytes=..." header line and return the
//   start and end of the requested byte range. A missing or malformed
//   Range header fails with carry set.
//
// Input/Arguments:
//   x0 -> HTTP header from client
//   x1 -> length of header
//
// Output/Returns:
//   x0 -> start range (or -1 for an open-ended range)
//   x1 -> end range (or -1 for an open-ended range)
//   carry set = error (no Range header, or a malformed one)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x19-x26 (saved and restored)
//
// Stack Usage:
//   80 bytes: stp x29, x30, [sp, #-80]!
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
range_match_str: .ascii "range"
.equ range_match_len, 5

.align 4
bytes_match_str: .ascii "bytes"
.equ bytes_match_len, 5
.align 4

.bss
.align 4
range_buf: .skip (19 + 15) & ~15 // 19 bytes, rounded up to 16-byte multiple
.align 4

.text
.align 2
.global parse_range
parse_range:
    stp x29, x30, [sp, #-80]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    mov x19, x0
    mov x20, x1
    mov x21, #0 // index

    // x0 is already set
    // x1 is already set
    adr_l x2, range_match_str
    mov x3, range_match_len
    bl get_header_field
    b.cs pr_no_range // wasn't found, oh well!

    mov x22, x0 // pointer to beginning of data
    mov x23, x1 // remaining length in header field

    mov x0, bytes_match_len
    cmp x0, x23
    b.ge pr_no_range

    mov x21, x0 // save this as offset now

    // check if the next content is bytes
    mov x2, x0
    mov x0, x22
    adr_l x1, bytes_match_str
    bl streqn_i
    cbz x0, pr_no_range

    ldrb w0, [x22, x21]
    cmp w0, #'='
    b.ne pr_no_range

    add x21, x21, #1
    cmp x21, x23
    b.ge pr_no_range

    // now we know it's Range: bytes=
    adr_l x2, range_buf
    mov x24, #0
pr_get_start_range:
    ldrb w0, [x22, x21]
    cmp w0, #'-'
    b.eq Lpr_start_next
    cmp w0, #'0'
    b.lt pr_no_range
    cmp w0, #'9'
    b.gt pr_no_range

    strb w0, [x2, x24]
    add x24, x24, #1
    cmp x24, #19
    b.ge pr_no_range

    add x21, x21, #1
    cmp x21, x23
    b.ge pr_no_range

    b pr_get_start_range
Lpr_start_next:
    // check if the range was 0 bytes long, ie, immediately a '-'.
    cmp x24, #0
    b.eq 1f

    mov x0, x2
    mov x1, x24
    bl atoi_n
    b.cs pr_no_range
    mov x25, x0
    b pr_got_start
1:
    mov x25, #-1
pr_got_start:
    adr_l x2, range_buf
    mov x24, #0

pr_get_end_range:
    add x21, x21, #1
    cmp x21, x23
    b.ge pr_no_range

    ldrb w0, [x22, x21]
    cmp w0, #'\r'
    b.eq Lpr_end_next
    cmp w0, #'0'
    b.lt pr_no_range
    cmp w0, #'9'
    b.gt pr_no_range

    strb w0, [x2, x24]
    add x24, x24, #1
    cmp x24, #19
    b.ge pr_no_range

    b pr_get_end_range
Lpr_end_next:
    // check if the range was 0 bytes long, ie, immediately a newline.
    cmp x24, #0
    b.eq 1f

    mov x0, x2
    mov x1, x24
    bl atoi_n
    b.cs pr_no_range
    mov x26, x0
    b pr_got_range
1:
    mov x26, #-1
pr_got_range:
    // both -1 is invalid (like Range: bytes=-)
    cmn x25, #1
    b.ne 1f
    cmn x26, #1
    b.eq pr_no_range

1:
    // if they're negative, don't compare if x25 > x26
    cmn x25, #1
    b.eq 2f
    cmn x26, #1
    b.eq 2f

    // if end < start, it's invalid. ignored! blocked! loser!
    cmp x25, x26
    b.gt pr_no_range

2:
    // if we're here, the ranges are good!
    mov x0, x25
    mov x1, x26
    cmn xzr, xzr
    b pr_epilogue

pr_no_range:
    cmp xzr, xzr
    mov x0, #0
    mov x1, #0
    b pr_epilogue

pr_epilogue:
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #80
    ret
