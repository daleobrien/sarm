#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_parse_range
//
// Description: Parse the decoded value of a `range` request header
//   ("bytes=0-99", "bytes=100-", "bytes=-50") into a (start, end) pair
//   — the same shape HTTP/1's parse_range produces. -1 means the part
//   is absent: a -1 start is a suffix range, a -1 end is open-ended.
//   The value scan mirrors parse_range's value half (case-insensitive
//   "bytes" prefix, digits up to '-', 19-digit cap, end < start
//   rejected), but works on the bare value rather than the whole
//   HTTP/1 header buffer, so it terminates on the value length instead
//   of a CRLF.
//
// Input/Arguments:
//   x0 — range value (e.g. "bytes=0-99")
//   x1 — value length
//
// Output/Returns:
//   x0 — start (-1 = suffix range)
//   x1 — end   (-1 = open-ended)
//   carry clear = usable single range; carry set = no usable range
//
// Clobbered Registers:
//   x0-x17, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.data
// the range-unit prefix h2_parse_range accepts (matched
// case-insensitively, like HTTP/1's get_header_field/parse_range)
.align 4
h2_bytes_name:
    .asciz "bytes"
.equ h2_bytes_name_len, 5
.align 4

.text
.align 2
.global h2_parse_range
h2_parse_range:
    str x30, [sp, #-16]!
    mov x6, x0              // value ptr — survives streqn_i / atoi_n
    mov x7, x1              // value length
    // must be at least "bytes=" (6 bytes) with the right prefix
    cmp x7, #6
    b.lo .Lh2pr_no_range
    mov x0, x6
    adr_l x1, h2_bytes_name
    mov x2, #h2_bytes_name_len
    bl streqn_i
    cbz x0, .Lh2pr_no_range
    ldrb w4, [x6, #5]
    cmp w4, #'='
    b.ne .Lh2pr_no_range
    // ── the start: digits up to '-' ──
    mov x8, #6              // cursor
    mov x4, #0              // start digit count
.Lh2pr_start_digits:
    cmp x8, x7
    b.ge .Lh2pr_no_range    // ran off the value before '-' — invalid
    ldrb w5, [x6, x8]
    cmp w5, #'-'
    b.eq .Lh2pr_start_done
    cmp w5, #'0'
    b.lo .Lh2pr_no_range
    cmp w5, #'9'
    b.hi .Lh2pr_no_range
    add x4, x4, #1
    cmp x4, #19
    b.ge .Lh2pr_no_range    // atoi_n's overflow guard (like parse_range)
    add x8, x8, #1
    b .Lh2pr_start_digits
.Lh2pr_start_done:
    // empty start is a suffix range
    cbz x4, .Lh2pr_suffix
    mov x0, x6
    add x0, x0, #6
    mov x1, x4
    bl atoi_n
    b.cs .Lh2pr_no_range
    mov x9, x0              // start
    b .Lh2pr_scan_end
.Lh2pr_suffix:
    mov x9, #-1             // start = -1 → bytes=-N
.Lh2pr_scan_end:
    // ── the end: digits after '-', up to the value end / CR / LF ──
    add x8, x8, #1          // cursor past '-'
    mov x4, #0              // end digit count
.Lh2pr_end_digits:
    cmp x8, x7
    b.ge .Lh2pr_end_done
    ldrb w5, [x6, x8]
    cmp w5, #'\r'
    b.eq .Lh2pr_end_done
    cmp w5, #'\n'
    b.eq .Lh2pr_end_done
    cmp w5, #'0'
    b.lo .Lh2pr_no_range
    cmp w5, #'9'
    b.hi .Lh2pr_no_range
    add x4, x4, #1
    cmp x4, #19
    b.ge .Lh2pr_no_range
    add x8, x8, #1
    b .Lh2pr_end_digits
.Lh2pr_end_done:
    // empty end is an open-ended range
    cbz x4, .Lh2pr_open
    mov x0, x6
    add x0, x0, x8
    sub x0, x0, x4          // pointer to the end digits
    mov x1, x4
    bl atoi_n
    b.cs .Lh2pr_no_range
    mov x10, x0             // end
    b .Lh2pr_check
.Lh2pr_open:
    mov x10, #-1            // end = -1 → bytes=N-
.Lh2pr_check:
    // "bytes=-" (both -1) is invalid
    cmn x9, #1
    b.ne 1f
    cmn x10, #1
    b.eq .Lh2pr_no_range
1:
    // a concrete end below the start is invalid
    cmn x9, #1
    b.eq 2f
    cmn x10, #1
    b.eq 2f
    cmp x9, x10
    b.gt .Lh2pr_no_range
2:
    mov x0, x9
    mov x1, x10
    ldr x30, [sp], #16
    cmn xzr, xzr            // success — carry clear
    ret
.Lh2pr_no_range:
    ldr x30, [sp], #16
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    mov x1, #0
    ret
