#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: parse_header_end
//
// Description: Scan a string for the end of the HTTP header ("\r\n\r\n")
//   and return the index of the first byte after it.
//
// Input/Arguments:
//   x0 -> string
//   x1 -> length
//
// Output/Returns:
//   x1 -> index of the first byte after the header (0 if not found)
//
// Clobbered Registers:
//   x1, x2, x3, x4, x5, x6
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
header_end: .ascii "\r\n\r\n"
.equ header_end_len, 4

.text
.align 2
.global parse_header_end
parse_header_end:
    adr_l x2, header_end
    mov x5, #0
    mov x6, #0
Lheader_end_loop:
    cmp x5, x1
    b.ge Lno_end_found

    ldrb w3, [x0, x5]
    ldrb w4, [x2, x6]

    cmp w3, w4
    b.eq Lcorrect_char

    b Lincorrect_char

Lcorrect_char:
    add x6, x6, #1

    cmp x6, #4 // length of \r\n\r\n
    b.ge Lend_found

    add x5, x5, #1
    b Lheader_end_loop

Lincorrect_char:
    mov x6, #0
    cmp w3, #'\r' // this \r starts a new potential match, eg, \r\n\r>\r<\n\r\n
    b.ne 2f
    mov x6, #1
2:
    add x5, x5, #1
    b Lheader_end_loop

Lend_found:
    add x1, x5, #1
    ret

Lno_end_found:
    mov x1, #0
    ret
