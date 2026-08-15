#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: find_http_code
//
// Description: Look up an HTTP status code in the status_table and
//   return the matching status-line string and its length. Returns
//   0/0 when the code is not in the table.
//
// Input/Arguments:
//   x0 — status code
//
// Output/Returns:
//   x1 — string pointer (0 if not found)
//   x2 — length (0 if not found)
//
// Clobbered Registers:
//   x1, x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global find_http_code
find_http_code:
    adr_l x3, status_table
1:
    // load the first element
    ldr x4, [x3]
    cbz x4, 3f

    // found the matching entry
    cmp x4, x0
    b.eq 2f

    // jump to the next entry
    add x3, x3, #32
    b 1b

2:
    ldr x1, [x3, #8]
    ldr x2, [x3, #16]
    ret

3:
    mov x1, #0
    mov x2, #0
    ret
