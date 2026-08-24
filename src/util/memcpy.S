#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: memcpy
//
// Description: Copy N bytes from x1 into x0. Copies in 16-byte chunks
//   when possible, falling back to a byte loop.
//
// Input/Arguments:
//   x0 -> destination
//   x1 -> source
//   x2 -> length
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0-x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC memcpy
    cbz x2, 1f
    cmp x2, #16
    b.lo 3f
2:
    ldp x3, x4, [x1], #16
    stp x3, x4, [x0], #16
    sub x2, x2, #16
    cmp x2, #16
    b.hs 2b
3:
    cbz x2, 1f
    ldrb w3, [x1], #1
    strb w3, [x0], #1
    sub x2, x2, #1
    b 3b
1:
    ret
ENDFUNC memcpy
