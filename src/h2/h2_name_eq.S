#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_name_eq
//
// Description: Byte-exact compare of (x0, len x1) with the string at
//   x2 (of length x3). Returns x0 = 1 if equal, 0 otherwise. Reading is
//   bounded by the lengths, so a decoded name or value that points into
//   a header block (not NUL-terminated) is safe to compare.
//
// Input/Arguments:
//   x0 — string to compare
//   x1 — its length
//   x2 — reference string
//   x3 — reference length
//
// Output/Returns:
//   x0 — 1 if equal, 0 otherwise
//
// Clobbered Registers:
//   x0, x4-x6
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_name_eq
h2_name_eq:
    cmp x1, x3
    b.ne .Lh2_name_ne
    mov x4, #0
.Lh2_name_loop:
    cmp x4, x1
    b.hs .Lh2_name_eq_yes
    ldrb w5, [x0, x4]
    ldrb w6, [x2, x4]
    cmp w5, w6
    b.ne .Lh2_name_ne
    add x4, x4, #1
    b .Lh2_name_loop
.Lh2_name_eq_yes:
    mov x0, #1
    ret
.Lh2_name_ne:
    mov x0, #0
    ret
