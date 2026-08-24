#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: check_path_safety
//
// Description: Ensure a path only contains printable ASCII characters.
//   Allowed bytes are 0x20-0x7E; control characters (0x00-0x1F), DEL (0x7F)
//   and all non-ASCII bytes (including UTF-8 multi-byte sequences) are
//   rejected. This is deliberately restrictive for a small server.
//   Tail-recurses into itself via `b check_path_safety`.
//
// Input/Arguments:
//   x0 -> path to check
//   x1 -> path length
//
// Output/Returns:
//   x0 -> 1 if safe, 0 if unsafe
//
// Clobbered Registers:
//   x0, x1, w3
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC check_path_safety
    // if we've reached the end and no issues yet, it's safe
    cbz x1, Lsafe

    ldrb w3, [x0]

    // everything under and including 0x1F, "US" or Unit Separator.
    cmp w3, #0x1F
    b.le Lunsafe

    // everything including and after 0x7F, which is DELETE. everything after
    // that is not valid ascii anymore.
    cmp w3, #0x7F
    b.ge Lunsafe

    sub x1, x1, #1
    add x0, x0, #1
    b check_path_safety

Lsafe:
    mov x0, #1
    ret

Lunsafe:
    mov x0, #0
    ret
ENDFUNC check_path_safety
