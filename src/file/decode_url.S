#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: decode_url
//
// Description: Convert %XX escape sequences in a URL to raw bytes (%0a =
//   newline, %20 = space), decoding in place. Rejects dangerous inputs by
//   returning (0, 0): %00 decoded null bytes, %XX where X is not a hex
//   digit, and a truncated % at the end of the string. Called before
//   check_path_safety/check_path_traversal so decoded sequences like
//   %2e%2e%2f are caught by check_path_traversal.
//
// Input/Arguments:
//   x0 -> encoded string
//   x1 -> length of encoded string, which must be >= 1. The loop loads
//         the first byte before consulting the length and then tests
//         the decremented length for equality with zero, so a length of
//         0 underflows past the test and keeps decoding in place until
//         it meets a NUL byte or a '%'. Every caller passes at least
//         the 4-byte docroot; recorded in docs/security/fuzzing.md §17
//         rather than checked here.
//
// Output/Returns:
//   x0 -> decoded string (decoded in-place), or 0 on rejection
//   x1 -> length of decoded string, or 0 on rejection
//
// Clobbered Registers:
//   x0, x1, x2, x3, w4, w5, x20 (x20 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x29, x30, [sp, #-32]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global decode_url
decode_url:
    stp x29, x30, [sp, #-32]!
    str x20, [sp, #16]
    mov x2, x0 // write pointer
    mov x3, #0 // x3 is length of new string

Ldecode_loop:
    ldrb w4, [x0]
    // make sure we're not null
    cmp w4, #0
    b.eq Ldecode_end

    cmp w4, #'%'
    b.eq Lencoded_char

    strb w4, [x2, x3]
    add x3, x3, #1

    // make sure we're not reading beyond the length of the string
    sub x1, x1, #1
    cmp x1, #0
    b.eq Ldecode_end

    add x0, x0, #1 // increment along the new string to the next char
    b Ldecode_loop

Lencoded_char:
    cmp x1, #3
    b.lt Lbad_end

    // high nibble
    ldrb w4, [x0, #1]
    bl hex_to_val
    cbnz x20, Lbad_end

    lsl w5, w4, #4 // stash in w5

    // low nibble
    ldrb w4, [x0, #2]
    bl hex_to_val
    cbnz x20, Lbad_end

    orr w4, w5, w4 // combine w5 (high nibble) with w4 (low nibble)

    cmp w4, #0
    b.eq Lbad_end

    // now w4 contains the decoded byte
    strb w4, [x2, x3]

    add x3, x3, #1
    sub x1, x1, #3
    cmp x1, #0
    b.le Ldecode_end

    add x0, x0, #3
    b Ldecode_loop

hex_to_val:
    orr w4, w4, #0x20

    cmp w4, #'0'
    b.lt 2f
    cmp w4, #'9'
    b.le 1f

    cmp w4, #'a'
    b.lt 2f
    cmp w4, #'f'
    b.gt 2f

    mov x20, #0
    sub w4, w4, #'a' - 10
    ret
1:
    mov x20, #0
    sub w4, w4, #'0'
    ret
2:
    mov x20, #1
    ret

Ldecode_end:
    mov x0, x2
    mov x1, x3

    strb wzr, [x0, x1] // null terminate decoded string
    b Ldecode_epilogue

Lbad_end:
    mov x0, #0
    mov x1, #0
    b Ldecode_epilogue

Ldecode_epilogue:
    ldr x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
