#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: fnv1a_64
//
// Description: FNV-1a 64-bit hash of a byte buffer. Optimized with
//   native 64-bit hardware multiplication to break serial shift-add
//   dependency chains.
//
// Input/Arguments:
//   x0 -> buffer
//   x1 -> length
//
// Output/Returns:
//   x0 -> 64-bit hash
//
// Clobbered Registers:
//   x1, x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 4                        // 16-byte instruction alignment (2^4)
.global fnv1a_64
fnv1a_64:
    // FNV offset basis: 0xcbf29ce484222325
    movz x3, #0x2325
    movk x3, #0x8422, lsl #16
    movk x3, #0x9ce4, lsl #32
    movk x3, #0xcbf2, lsl #48

    // FNV prime: 0x100000001b3
    movz x4, #0x01b3
    movk x4, #0x0100, lsl #32

Lloop_4x:
    cmp x1, #4
    b.lo Lscalar_loop           // Less than 4 bytes remaining -> scalar loop

    // Byte 1
    ldrb w2, [x0], #1
    eor x3, x3, x2
    mul x3, x3, x4

    // Byte 2
    ldrb w2, [x0], #1
    eor x3, x3, x2
    mul x3, x3, x4

    // Byte 3
    ldrb w2, [x0], #1
    eor x3, x3, x2
    mul x3, x3, x4

    // Byte 4
    ldrb w2, [x0], #1
    eor x3, x3, x2
    mul x3, x3, x4

    sub x1, x1, #4
    b Lloop_4x

Lscalar_loop:
    cbz x1, Ldone

    ldrb w2, [x0], #1
    eor x3, x3, x2
    mul x3, x3, x4

    subs x1, x1, #1
    b.ne Lscalar_loop

Ldone:
    mov x0, x3
    ret
