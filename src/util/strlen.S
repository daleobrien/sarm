#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: strlen
//
// Description: Get the length of a NULL-terminated string, scanning 16
//   bytes at a time with NEON (cmeq NUL mask, umaxv reduction) and
//   pinpointing the exact NUL byte position with rbit/clz. NOTE: this
//   is a non-standard ABI — the string argument is passed in x1, not x0.
//
// Input/Arguments:
//   x1 -> NULL-terminated string whose length to check
//
// Output/Returns:
//   x0 -> length of string
//
// Clobbered Registers:
//   x0, x2, x3, v0, v1, v2
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────


.text
.align 4
FUNC strlen
    mov     x0, x1                  // x0 tracks our current position

    // ─── 1. PAGE-SAFE ALIGNMENT ───
    // Align pointer to 16 bytes to prevent illegal page crossings
    ands    x2, x0, #15             // Check alignment offset
    b.eq    Lloop_start             // If already aligned, jump to loop

    bic     x0, x0, #15             // Align pointer down to 16-byte boundary
    ldr     q0, [x0]                // Safe load (stays within the same page)
    cmeq    v1.16b, v0.16b, #0      // Mask NUL bytes
    shrn    v2.8b, v1.8h, #4        // Pack mask
    mov     x3, v2.d[0]             // Move to GPR

    // Shift out the junk bytes from before the string start
    lsl     x2, x2, #2              // 4 bits per byte due to shrn
    lsr     x3, x3, x2              // Clear out bytes before string start
    cbz     x3, Ladvance_alignment  // If no NUL found in unaligned part, proceed

    // NUL found in the initial unaligned fragment
    rbit    x3, x3
    clz     x3, x3
    lsr     x3, x3, #2              // Convert back to byte count
    mov     x0, x3                  // Return directly
    ret

Ladvance_alignment:
    add     x0, x0, #16             // Advance to the now-aligned loop pointer

Lloop_start:
    // ─── 2. MAIN OPTIMISED LOOP ───
Lneon_loop:
    ldr     q0, [x0]
    cmeq    v1.16b, v0.16b, #0
    shrn    v2.8b, v1.8h, #4
    mov     x2, v2.d[0]
    cbnz    x2, Lfound              // Exit loop if NUL found
    add     x0, x0, #16
    b       Lneon_loop

    // ─── 3. TAIL ELEMENT PINPOINTING ───
Lfound:
    rbit    x2, x2                  // Bit-reverse the packed mask
    clz     x2, x2                  // Count leading zeros
    lsr     x2, x2, #2              // Divide by 4 (since shrn used 4 bits per lane)
    add     x0, x0, x2              // Exact address of NUL
    sub     x0, x0, x1              // Compute length (End - Start)
    ret
ENDFUNC strlen
