#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: streqn_i
//
// Description: Case-insensitive streqn. Compares up to `max length`
//   bytes of str1 and str2, folding ASCII A-Z to lowercase on both
//   sides. A 16-byte-wide NEON fast path handles the bulk of the
//   comparison (case folding via cmhs range check + OR-with-0x20,
//   combined NUL/mismatch exit mask, OR-reduce to detect a stop),
//   falling back to a byte-at-a-time loop for the tail (< 16 bytes)
//   and to resolve the exact position of a NUL or mismatch.
//
//   Uses x11/x12 (w11/w12) as scratch so w5-w10 used by callers
//   (get_filetype etc) are preserved. NEON v0-v5 and v16-v18 are
//   clobbered but only when the 16-byte path actually runs (x2 >= 16).
//
// Input/Arguments:
//   x0 -> str1
//   x1 -> str2
//   x2 -> max length
//
// Output/Returns:
//   x0 -> 1 if match, 0 if doesn't match
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x11, x12
//   NEON (only on the x2 >= 16 path): v0-v5, v16-v18
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 4
FUNC streqn_i
    cbz x2, Lstreqn_i_match

    // Short inputs (the common case for every current caller — MIME
    // extensions, header names, "bytes"/"range" prefixes) skip the NEON
    // machinery entirely and go straight to the byte loop.
    cmp x2, #16
    b.lo Lbyte_loop

    // Preload NEON vector constants for 16-byte case folding.
    mov w11, #'A'
    dup v16.16b, w11           // Vector filled with 'A'
    mov w11, #'Z'
    dup v17.16b, w11           // Vector filled with 'Z'
    mov w11, #0x20
    dup v18.16b, w11           // Vector filled with 0x20 (lowercase bit)

Lneon_loop:
    cmp x2, #16
    b.lo Lbyte_loop            // Less than 16 bytes remaining -> byte loop

    // Load 16 bytes from each string
    ldr q0, [x0]               // q0 = 16 bytes from str1
    ldr q1, [x1]               // q1 = 16 bytes from str2

    // Case-fold str1 (v0) to lowercase -> v4. cmhs is the unsigned
    // compare; bytes outside ['A','Z'] (including 0x80-0xFF, which a
    // signed cmge would have to reason about) are rejected by one of
    // the two range bounds, so the mask is exactly A-Z.
    cmhs v2.16b, v0.16b, v16.16b   // Is byte >= 'A'?
    cmhs v3.16b, v17.16b, v0.16b   // Is byte <= 'Z'?
    and v2.16b, v2.16b, v3.16b     // True if character is within ['A', 'Z']
    and v2.16b, v2.16b, v18.16b    // Mask to 0x20 where uppercase
    orr v4.16b, v0.16b, v2.16b     // v4 = str1 lowercased

    // Case-fold str2 (v1) to lowercase -> v5
    cmhs v2.16b, v1.16b, v16.16b   // Is byte >= 'A'?
    cmhs v3.16b, v17.16b, v1.16b   // Is byte <= 'Z'?
    and v2.16b, v2.16b, v3.16b     // True if character is within ['A', 'Z']
    and v2.16b, v2.16b, v18.16b    // Mask to 0x20 where uppercase
    orr v5.16b, v1.16b, v2.16b     // v5 = str2 lowercased

    // Check for null terminators in original data
    cmeq v2.16b, v0.16b, #0        // Is byte in str1 == 0?
    cmeq v3.16b, v1.16b, #0        // Is byte in str2 == 0?
    orr v2.16b, v2.16b, v3.16b     // Combined null terminator mask

    // Compare lowercased strings for differences
    cmeq v3.16b, v4.16b, v5.16b    // True where bytes match
    mvn v3.16b, v3.16b             // Invert -> True where bytes mismatch

    // Merge exit conditions: stop if there is a null byte OR a mismatch
    orr v2.16b, v2.16b, v3.16b

    // Any lane triggered? OR-reduce the two 64-bit halves: the mask is
    // all-0x00 or all-0xFF per byte, so ORing the halves is non-zero
    // exactly when some byte hit a stop condition. (A cross-lane umaxv
    // would need the non-standard `umaxv b6, v2.16b` form — clang
    // accepts that as an alias, GNU as rejects it — so the portable
    // umov/umov/orr is used instead, and it avoids the slow reduction
    // pipe too.)
    umov x11, v2.d[0]
    umov x12, v2.d[1]
    orr x11, x11, x12
    cbnz x11, Lbyte_loop        // NUL or mismatch found -> resolve in byte loop

    // No stop condition triggered; advance pointers and counter. If the
    // limit is consumed exactly, we're done — do NOT fall into the byte
    // loop, which would compare a byte past the limit.
    add x0, x0, #16
    add x1, x1, #16
    subs x2, x2, #16
    b.eq Lstreqn_i_match
    b Lneon_loop

Lbyte_loop:
    // Safe byte-by-byte comparison fallback (identical semantics to the
    // scalar path). Reached with x2 < 16 for the tail, or with the
    // pointers still at the start of the 16-byte chunk that triggered a
    // NUL/mismatch above.
    cbz x2, Lstreqn_i_match     // nothing left to compare -> match

    ldrb w3, [x0]
    ldrb w4, [x1]

    cmp w3, #0
    ccmp w4, #0, #0, eq
    b.eq Lstreqn_i_match
    cbz w3, Lstreqn_i_no_match
    cbz w4, Lstreqn_i_no_match

    // Fold w3 to lowercase
    cmp w3, #'A'
    b.lo 1f
    cmp w3, #'Z'
    b.hi 1f
    add w3, w3, #0x20
1:
    // Fold w4 to lowercase
    cmp w4, #'A'
    b.lo 2f
    cmp w4, #'Z'
    b.hi 2f
    add w4, w4, #0x20
2:
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    subs x2, x2, #1
    b.eq Lstreqn_i_match

    add x0, x0, #1
    add x1, x1, #1
    b Lbyte_loop

Lstreqn_i_match:
    mov x0, #1
    ret

Lstreqn_i_no_match:
    mov x0, #0
    ret
ENDFUNC streqn_i
