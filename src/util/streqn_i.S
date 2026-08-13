#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: streqn_i
//
// Description: Case-insensitive streqn, optimized with 4-byte wide
//   loads. Compares up to `max length` bytes of str1 and str2, folding
//   ASCII A-Z to lowercase on both sides. Uses w11-w17 as scratch so
//   w5-w10 used by callers (get_filetype etc) are preserved.
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
//   x0, x1, x2, x3, x4, w11-w17
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global streqn_i
streqn_i:
    cbz x2, Lstreqn_i_match

    // Preload constants for the 4-byte case-fold fast path.
    // Use w11-w17 to avoid clobbering w5-w10 used by callers (get_filetype etc).
    // w11 = 0x80808080 (used in haszero and as byte-range stopper)
    movz w11, #0x8080
    movk w11, #0x8080, lsl #16
    // w12 = 0x41414141  (ASCII 'A' repeated)
    movz w12, #0x4141
    movk w12, #0x4141, lsl #16
    // w13 = 0x1A1A1A1A  (26 = 'Z'+1 - 'A')
    movz w13, #0x1A1A
    movk w13, #0x1A1A, lsl #16
    // w14 = 0x01010101  (used in haszero)
    movz w14, #0x0101
    movk w14, #0x0101, lsl #16

1:
    cmp x2, #4
    b.lo 4f                    // fewer than 4 bytes left — byte loop

    // Load and fold str1 (4 bytes) to lowercase
    ldr w3, [x0]
    orr w15, w3, w11           // w15 = word | 0x80 per byte
    sub w15, w15, w12          // mask_ge_A  (bit 7 set where byte >= 'A')
    sub w16, w15, w13          // mask_gt_Z  (bit 7 set where byte >  'Z')
    bic w16, w15, w16          // mask_AZ = mask_ge_A & ~mask_gt_Z
    and w16, w16, w11          // isolate bit 7 per byte
    lsr w16, w16, #2           // 0x80 → 0x20
    orr w3, w3, w16            // w3 = str1 lowercased

    // Load and fold str2 (4 bytes) to lowercase
    ldr w4, [x1]
    orr w15, w4, w11
    sub w15, w15, w12
    sub w17, w15, w13
    bic w17, w15, w17
    and w17, w17, w11
    lsr w17, w17, #2
    orr w4, w4, w17            // w4 = str2 lowercased

    // Check for null bytes in either word (would mean string ends inside these 4 bytes)
    sub w15, w3, w14           // haszero(w3)
    bic w15, w15, w3
    tst w15, w11
    b.ne 4f                    // str1 has zero — fall to byte loop

    sub w15, w4, w14           // haszero(w4)
    bic w15, w15, w4
    tst w15, w11
    b.ne 4f                    // str2 has zero — fall to byte loop

    // No null bytes — 4-byte word compare is safe
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    sub x2, x2, #4
    add x0, x0, #4
    add x1, x1, #4
    cbz x2, Lstreqn_i_match
    b 1b

4:  // byte-at-a-time fallback (same semantics as original)
    ldrb w3, [x0]
    ldrb w4, [x1]

    cmp w3, #0
    ccmp w4, #0, #0, eq
    b.eq Lstreqn_i_match
    cbz w3, Lstreqn_i_no_match
    cbz w4, Lstreqn_i_no_match

    cmp w3, #'A'
    b.lo 5f
    cmp w3, #'Z'
    b.hi 5f
    add w3, w3, #0x20
5:
    cmp w4, #'A'
    b.lo 6f
    cmp w4, #'Z'
    b.hi 6f
    add w4, w4, #0x20
6:
    cmp w3, w4
    b.ne Lstreqn_i_no_match

    subs x2, x2, #1
    b.eq Lstreqn_i_match

    add x0, x0, #1
    add x1, x1, #1
    b 4b

Lstreqn_i_match:
    mov x0, #1
    ret

Lstreqn_i_no_match:
    mov x0, #0
    ret
