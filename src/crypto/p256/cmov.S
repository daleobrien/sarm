// Constant-time conditional move

#include "../../defs.S"

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_fe_cmov
//
// Description: Constant-time conditional move: if cond != 0, dst = src;
//   otherwise dst is unchanged. Implemented with CSEL, not a branch, so
//   it is safe to use on secret-dependent conditions (e.g. selecting
//   between point-arithmetic results based on a scalar bit).
//
// Input/Arguments:
//   x0 — dst fe pointer, x1 — src fe pointer, x2 — cond
//
// Clobbered Registers:
//   x3-x4
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_fe_cmov
p256_fe_cmov:
    cmp     x2, #0
    ldr     x3, [x0, #0]
    ldr     x4, [x1, #0]
    csel    x3, x4, x3, ne
    str     x3, [x0, #0]
    ldr     x3, [x0, #8]
    ldr     x4, [x1, #8]
    csel    x3, x4, x3, ne
    str     x3, [x0, #8]
    ldr     x3, [x0, #16]
    ldr     x4, [x1, #16]
    csel    x3, x4, x3, ne
    str     x3, [x0, #16]
    ldr     x3, [x0, #24]
    ldr     x4, [x1, #24]
    csel    x3, x4, x3, ne
    str     x3, [x0, #24]
    ret
