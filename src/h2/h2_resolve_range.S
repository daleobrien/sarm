#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_resolve_range
//
// Description: Mirror of get.S's range-resolution logic: given a parsed
//   (start, end) pair and the resource size, decide the response.
//   Returns the resolved inclusive window and the status to send — 206
//   with the window, 200 to ignore the range (serve the whole file), or
//   416 when no part of the file lies in the range.
//
// Input/Arguments:
//   x0 — range start (-1 = suffix range)
//   x1 — range end   (-1 = open-ended)
//   x2 — resource size
//
// Output/Returns:
//   x0 — resolved start, x1 — resolved end, x2 — status (200/206/416)
//
// Clobbered Registers:
//   x0-x3
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_resolve_range
h2_resolve_range:
    cmn x0, #1
    b.ne 1f
    // ── suffix range — bytes=-N ──
    cbz x1, .Lh2rr_416       // bytes=-0 is unsatisfiable
    cbz x2, .Lh2rr_200       // empty file — serve the whole (empty) file
    cmp x1, x2
    b.lo 2f
    // N >= size — the whole file is the last N bytes
    mov x0, #0
    sub x1, x2, #1
    b .Lh2rr_206
2:
    // start = size - N, end = size - 1 (inclusive)
    sub x0, x2, x1
    sub x1, x2, #1
    b .Lh2rr_206
1:
    // ── non-suffix range ──
    cbz x2, .Lh2rr_416       // an empty file has no satisfiable range
    cmp x0, x2
    b.hs .Lh2rr_416          // start at or beyond the end of the file
    cmn x1, #1
    b.ne 3f
    sub x1, x2, #1           // open-ended — end = size - 1
    b .Lh2rr_206
3:
    // both concrete — clamp the end to size - 1
    sub x3, x2, #1
    cmp x1, x3
    csel x1, x3, x1, hi
    b .Lh2rr_206
.Lh2rr_416:
    mov x0, #-1
    mov x1, #-1
    mov x2, #416
    ret
.Lh2rr_200:
    mov x0, #-1
    mov x1, #-1
    mov x2, #200
    ret
.Lh2rr_206:
    mov x2, #206
    ret
