#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: log_timing
//
// Description: Read the req_start and req_end timevals, compute the
//   elapsed time in microseconds (handling a usec borrow), and write
//   "Took: Nµs\n" to stdout using itoa for the number.
//
// Input/Arguments:
//   (none — reads the req_start/req_end globals)
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x19, x20, x21 (x19/x20 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x29, x30, [sp, #-32]!; stp x19, x20, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.data
took_prefix:    .ascii "Took: "
.equ took_prefix_len, . - took_prefix
took_suffix:    .ascii "µs\n"
.equ took_suffix_len, . - took_suffix

.text
.align 2
.global log_timing

// ── log_timing: write "Took: Nµs\n" to stdout ──────────────────
//
// Reads req_start and req_end globals, computes elapsed microseconds,
// and writes a timing line to stdout.
//
// Clobbers x0–x8.
log_timing:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]

    // ── compute elapsed microseconds ──────────────────────────
    adr_l x0, req_end
    ldp x0, x1, [x0]           // x0 = end.tv_sec, x1 = end.tv_usec
    adr_l x2, req_start
    ldp x2, x3, [x2]           // x2 = start.tv_sec, x3 = start.tv_usec

    sub x19, x0, x2            // x19 = sec_diff
    sub x20, x1, x3            // x20 = usec_diff (may be negative if borrow)

    // handle borrow: if usec_diff < 0, subtract 1 from sec_diff and add 1000000
    cmp x20, #0
    b.ge 1f
    sub x19, x19, #1
    movz x21, #0x4240          // 1000000 low 16 bits
    movk x21, #0x000F, lsl #16 // 1000000 = 0xF4240
    add x20, x20, x21
1:
    // multiply sec_diff by 1000000, add usec_diff for total microseconds
    movz x21, #0x4240
    movk x21, #0x000F, lsl #16 // 1000000 = 0xF4240
    mul x19, x19, x21          // x19 = sec_diff * 1000000
    add x19, x19, x20          // x19 = total elapsed microseconds

    // ── write "Took: " to stdout ─────────────────────────────
    SCWINUM SYS_write
    mov x0, #1                 // stdout
    adr_l x1, took_prefix
    mov x2, took_prefix_len
    SCWISVC
    SCERR

    // ── itoa the elapsed microseconds and write to stdout ───
    mov x0, x19
    bl itoa                    // x0=ptr, x1=len
    SCWINUM SYS_write
    mov x2, x1
    mov x1, x0
    mov x0, #1                 // stdout
    SCWISVC
    SCERR

    // ── write "µs\n" to stdout ──────────────────────────────
    SCWINUM SYS_write
    mov x0, #1
    adr_l x1, took_suffix
    mov x2, took_suffix_len
    SCWISVC
    SCERR

    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
