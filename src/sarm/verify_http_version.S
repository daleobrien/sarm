#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: verify_http_version
//
// Description: Scan the header for the request line's HTTP version.
//   Accepts HTTP/1.1 (which must also carry a Host: field, checked via
//   get_header_field) and HTTP/1.0. Anything else replies 400 (or 505
//   for a bare "HTTP/" prefix) via the reply_status trampolines at the
//   bottom of the file.
//
// Input/Arguments:
//   x0 — header buffer
//   x1 — header length
//
// Output/Returns:
//   (none — returns to the caller on success, branches to a
//   reply_status trampoline on failure)
//
// Clobbered Registers:
//   x0, x1, x2, x3, x4, x9, x20, x21 (x20/x21 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x29, x30, [sp, #-32]!; stp x20, x21, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

rodata
host_str: .ascii "Host"
.equ host_str_len, . - host_str

.text
.align 2

// verify the header has an HTTP version and that it's 1.1 or 1.0
// if it's 1.1, ensure we have a Host: field.
// input
// x0 -> header buffer
// x1 -> header length
//
// returns
// nothing, kills process on failure
FUNC verify_http_version
    stp x29, x30, [sp, #-32]!
    stp x20, x21, [sp, #16]

    mov x20, x0
    mov x21, x1

    mov x0, #0
1:
    ldrb w1, [x20, x0]
    cmp w1, #'\r'
    b.ne 2f

    add x0, x0, #1
    cmp x0, x21
    b.ge L400

    ldrb w1, [x20, x0]
    cmp w1, #'\n'
    b.eq 3f

2:
    add x0, x0, #1
    cmp x0, x21
    b.ge L400
    b 1b

3:
    // gotta have at least 9 bytes to hold HTTP/1.1\r
    cmp x0, #9
    b.lt L400

    // x0 points to the index of the \n in \r\n.
    sub x9, x0, #9
    // now it should point to where the "H" would be.

    // Load 8 bytes and compare directly (no streqn calls)
    add x0, x20, x9
    ldr x3, [x0]

    // HTTP/1.1  (LE: 0x312E312F50545448)
    movz x4, #0x5448
    movk x4, #0x5054, lsl #16
    movk x4, #0x312F, lsl #32
    movk x4, #0x312E, lsl #48
    cmp x3, x4
    b.eq Lhttp11

    // HTTP/1.0  (LE: 0x302E312F50545448)
    movz x4, #0x5448
    movk x4, #0x5054, lsl #16
    movk x4, #0x312F, lsl #32
    movk x4, #0x302E, lsl #48
    cmp x3, x4
    b.eq Lhttp10

    // Check at least "HTTP/"  (5 bytes)
    movz w4, #0x5448
    movk w4, #0x5054, lsl #16    // 0x50545448 = "HTTP"
    cmp w3, w4
    b.ne L400
    ldrb w4, [x0, #4]
    cmp w4, #'/'
    b.eq L505

    // oops. none.
    b L400

Lhttp11:
    // if it's 1.1, we need a Host: field.
    mov x0, x20
    mov x1, x21
    adr_l x2, host_str
    mov x3, host_str_len
    bl get_header_field
    b.cs L400

    b vh_epilogue

Lhttp10:
    // HTTP/1.0 doesn't need Host:
    b vh_epilogue

vh_epilogue:
    ldp x20, x21, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

L400:
    mov x0, #400
    mov x1, #0
    b reply_status
L505:
    mov x0, #505
    mov x1, #0
    b reply_status
ENDFUNC verify_http_version
