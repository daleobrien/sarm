#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_verify_preface
//
// Description: Read exactly H2_PREFACE_LEN (24) bytes from the client
//   and compare them against h2_preface. read() on a stream socket may
//   return fewer bytes than requested, so the read loops until all 24
//   arrive; EINTR is retried. On success connection_mode is set to
//   CONNECTION_HTTP2 (RFC 9113 §3.4).
//
// Input/Arguments:
//   x0 — client file descriptor
//   x1 — buffer of at least H2_PREFACE_LEN bytes to read into
//
// Output/Returns:
//   x0 — CONNECTION_HTTP2 on success (carry clear)
//   x0 — H2_ERR_PROTOCOL_ERROR or errno on failure (carry set):
//     H2_ERR_PROTOCOL_ERROR  the bytes aren't the preface (or EOF)
//     errno                  read() failed (ECONNRESET, ETIMEDOUT, ...)
//
// Clobbered Registers:
//   x0-x3, x9 (via str_l), x16 (x19-x21 saved and restored)
//
// Stack Usage:
//   48 bytes: stp x29, x30, [sp, #-48]!; stp x19, x20, [sp, #16];
//   str x21, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_verify_preface
h2_verify_preface:
    stp x29, x30, [sp, #-48]!
    stp x19, x20, [sp, #16]
    str x21, [sp, #32]
    mov x19, x0            // fd
    mov x20, x1            // buffer
    mov x21, #0            // bytes read so far
.Lh2_preface_read:
    SCWINUM SYS_read
    mov x0, x19
    add x1, x20, x21       // append at the end of what we already have
    mov x2, #H2_PREFACE_LEN
    sub x2, x2, x21
    SCWISVC
    SCERR
    b.cs .Lh2_preface_read_failed
    cbz x0, .Lh2_preface_bad       // EOF before the full preface
    add x21, x21, x0
    cmp x21, #H2_PREFACE_LEN
    b.lo .Lh2_preface_read

    // 24 bytes = three 8-byte words; the buffer and the constant are
    // both read little-endian, so plain word compares are exact.
    adr_l x9, h2_preface
    ldr x2, [x20]
    ldr x3, [x9]
    cmp x2, x3
    b.ne .Lh2_preface_bad
    ldr x2, [x20, #8]
    ldr x3, [x9, #8]
    cmp x2, x3
    b.ne .Lh2_preface_bad
    ldr x2, [x20, #16]
    ldr x3, [x9, #16]
    cmp x2, x3
    b.ne .Lh2_preface_bad

    // preface confirmed — the connection speaks HTTP/2
    mov x0, #CONNECTION_HTTP2
    str_l x0, connection_mode
    cmn xzr, xzr           // success — carry clear
    ldr x21, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret

.Lh2_preface_read_failed:
    cmp x0, #EINTR
    b.eq .Lh2_preface_read  // interrupted — retry, nothing was read
    cmp xzr, xzr            // failure — carry set
    ldr x21, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret                     // x0 = errno

.Lh2_preface_bad:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ldr x21, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #48
    ret
