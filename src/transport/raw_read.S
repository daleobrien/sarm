#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: raw_read_exact
//
// Description: Read exactly len bytes from an fd into buf, looping
//   over short reads, unconditionally — no transport_mode dispatch.
//   This is the primitive transport_read's TRANSPORT_PLAIN path
//   tail-calls, and the one everything that must always touch the
//   wire directly uses instead: tls_read_record (which reads TLS
//   records both before the handshake completes, when transport_mode
//   is still PLAIN, and from transport_read's own TRANSPORT_TLS
//   branch, when calling transport_read itself would just dispatch
//   straight back here and recurse) and transport_write's TLS branch
//   for sending sealed records. EINTR is retried; EOF or any other
//   error returns with carry set.
//
// Input/Arguments:
//   x0 — fd, x1 — buffer, x2 — length
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 — errno on failure (carry set); 0 on EOF
//
// Clobbered Registers:
//   x0-x2, x16, x19-x21 (saved/restored)
//
// Stack Usage:
//   32 bytes: stp x19, x20, [sp, #-32]!; stp x21, x30, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global raw_read_exact
raw_read_exact:
    stp     x19, x20, [sp, #-32]!
    stp     x21, x30, [sp, #16]
    mov     x19, x0             // fd
    mov     x20, x1             // buffer
    mov     x21, x2             // bytes remaining
.Lraw_read_loop:
    cbz     x21, .Lraw_read_done
    SCWINUM SYS_read
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21
    SCWISVC
    SCERR
    b.cs    .Lraw_read_fail
    cbz     x0, .Lraw_read_eof
    add     x20, x20, x0
    sub     x21, x21, x0
    b       .Lraw_read_loop
.Lraw_read_done:
    cmn     xzr, xzr            // success — carry clear
    mov     x0, #0
    ldp     x21, x30, [sp, #16]
    ldp     x19, x20, [sp], #32
    ret
.Lraw_read_fail:
    cmp     x0, #EINTR
    b.eq    .Lraw_read_loop     // interrupted — nothing was consumed, retry
    cmp     xzr, xzr            // failure — carry set
    ldp     x21, x30, [sp, #16]
    ldp     x19, x20, [sp], #32
    ret                         // x0 = errno
.Lraw_read_eof:
    cmp     xzr, xzr            // failure — carry set
    mov     x0, #0
    ldp     x21, x30, [sp, #16]
    ldp     x19, x20, [sp], #32
    ret
