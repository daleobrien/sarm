#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_read
//
// Description: The transport read primitive. Reads exactly len bytes
//   from the fd into buf, looping over short reads. EINTR is retried;
//   EOF or any other error returns with carry set. Dispatches on the
//   runtime `transport_mode` (PLAN.MD §1.3): TRANSPORT_PLAIN issues the
//   raw socket read directly; TRANSPORT_TLS is not implemented yet and
//   fails closed with ENOTSUP (carry set).
//
// Input/Arguments:
//   x0 — fd, x1 — buffer, x2 — length
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 — errno on failure (carry set); 0 on EOF
//
// Clobbered Registers:
//   x0-x4, x9, x19-x21, x30 (x19-x21 saved/restored)
//
// Stack Usage:
//   32 bytes: stp x19, x20, [sp, #-32]!; stp x21, x30, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global transport_read
transport_read:
    ldr_l x9, transport_mode
    cbnz x9, .Ltransport_read_tls
    stp x19, x20, [sp, #-32]!
    stp x21, x30, [sp, #16]
    mov x19, x0             // fd
    mov x20, x1             // buffer
    mov x21, x2             // bytes remaining
.Ltransport_read_loop:
    cbz x21, .Ltransport_read_done
    SCWINUM SYS_read
    mov x0, x19
    mov x1, x20
    mov x2, x21
    SCWISVC
    SCERR
    b.cs .Ltransport_read_fail
    cbz x0, .Ltransport_read_eof
    add x20, x20, x0
    sub x21, x21, x0
    b .Ltransport_read_loop
.Ltransport_read_done:
    cmn xzr, xzr            // success — carry clear
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.Ltransport_read_fail:
    cmp x0, #EINTR
    b.eq .Ltransport_read_loop  // interrupted — nothing was consumed, retry
    cmp xzr, xzr            // failure — carry set
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret                     // x0 = errno
.Ltransport_read_eof:
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    ldp x21, x30, [sp, #16]
    ldp x19, x20, [sp], #32
    ret
.Ltransport_read_tls:
    // TLS transport is not implemented yet (PLAN.MD §1.3 — later phases
    // build it): fail closed rather than serve plaintext on a TLS-mode
    // connection. Nothing was read; x0 = ENOTSUP with carry set.
    mov x0, #ENOTSUP
    cmp xzr, xzr            // failure — carry set
    ret
