// ─────────────────────────────────────────────────────────────────────
// File: src/crypto/random.S — cryptographically secure random bytes
//   (PLAN.MD Phase 13: ephemeral X25519 keys and server_random need
//   real entropy, not the deterministic vectors every earlier phase
//   tested against)
// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

.data
.align 4
urandom_path: .asciz "/dev/urandom"

// ─────────────────────────────────────────────────────────────────────
// Function Name: crypto_random_bytes
//
// Description: Fill a buffer with cryptographically secure random
//   bytes, read from /dev/urandom. Opens the device, reads exactly len
//   bytes (looping over short reads and retrying on EINTR, like
//   transport_read), then closes it. An unexpected EOF (the device
//   closing early) is treated as failure — it should never happen for
//   a character device.
//
// Input/Arguments:
//   x0 — pointer to the output buffer
//   x1 — number of bytes to write
//
// Output/Returns:
//   carry clear (success): buffer filled with len random bytes
//   carry set (failure):   x0 — errno (open/read failure), or -1 for
//                           an unexpected EOF
//
// Clobbered Registers:
//   x0-x9, x19-x22 (saved/restored), x30 (saved/restored), NZCV
//
// Stack Usage:
//   48 bytes: x19-x22, x30
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global crypto_random_bytes
crypto_random_bytes:
    stp     x19, x20, [sp, #-48]!
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x19, x0                 // buf
    mov     x20, x1                 // bytes remaining

    adr_l   x0, urandom_path
    mov     x1, #O_RDONLY
    mov     x2, #0
    SCWINUM SYS_open
    SCWISVC
    SCERR
    b.cs    .Lcrb_fail_noclose
    mov     x21, x0                 // fd

.Lcrb_read_loop:
    cbz     x20, .Lcrb_close_ok
    mov     x0, x21
    mov     x1, x19
    mov     x2, x20
    SCWINUM SYS_read
    SCWISVC
    SCERR
    b.cs    .Lcrb_read_err
    cbz     x0, .Lcrb_eof            // EOF before len bytes — unexpected
    add     x19, x19, x0
    sub     x20, x20, x0
    b       .Lcrb_read_loop
.Lcrb_read_err:
    cmp     x0, #EINTR
    b.eq    .Lcrb_read_loop          // interrupted — nothing was consumed
    mov     x22, x0                  // save errno across close
    b       .Lcrb_close_fail

.Lcrb_close_ok:
    mov     x0, x21
    SCWINUM SYS_close
    SCWISVC
    cmn     xzr, xzr                 // success — carry clear
    mov     x0, #0
    b       .Lcrb_ret

.Lcrb_eof:
    mov     x22, #-1
.Lcrb_close_fail:
    mov     x0, x21
    SCWINUM SYS_close
    SCWISVC
    mov     x0, x22
    cmp     xzr, xzr                 // failure — carry set
    b       .Lcrb_ret

.Lcrb_fail_noclose:
    cmp     xzr, xzr                 // failure — carry set (x0 = errno)

.Lcrb_ret:
    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #48
    ret
