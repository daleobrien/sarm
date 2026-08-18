// ─────────────────────────────────────────────────────────────────────
// File: src/crypto/random.S — cryptographically secure random bytes
//   (ephemeral X25519 keys, server_random and the ECDSA nonce need real
//   entropy, not the deterministic vectors every earlier phase tested
//   against)
// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: crypto_random_bytes
//
// Description: Fill a buffer with cryptographically secure random
//   bytes, straight from the kernel CSPRNG — getentropy(2) on macOS,
//   getrandom(2) on Linux. No file descriptor is involved.
//
//   This used to open("/dev/urandom"), read, and close, once per call.
//   That is three syscalls, and the open dominates them: the benchmark
//   measured 8.9 us per call at every size from 16 to 64 bytes, i.e.
//   entirely fixed cost, entirely path lookup. A TLS connection calls
//   this three times — server_random and the ephemeral X25519 private
//   key in tls_build_server_hello, and the ECDSA nonce k in
//   tls_certificate_verify_write — so it was ~27 us per connection, and
//   scripts/profile_samples.py put it at 11.8% of the handshake
//   workload's busy samples, the largest single non-syscall-wait cost
//   left after the P-256 work.
//
//   Three practical consequences beyond speed:
//     1. No descriptor to leak, and no failure mode where the process
//        is out of file descriptors or running somewhere /dev is not
//        mounted.
//     2. On Linux, getrandom with flags = 0 blocks until the CSPRNG is
//        seeded. Reading /dev/urandom does not, and can hand back
//        unseeded output very early in boot. This is strictly the safer
//        interface, not merely the faster one.
//     3. Same entropy source either way — this is the interface the
//        kernel documents for exactly this purpose, not a userspace
//        PRNG.
//
//   getentropy caps a single call at 256 bytes (EINVAL above that,
//   confirmed on this machine), and getrandom may return a short count
//   or be interrupted, so both paths loop until the buffer is full.
//   Every caller in this tree asks for 32 bytes, so the loop runs once
//   in practice; it exists because the function's contract takes a
//   length, not because a caller needs it.
//
// Input/Arguments:
//   x0 — pointer to the output buffer
//   x1 — number of bytes to write
//
// Output/Returns:
//   carry clear (success): buffer filled with len random bytes
//   carry set (failure):   x0 — errno, or -1 if the kernel returned a
//                          zero-length fill (which it should never do
//                          for a non-zero request)
//
// Clobbered Registers:
//   x0-x2, x16, x19-x21 (saved/restored), NZCV
//
// Stack Usage:
//   32 bytes: x19-x21. Leaf function — nothing is called, so x30 is not
//   saved (the previous /dev/urandom implementation saved it only
//   because it, too, was a leaf and did so unnecessarily).
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global crypto_random_bytes
crypto_random_bytes:
    stp     x19, x20, [sp, #-32]!
    str     x21, [sp, #16]
    mov     x19, x0                 // buf
    mov     x20, x1                 // bytes remaining

#ifdef __linux__
    // getrandom(buf, len, 0). Returns the count written, which may be
    // short, and may fail with EINTR before writing anything.
.Lcrb_loop:
    cbz     x20, .Lcrb_ok
    mov     x0, x19
    mov     x1, x20
    mov     x2, #0                  // flags: block until seeded
    SCWINUM SYS_getrandom
    SCWISVC
    SCERR
    b.cs    .Lcrb_err
    cbz     x0, .Lcrb_stalled       // no progress — would spin forever
    add     x19, x19, x0
    sub     x20, x20, x0
    b       .Lcrb_loop
.Lcrb_err:
    cmp     x0, #EINTR
    b.eq    .Lcrb_loop              // interrupted — nothing was consumed
    b       .Lcrb_fail
#else
    // getentropy(buf, n) fills n bytes or fails outright; n <= 256.
.Lcrb_loop:
    cbz     x20, .Lcrb_ok
    mov     x21, #256
    cmp     x20, x21
    csel    x21, x20, x21, lo       // n = min(remaining, 256)
    mov     x0, x19
    mov     x1, x21
    SCWINUM SYS_getentropy
    SCWISVC
    SCERR
    b.cs    .Lcrb_fail
    add     x19, x19, x21
    sub     x20, x20, x21
    b       .Lcrb_loop
#endif

.Lcrb_ok:
    mov     x0, #0
    cmn     xzr, xzr                // success — carry clear
    b       .Lcrb_ret

#ifdef __linux__
.Lcrb_stalled:
    mov     x0, #-1
#endif
.Lcrb_fail:
    cmp     xzr, xzr                // failure — carry set (x0 = errno)

.Lcrb_ret:
    ldr     x21, [sp, #16]
    ldp     x19, x20, [sp], #32
    ret
