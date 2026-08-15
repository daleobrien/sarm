// ─────────────────────────────────────────────────────────────────────
// Function Name: hkdf_expand
//
// Description: RFC 5869 §2.3 — derive okmlen bytes of output keying
//   material from a pseudorandom key:
//
//     N   = ceil(okmlen / 32)
//     T(0) = empty string
//     T(i) = HMAC-SHA256(PRK, T(i-1) || info || octet(i))
//     OKM  = first okmlen octets of T(1) || ... || T(N)
//
//   Each block's HMAC input is assembled in a stack buffer as
//   [T(i-1)] || [info] || [i], so a single hmac_sha256 call per block
//   does the work. info is snapshotted into that buffer once before
//   the loop, so an OKM buffer that aliases the info is safe (and a
//   single-block output <= 32 octets may also alias the PRK, which is
//   only read once). For multi-block outputs the OKM must not overlap
//   the PRK: hmac_sha256 re-reads its key on every block. The counter
//   is a single octet: okmlen must be <= 255*32 = 8160 (RFC 5869), and
//   infolen must satisfy 32 + infolen + 1 <= 640, i.e. infolen <= 607
//   — the largest TLS 1.3 HkdfLabel (hkdf_expand_label's info) is 514
//   octets, so every real call fits. A zero okmlen produces the empty
//   OKM (no-op). An okmlen of 0 with a NULL okm is fine; otherwise
//   okm must hold okmlen bytes.
//
// Input/Arguments:
//   x0 — pointer to the PRK (the HMAC key)
//   x1 — PRK length in bytes (RFC 5869 wants >= 32; hmac_sha256
//        accepts any length)
//   x2 — pointer to the info (ignored when infolen == 0)
//   x3 — info length in bytes (0 is valid)
//   x4 — pointer to the OKM output buffer (okmlen bytes)
//   x5 — OKM length in bytes (0..8160)
//
// Output/Returns:
//   none (void) - okmlen bytes written to [x4].
//
// Clobbered Registers:
//   x0-x10, x13, w11, x19-x27 (saved/restored), x30 (saved/restored),
//   everything hmac_sha256 clobbers
//
// Stack Usage:
//   768 bytes - 80 for x19-x27 + x30, 640 for the assembled HMAC input
//   (32 prev-block octets + info + 1 counter octet), 32 for the running
//   T(i) block (all scratch 16-byte aligned)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.text
.align 2
.global hkdf_expand
hkdf_expand:
    cbz     x5, .Lexpand_done      // okmlen == 0: empty OKM, no-op
    sub     sp, sp, #768
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x30, [sp, #64]

    mov     x19, x0                // prk
    mov     x20, x1                // prklen
    mov     x21, x2                // info
    mov     x22, x3                // infolen
    mov     x23, x4                // okm cursor
    add     x24, sp, #80           // msg: assembled HMAC input (640 B)
    add     x25, sp, #720          // T:   running 32-byte T(i) block
    mov     x26, x5                // remaining output octets
    mov     x27, #0                // i (incremented to 1 before block 1)

    // ── snapshot info at msg[32..32+infolen) ──
    // The output writes would otherwise clobber a caller buffer that
    // aliases info before the later blocks re-read it.
    add     x7, x24, #32
    mov     x8, x21
    mov     x10, x22
    bl      .Lhkdf_memcpy

.Lexpand_loop:
    add     x27, x27, #1           // i = 1..N

    // ── msg = [T(i-1) if i > 1] || info || octet(i) ──
    cmp     x27, #1
    b.eq    .Lexpand_first
    mov     x7, x24                // dst = msg
    mov     x8, x25                // src = T(i-1)
    mov     x10, #32
    bl      .Lhkdf_memcpy          // msg[0..32) = T(i-1)
    mov     x13, x24               // data = msg (prev || info || i)
    b       .Lexpand_counter
.Lexpand_first:
    add     x13, x24, #32          // data = info || i (T(0) is empty)
.Lexpand_counter:
    add     x7, x24, #32
    add     x7, x7, x22
    strb    w27, [x7]              // msg[32 + infolen] = octet(i)
    add     x10, x22, #1           // msglen = infolen + 1
    cmp     x27, #1
    b.eq    .Lexpand_hmac
    add     x10, x10, #32          //   = 32 + infolen + 1 for i > 1

.Lexpand_hmac:
    // ── T(i) = HMAC-SHA256(PRK, data, msglen) ──
    mov     x0, x19
    mov     x1, x20
    mov     x2, x13
    mov     x3, x10
    mov     x4, x25
    bl      hmac_sha256

    // ── append the first min(32, remaining) octets of T(i) to OKM ──
    mov     x10, #32
    cmp     x26, #32
    csel    x10, x26, x10, ls      // copy = min(32, remaining)
    mov     x7, x23                // dst = okm cursor
    mov     x8, x25                // src = T(i)
    bl      .Lhkdf_memcpy
    add     x23, x23, x10          // okm += copy
    subs    x26, x26, x10          // remaining -= copy
    b.ne    .Lexpand_loop

    ldp     x27, x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #768
.Lexpand_done:
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lhkdf_memcpy (private, leaf)
//
// Description: Byte copy used to assemble the HMAC input blocks.
//   Advances both pointers; preserves the byte count in x10.
//
// Input/Arguments:
//   x7  — destination pointer (advanced to the end on exit)
//   x8  — source pointer (advanced to the end on exit)
//   x10 — byte count (0 = no-op, preserved on exit)
//
// Output/Returns:
//   none (void)
//
// Clobbered Registers:
//   x7, x8, x9, w11, NZCV
//
// Stack Usage:
//   none - leaf function
// ─────────────────────────────────────────────────────────────────────

.Lhkdf_memcpy:
    cbz     x10, .Lhkdf_memcpy_done
    mov     x9, x10
.Lhkdf_memcpy_loop:
    ldrb    w11, [x8], #1
    strb    w11, [x7], #1
    subs    x9, x9, #1
    b.ne    .Lhkdf_memcpy_loop
.Lhkdf_memcpy_done:
    ret
