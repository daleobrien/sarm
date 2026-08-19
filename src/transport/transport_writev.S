#include "../defs.S"

.extern raw_writev_all
.extern memcpy
.extern transport_write

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_writev
//
// Description: The transport write primitive for a two-part write (a
//   small frame header immediately followed by a body chunk that
//   already lives somewhere else, so copying it next to the header
//   first would cost a memcpy for no reason — Plan.md Phase 2, Step
//   11). Dispatches on the runtime `transport_mode` like transport_write:
//   TRANSPORT_PLAIN sends both parts with a single real writev(2)
//   (raw_writev_all), genuinely zero-copy; TRANSPORT_TLS has no
//   vectored-write equivalent (a TLS record's ciphertext has to be
//   assembled contiguously to be sealed as one unit), so it copies both
//   parts into transport_writev_scratch and hands that off to the
//   ordinary transport_write, unchanged from how a caller doing its own
//   copy-then-write_all behaved before this existed.
//
// Input/Arguments:
//   x0 -> file descriptor
//   x1 -> header pointer, x2 -> header length
//   x3 -> body pointer, x4 -> body length (x2 + x4 must fit
//         transport_writev_scratch_size)
//
// Output/Returns:
//   x0 -> total number of bytes written on success (carry clear)
//   x0 -> errno on failure (carry set)
//
// Clobbered Registers:
//   x0-x11, x16, x19-x24, x30 (x19-x24, x30 saved/restored) — a
//   superset covering both paths (the PLAIN path only touches
//   x0-x2/x9-x11/x16; the TLS path additionally uses everything
//   memcpy/transport_write clobber)
//
// Stack Usage:
//   64 bytes: x19-x24, x30 (padded) for the TLS path; 48 bytes for the
//   PLAIN path (a 2-entry iovec array plus our own saved x30, clobbered
//   by the bl raw_writev_all)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global transport_writev
transport_writev:
    ldr_l   x9, transport_mode
    cbnz    x9, .Ltwv_tls

    // ── TRANSPORT_PLAIN: one real writev(2), zero-copy ──
    sub     sp, sp, #48
    str     x30, [sp, #32]       // bl below clobbers x30 — save our own
    str     x1, [sp, #0]        // iov[0].iov_base = header
    str     x2, [sp, #8]        // iov[0].iov_len  = header length
    str     x3, [sp, #16]       // iov[1].iov_base = body
    str     x4, [sp, #24]       // iov[1].iov_len  = body length
    mov     x1, sp              // iovec array (x0 = fd, untouched)
    mov     x2, #2              // iovcnt
    bl      raw_writev_all
    ldr     x30, [sp, #32]
    add     sp, sp, #48
    ret

.Ltwv_tls:
    // ── TRANSPORT_TLS: no vectored write — assemble contiguously ──
    stp     x19, x20, [sp, #-64]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0             // fd
    mov     x20, x1             // header ptr
    mov     x21, x2             // header length
    mov     x22, x3             // body ptr
    mov     x23, x4             // body length

    adr_l   x24, transport_writev_scratch
    mov     x0, x24
    mov     x1, x20
    mov     x2, x21
    bl      memcpy
    add     x24, x24, x21

    mov     x0, x24
    mov     x1, x22
    mov     x2, x23
    bl      memcpy

    mov     x0, x19
    adr_l   x1, transport_writev_scratch
    add     x2, x21, x23
    bl      transport_write     // propagates x0/carry as our own return

    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #64
    ret
