// ─────────────────────────────────────────────────────────────────────
// Function Name: hkdf_expand_label
//
// Description: TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1):
//
//     HkdfLabel = struct {
//         uint16            length = Length;
//         opaque label<7..255> = "tls13 " + Label;
//         opaque context<0..255> = Context;
//     }
//     OKM = HKDF-Expand(Secret, HkdfLabel, Length)
//
//   Builds HkdfLabel in a stack buffer (2-byte big-endian length, the
//   1-byte label length 6 + label_len, the "tls13 " prefix, the bare
//   label, the 1-byte context length, the context), then delegates to
//   hkdf_expand with the secret as a 32-octet PRK (SHA-256 HashLen).
//   Constraints carried over from RFC 8446 / RFC 5869: 6 + label_len
//   and context_len must fit in one octet, and outlen <= 8160.
//   A zero-length context is valid (e.g. the "key" / "finished"
//   derivations); its pointer is then ignored.
//
//   Those constraints are checked, not assumed (Step 5,
//   docs/SECURITY.md §3.5). The 520-byte HkdfLabel buffer is
//   sized for the maxima exactly, so an over-long label or context
//   would run the assembly off the end of the frame — and the length
//   octet it writes would silently truncate on the way, producing a
//   label the peer never sent rather than an error. Every one of the
//   fifteen call sites in the TLS key schedule passes compile-time
//   constant lengths, so the check cannot fire today; it is here so
//   that stops being something a reader has to verify call site by
//   call site.
//
// Input/Arguments:
//   x0 — pointer to the 32-octet secret (PRK)
//   x1 — pointer to the bare label (no "tls13 " prefix), e.g. "key"
//   x2 — label length in bytes
//   x3 — pointer to the context (ignored when context_len == 0)
//   x4 — context length in bytes
//   x5 — pointer to the output buffer
//   x6 — output length in bytes (the HkdfLabel `length` field)
//
// Output/Returns:
//   carry clear — outlen bytes written to [x5]
//   carry set   — label_len > 249, context_len > 255, or hkdf_expand
//                 refused the derived info/output lengths; nothing is
//                 written
//
// Clobbered Registers:
//   x0-x10, x13, w11, v0-v7, v16, v18, v19, NZCV, x19-x26
//   (saved/restored), x30 (saved/restored) — everything hkdf_expand
//   (and transitively hmac_sha256) clobbers
//
// Stack Usage:
//   608 bytes - 72 for x19-x26 + x30, 520 for the HkdfLabel buffer
//   (2 + 1 + 6 + 255 label + 1 + 255 context = 520 max, 16-aligned)
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.text
.align 2
FUNC hkdf_expand_label
    // ── preconditions, checked before the buffer is touched ──
    mov     x7, #HKDF_LABEL_MAX_LABEL
    cmp     x2, x7
    b.hi    .Lexpand_label_refuse  // 6 + label_len must fit one octet
    mov     x7, #HKDF_LABEL_MAX_CONTEXT
    cmp     x4, x7
    b.hi    .Lexpand_label_refuse  // context_len must fit one octet
    sub     sp, sp, #608
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    str     x30, [sp, #64]

    mov     x19, x0                // secret
    mov     x20, x1                // label
    mov     x21, x2                // label_len
    mov     x22, x3                // context
    mov     x23, x4                // context_len
    mov     x24, x5                // out
    mov     x25, x6                // outlen
    add     x26, sp, #80           // hkdf_label buffer (520 B)

    // ── HkdfLabel: u16 Length, big-endian ──
    lsr     x7, x25, #8
    strb    w7, [x26]              // length >> 8
    strb    w25, [x26, #1]         // length & 0xff

    // ── opaque label<7..255> = "tls13 " + Label ──
    add     w7, w21, #6
    strb    w7, [x26, #2]          // label length octet = 6 + label_len
    mov     w7, #0x74              // "t"
    strb    w7, [x26, #3]
    mov     w7, #0x6c              // "l"
    strb    w7, [x26, #4]
    mov     w7, #0x73              // "s"
    strb    w7, [x26, #5]
    mov     w7, #0x31              // "1"
    strb    w7, [x26, #6]
    mov     w7, #0x33              // "3"
    strb    w7, [x26, #7]
    mov     w7, #0x20              // " "
    strb    w7, [x26, #8]
    add     x7, x26, #9
    mov     x8, x20                // src = label
    mov     x10, x21               // n = label_len
    bl      .Lhkdf_memcpy

    // ── opaque context<0..255> ──
    strb    w23, [x7]              // context length octet (9+label_len)
    add     x7, x7, #1             // dst = 10 + label_len
    mov     x8, x22                // src = context
    mov     x10, x23               // n = context_len
    bl      .Lhkdf_memcpy

    // ── OKM = HKDF-Expand(secret, HkdfLabel, outlen) ──
    mov     x0, x19                // secret (32-octet PRK)
    mov     x1, #32
    mov     x2, x26                // hkdf_label
    add     w7, w21, w23
    add     w7, w7, #10            // HkdfLabel length = 10+label_len+ctx_len
    mov     x3, x7
    mov     x4, x24                // out
    mov     x5, x25                // outlen
    bl      hkdf_expand            // its carry is this function's carry

    ldr     x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #608
    ret
.Lexpand_label_refuse:
    cmp     xzr, xzr               // failure — carry set, out untouched
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lhkdf_memcpy (private, leaf)
//
// Description: Byte copy used to assemble the HkdfLabel.
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
ENDFUNC hkdf_expand_label
