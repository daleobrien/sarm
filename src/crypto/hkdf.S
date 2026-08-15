// ─────────────────────────────────────────────────────────────────────

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// File: hkdf.S — HKDF-SHA256 for ymawky (PLAN.MD Phase 5)
//
// HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869) plus
// the TLS 1.3 HKDF-Expand-Label wrapper (RFC 8446 §7.1), built on the
// one-shot hmac_sha256 from hmac.S. No libc or external crypto library
// required.
//
//   hkdf_extract      — HKDF-Extract: PRK = HMAC(salt, IKM). An absent
//                       salt (saltlen == 0) is replaced by 32 zero
//                       octets (RFC 5869 §2.2), exactly the "extract
//                       secret early" step of the TLS 1.3 key schedule.
//   hkdf_expand       — HKDF-Expand: OKM = T(1) || ... || T(N), with
//                       T(i) = HMAC(PRK, T(i-1) || info || i) and T(0)
//                       the empty string (RFC 5869 §2.3). The counter
//                       octet runs 1..ceil(L/32); L (okmlen) must be
//                       <= 255*32 = 8160 and infolen <= 607 (the
//                       largest possible TLS 1.3 HkdfLabel is 514
//                       octets, so every real call fits).
//   hkdf_expand_label — TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1):
//                       OKM = HKDF-Expand(Secret, HkdfLabel, Length)
//                       where HkdfLabel is the wire struct
//                         { u16 Length; opaque label<7..255>
//                             = "tls13 " || label;
//                           opaque context<0..255> = context }
//                       and `label` is the bare label ("key", "iv",
//                       "finished", "c hs traffic", ...). The secret is
//                       always 32 octets (SHA-256 HashLen). label_len
//                       + 6 and context_len must each fit in one octet
//                       (RFC 8446 bounds), and Length (outlen) must be
//                       <= 8160 like hkdf_expand.
//
// All scratch state lives on the stack: the functions are re-entrant
// and need no global context. hmac_sha256 clobbers x0-x7, x19-x27
// (saved/restored), x30, v0-v7, v16, v18, v19, NZCV — every caller
// below keeps its live values in saved registers across those calls.
//
// Exported Symbols:
//   hkdf_extract      — one-shot extract (doc block below)
//   hkdf_expand       — one-shot expand (doc block below)
//   hkdf_expand_label — one-shot TLS 1.3 expand-label (doc block below)
//
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// Function Name: hkdf_extract
//
// Description: RFC 5869 §2.2 — PRK = HMAC-SHA256(salt, IKM). When
//   saltlen == 0 the salt defaults to a string of 32 zero octets (the
//   RFC's "salt not provided" case; also the TLS 1.3 early-secret
//   extraction). The IKM pointer is ignored when ikmlen == 0.
//
// Input/Arguments:
//   x0 — pointer to the salt (ignored when saltlen == 0)
//   x1 — salt length in bytes (0 = absent, defaults to 32 zeros)
//   x2 — pointer to the input keying material
//   x3 — IKM length in bytes (0 is valid)
//   x4 — pointer to the 32-byte PRK output buffer
//
// Output/Returns:
//   none (void) - 32 PRK bytes written to [x4].
//
// Clobbered Registers:
//   x0-x7, x19-x27, x30, v0-v7, v16, v18, v19, NZCV — everything
//   hmac_sha256 clobbers
//
// Stack Usage:
//   48 bytes (x19 + x30) plus a 32-byte zero-salt block, only on the
//   saltlen == 0 path; the saltlen != 0 path is a tail call
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global hkdf_extract
hkdf_extract:
    cbnz    x1, .Lextract_hmac     // salt provided: tail-call straight
                                   //   into hmac_sha256 (x0..x4 are
                                   //   already its exact arguments)
    // ── absent salt -> 32 zero octets (RFC 5869 §2.2) ──
    stp     x19, x30, [sp, #-48]!
    add     x19, sp, #16           // 32-byte zero salt (16-aligned)
    stp     xzr, xzr, [x19]
    stp     xzr, xzr, [x19, #16]
    mov     x0, x19
    mov     x1, #32
    // x2 (ikm), x3 (ikmlen), x4 (prk) are untouched
    bl      hmac_sha256
    ldp     x19, x30, [sp], #48
    ret

.Lextract_hmac:
    b       hmac_sha256            // tail call: PRK = HMAC(salt, IKM)

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
//   none (void) - outlen bytes written to [x5].
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

.align 2
.global hkdf_expand_label
hkdf_expand_label:
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
    bl      hkdf_expand

    ldr     x30, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #608
    ret

// ─────────────────────────────────────────────────────────────────────
// Function Name: .Lhkdf_memcpy (private, leaf)
//
// Description: Byte copy used to assemble the HMAC input blocks and the
//   HkdfLabel. Advances both pointers; preserves the byte count in
//   x10 so callers can reuse it after the call (the internal counter
//   runs in x9).
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
