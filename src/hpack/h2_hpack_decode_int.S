#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_decode_int
//
// Description: Decode the RFC 7541 §5.1 integer that starts at x0: the
//   value sits in the low N bits of the first octet; if it equals
//   2^N - 1, continuation octets follow (7 payload bits each,
//   continuation bit 0x80, most significant group first). The bits
//   above N in the first octet belong to the field representation and
//   are ignored. Values are bounded to 32 bits — an encoding that would
//   overflow is a decoding error (COMPRESSION_ERROR), which also bounds
//   the number of continuation octets a hostile block can make the
//   decoder read.
//
//   Two bounds, not one (docs/SECURITY.md §3.5, Step 5). The
//   32-bit bound is checked on the whole accumulator, because a
//   continuation octet placed at shift 28 contributes up to 2^35 and
//   can therefore leave the 32-bit range without ever setting bit 32 —
//   testing that one bit let 48 of the 128 possible final octets
//   through. And every octet is checked against `end` before it is
//   read, because the shift bound alone only limits *how many* octets
//   are read, not where they are: a truncated integer at the tail of a
//   header block would otherwise read up to five octets past it.
//
// Input/Arguments:
//   x0 — first octet of the integer
//   x1 — prefix length N (1..8)
//   x2 — one past the last readable octet of the enclosing header
//        block; every octet read is checked against it
//
// Output/Returns:
//   x0 — the value
//   x1 — bytes consumed (>= 1)
//   (carry clear = success / carry set = failure,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x8
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_hpack_decode_int
    mov x8, x2                  // end — x2 becomes the accumulator below
    cmp x0, x8
    b.hs .Lhpack_int_error      // not even the prefix octet is readable
    mov w3, #1
    lsl w3, w3, w1              // 1 << N
    sub w3, w3, #1              // mask = 2^N - 1
    ldrb w2, [x0]               // first octet
    and w2, w2, w3              // prefix value (zero-extends to x2)
    mov w4, #1                  // bytes consumed
    cmp w2, w3
    b.lo .Lhpack_int_done       // value < mask — the single-octet form

    // multi-octet form: value = mask + Σ (octet & 0x7f) << (7 * i)
    mov x5, #0                  // shift amount
.Lhpack_int_loop:
    add x3, x0, x4              // where the next octet would be read
    cmp x3, x8
    b.hs .Lhpack_int_error      // it is outside the block — truncated
    ldrb w6, [x0, x4]           // next continuation octet
    add x4, x4, #1              // consumed++
    cmp x5, #32                 // shift past the 32-bit value bound?
    b.hs .Lhpack_int_error      //   yes — over-long encoding
    and w7, w6, #0x7f           // payload bits
    lsl x7, x7, x5              // place them at their weight
    add x2, x2, x7              // value += chunk
    lsr x3, x2, #32             // anything at all above 32 bits?
    cbnz x3, .Lhpack_int_error  //   yes — the value does not fit
    add x5, x5, #7
    tbz w6, #7, .Lhpack_int_done
    b .Lhpack_int_loop

.Lhpack_int_done:
    mov x0, x2
    mov x1, x4
    cmn xzr, xzr                // success — carry clear
    ret
.Lhpack_int_error:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
    ret
ENDFUNC h2_hpack_decode_int
