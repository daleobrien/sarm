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
//   the read loop so a hostile block can never make the decoder walk
//   off the end of memory or loop forever.
//
// Input/Arguments:
//   x0 — first octet of the integer
//   x1 — prefix length N (1..8)
//
// Output/Returns:
//   x0 — the value
//   x1 — bytes consumed (>= 1)
//   (carry clear = success / carry set = failure,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x7
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_decode_int
h2_hpack_decode_int:
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
    ldrb w6, [x0, x4]           // next continuation octet
    add x4, x4, #1              // consumed++
    cmp x5, #32                 // shift past the 32-bit value bound?
    b.hs .Lhpack_int_error      //   yes — over-long encoding
    and w7, w6, #0x7f           // payload bits
    lsl x7, x7, x5              // place them at their weight
    add x2, x2, x7              // value += chunk
    tbnz x2, #32, .Lhpack_int_error // value overflowed 32 bits
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
