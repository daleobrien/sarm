#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_decode_string
//
// Description: Decode the RFC 7541 §5.2 string that starts at x0. The
//   H bit selects Huffman coding: a Huffman string's length prefix is
//   decoded the same way, then h2_huffman_decode expands the code into
//   h2_hpack_str_buf. The length is a 7-bit-prefix integer; the string
//   data follows verbatim.
//
// Input/Arguments:
//   x0 — first octet of the string representation
//
// Output/Returns:
//   x0 — the string data (first byte)
//   x1 — string length in bytes
//   x2 — bytes consumed by the whole representation (prefix + data)
//   (carry clear = success / carry set = failure — invalid Huffman
//   padding, EOS symbol, output overflow,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x13, x19, x20, x21, x30 (x19-x21/x30 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x19, x30, [sp, #-32]!, str x20, [sp, #16],
//     str x21, [sp, #24]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_decode_string
h2_hpack_decode_string:
    stp x19, x30, [sp, #-32]!
    str x20, [sp, #16]
    str x21, [sp, #24]
    mov x19, x0                 // input ptr — decode_int clobbers x0-x7
    ldrb w3, [x0]
    tbnz w3, #7, .Lhpack_str_huffman
    mov x1, #7                  // string length prefix is 7 bits (§5.2)
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x3, x0                  // length
    mov x4, x1                  // prefix bytes consumed
    add x0, x19, x4             // string data follows the length prefix
    mov x1, x3                  // length
    add x2, x4, x3              // total consumed = prefix + data
    ldp x19, x30, [sp], #32
    cmn xzr, xzr
    ret
.Lhpack_str_huffman:
    // Huffman-coded string (§5.2) — decode the length, then expand the
    // code with h2_huffman_decode into h2_hpack_str_buf
    mov x1, #7
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x20, x0                 // encoded length (bytes)
    mov x21, x1                 // prefix bytes consumed
    add x0, x19, x21            // the Huffman code bytes
    mov x1, x20
    bl h2_huffman_decode
    b.cs .Lhpack_str_error
    // h2_huffman_decode: x0 -> decoded, x1 = decoded len, x2 = consumed
    add x2, x21, x20            // total consumed = prefix + encoded bytes
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #32
    cmn xzr, xzr
    ret
.Lhpack_str_error:
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #32
    ret                         // carry + error already set
