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
//   The decoded length is checked against `end` before a single data
//   byte is touched (docs/SECURITY.md §3.5, Step 5). That
//   ordering is the whole point: h2_hpack_decode_block does verify that
//   every representation fits the block, but it can only do so once
//   this function has returned, and on the Huffman path the expansion
//   has already read the bytes by then. A 5-octet HEADERS payload
//   declaring a 4 GB Huffman string used to send h2_huffman_decode
//   walking off the end of h2_frame_buf until its 4096-byte output area
//   filled — roughly 2.5 KB of adjacent memory, decoded into a header
//   value. Checking here turns that into COMPRESSION_ERROR before the
//   first read.
//
// Input/Arguments:
//   x0 — first octet of the string representation
//   x1 — one past the last readable octet of the enclosing header block
//
// Output/Returns:
//   x0 — the string data (first byte)
//   x1 — string length in bytes
//   x2 — bytes consumed by the whole representation (prefix + data)
//   (carry clear = success / carry set = failure — a length that runs
//   past the block, invalid Huffman padding, EOS symbol, output
//   overflow, x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x13, x19-x22, x30 (x19-x22/x30 saved and restored)
//
// Stack Usage:
//   48 bytes: stp x19, x30, [sp, #-48]!, str x20, [sp, #16],
//     str x21, [sp, #24], str x22, [sp, #32]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_hpack_decode_string
    stp x19, x30, [sp, #-48]!
    str x20, [sp, #16]
    str x21, [sp, #24]
    str x22, [sp, #32]
    mov x19, x0                 // input ptr — decode_int clobbers x0-x8
    mov x22, x1                 // end — survives every call below
    cmp x19, x22
    b.hs .Lhpack_str_bad        // no length prefix octet to read
    ldrb w3, [x0]
    tbnz w3, #7, .Lhpack_str_huffman
    mov x1, #7                  // string length prefix is 7 bits (§5.2)
    mov x2, x22
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x3, x0                  // length
    mov x4, x1                  // prefix bytes consumed
    add x0, x19, x4             // string data follows the length prefix
    // the data must lie inside the block — checked before it is used
    ckrange x5, x0, x3, x22, .Lhpack_str_bad
    mov x1, x3                  // length
    add x2, x4, x3              // total consumed = prefix + data
    ldr x22, [sp, #32]
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #48
    cmn xzr, xzr
    ret
.Lhpack_str_huffman:
    // Huffman-coded string (§5.2) — decode the length, then expand the
    // code with h2_huffman_decode into h2_hpack_str_buf
    mov x1, #7
    mov x2, x22
    bl h2_hpack_decode_int
    b.cs .Lhpack_str_error
    mov x20, x0                 // encoded length (bytes)
    mov x21, x1                 // prefix bytes consumed
    add x0, x19, x21            // the Huffman code bytes
    // h2_huffman_decode reads all x20 of them, so the bound has to hold
    // before the call, not after it. It is checked twice on purpose:
    // here, because this is the check §11's defect was missing and the
    // ordering is the whole lesson; and inside the callee, which as of
    // Step 5's carried-forward item no longer borrows the bound from
    // whoever called it.
    ckrange x5, x0, x20, x22, .Lhpack_str_bad
    mov x1, x20
    mov x2, x22                 // block end — the callee's own bound
    bl h2_huffman_decode
    b.cs .Lhpack_str_error
    // h2_huffman_decode: x0 -> decoded, x1 = decoded len, x2 = consumed
    add x2, x21, x20            // total consumed = prefix + encoded bytes
    ldr x22, [sp, #32]
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #48
    cmn xzr, xzr
    ret
.Lhpack_str_bad:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhpack_str_error:
    ldr x22, [sp, #32]
    ldr x21, [sp, #24]
    ldr x20, [sp, #16]
    ldp x19, x30, [sp], #48
    ret                         // carry + error already set
ENDFUNC h2_hpack_decode_string
