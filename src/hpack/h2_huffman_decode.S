#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_huffman_decode
//
// Description: Expand a Huffman-coded string (RFC 7541 Appendix B) into
//   h2_hpack_str_buf at the current write offset (appending, so several
//   Huffman strings decoded from one header block coexist). The
//   bitstream is consumed MSB-first; after each bit the accumulated
//   code is looked up in the range of table entries whose code length
//   matches (h2_huffman_len_start[N]), so each look-up only scans the
//   handful of same-length codes. A match emits the symbol and resets
//   the accumulator. After the last byte the leftover bits are padding
//   (§5.2): at most 7 bits, all ones — the most significant bits of the
//   EOS code — and the EOS symbol itself is a decoding error.
//
//   The routine owns its own input bound. It reads all x1 encoded
//   bytes, and until Step 5's carried-forward item was closed it simply
//   trusted that count: h2_hpack_decode_string is its only caller and
//   checks first, so a bad length was unreachable — but the bound lived
//   entirely in the caller, one new caller away from being the same
//   defect it was in §11 (a 4 GB Huffman string walking ~2.5 KB off the
//   end of h2_frame_buf). x2 makes the bound the routine's own.
//
// Input/Arguments:
//   x0 — Huffman-coded bytes
//   x1 — encoded byte count
//   x2 — one past the last readable octet of the enclosing header block
//
// Output/Returns:
//   x0 — decoded string (h2_hpack_str_buf + old write offset)
//   x1 — decoded byte count
//   x2 — encoded bytes consumed (== x1-in: the length field is exact)
//   (carry clear = success / carry set = failure — EOS symbol, invalid
//   padding, output overflow, an encoded length running past x2,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x3, x8-x13, x19-x28, x30 (x19-x28/x30 saved and restored)
//
// Stack Usage:
//   96 bytes: stp x19, x20, [sp, #-96]!, stp x21, x22, [sp, #16],
//     stp x23, x24, [sp, #32], stp x25, x26, [sp, #48],
//     stp x27, x28, [sp, #64], str x30, [sp, #80]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_huffman_decode
h2_huffman_decode:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    str x30, [sp, #80]
    mov x19, x0             // src
    mov x20, x1             // encoded byte count
    // Before anything is read: the whole encoded run has to lie inside
    // the block. x2 is scratch from the next instruction on, so this is
    // the only place the bound can be taken.
    ckrange x9, x19, x20, x2, .Lhuff_bad_input
    adr_l x9, h2_hpack_str_off
    ldr x21, [x9]           // write offset
    adr_l x22, h2_hpack_str_buf
    add x22, x22, x21       // output ptr
    mov x23, #0             // decoded byte count
    lsl x24, x20, #3        // total bits in the stream
    mov x25, #0             // bit position
    mov x26, #0             // accumulated code
    mov x27, #0             // accumulated code length

.Lhuff_bit_loop:
    cmp x25, x24
    b.hs .Lhuff_padding
    // bit = (src[pos >> 3] >> (7 - (pos & 7))) & 1
    lsr x8, x25, #3
    ldrb w2, [x19, x8]
    and w3, w25, #7
    mov w8, #7
    sub w3, w8, w3
    lsr w2, w2, w3
    and w2, w2, #1
    // acc = (acc << 1) | bit
    lsl x26, x26, #1
    orr x26, x26, x2
    add x27, x27, #1
    add x25, x25, #1
    // scan only the entries with this code length
    adr_l x9, h2_huffman_len_start
    ldr w2, [x9, x27, lsl #2]
    add x8, x27, #1
    ldr w3, [x9, x8, lsl #2]
    adr_l x10, h2_huffman_table
.Lhuff_scan:
    cmp x2, x3
    b.hs .Lhuff_bit_loop
    lsl x8, x2, #3          // entry offset (8 bytes each)
    ldr w11, [x10, x8]      // code (u32, LSB-aligned)
    cmp w11, w26
    b.ne .Lhuff_scan_next
    // code matched — check the output bound, then emit the symbol
    add x13, x8, #4
    ldr w11, [x10, x13]     // symbol (u32)
    cmp w11, #256
    b.eq .Lhuff_eos         // EOS inside a string is a decoding error
    add x12, x21, x23       // write offset + decoded so far
    cmp x12, #H2_HPACK_STR_BUF_SIZE
    b.hs .Lhuff_overflow
    strb w11, [x22, x23]
    add x23, x23, #1
    mov x26, #0
    mov x27, #0
    b .Lhuff_bit_loop
.Lhuff_scan_next:
    add x2, x2, #1
    b .Lhuff_scan

.Lhuff_padding:
    // the leftover bits are padding: at most 7, all ones (a prefix of
    // the EOS code, whose 30 bits are all ones)
    cmp x27, #7
    b.hi .Lhuff_bad_padding
    cbz x27, .Lhuff_done
    mov x8, #1
    lsl x8, x8, x27
    sub x8, x8, #1          // (1 << len) - 1 — all ones
    cmp x26, x8
    b.ne .Lhuff_bad_padding
.Lhuff_done:
    adr_l x9, h2_hpack_str_off
    add x21, x21, x23
    str x21, [x9]           // next string appends after this one
    mov x0, x22             // the decoded string start
    mov x1, x23             // decoded length
    mov x2, x20             // encoded bytes consumed
    cmn xzr, xzr            // success — carry clear
    b .Lhuff_epilogue
.Lhuff_eos:
.Lhuff_overflow:
.Lhuff_bad_padding:
.Lhuff_bad_input:
    cmp xzr, xzr            // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhuff_epilogue:
    ldr x30, [sp, #80]
    ldp x27, x28, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
