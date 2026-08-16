#include "../defs.S"

.extern h2_hpack_table_lookup
.extern h2_hpack_dyn_insert
.extern h2_hpack_dyn_resize

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_decode_field
//
// Description: Decode a single HPACK header field. The first octet's
//   pattern bits select the representation:
//     1xxxxxxx  indexed header field (§6.1)
//     01xxxxxx  literal with incremental indexing (§6.2.1) — decoded
//               and inserted into the dynamic table (h2_hpack_dyn_insert)
//     001xxxxx  dynamic table size update (§6.3) — accepted up to
//               H2_HPACK_HEADER_TABLE_SIZE
//     0000xxxx  literal without indexing (§6.2.2)
//     0001xxxx  literal never indexed (§6.2.3)
//   An indexed field, or the indexed-name form of a literal, resolves
//   through h2_hpack_table_lookup — the combined static+dynamic address
//   space (§2.3.3). The decoded name and value point into the input
//   block (zero-copy), into h2_hpack_str_buf (Huffman-decoded), or —
//   for a dynamic-table hit — into the table's own byte arena.
//
// Input/Arguments:
//   x0 — first octet of the field
//
// Output/Returns:
//   x0 — next octet after the field
//   x1 — name pointer (0 for a size update — not a field, just advance)
//   x2 — name length
//   x3 — value pointer
//   x4 — value length
//   (carry clear = success / carry set = failure,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x16, x19-x27, x30 (x19-x27/x30 saved and restored)
//
// Stack Usage:
//   80 bytes: stp x19, x20, [sp, #-80]!; stp x21, x22, [sp, #16];
//     stp x23, x24, [sp, #32]; stp x25, x26, [sp, #48];
//     str x30, [sp, #64]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_decode_field
h2_hpack_decode_field:
    stp x19, x20, [sp, #-80]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    str x30, [sp, #64]
    mov x21, x0                 // input ptr — survives the sub-calls
    ldrb w6, [x0]               // first octet
    tbz w6, #7, .Lhpack_field_not_indexed

    // ── indexed header field (§6.1) ────────────────────────────────
    mov x1, #7
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    cbz x0, .Lhpack_field_bad   // index 0 is never valid (§6.1)
    mov x6, x1                  // bytes consumed (the index octets)
    bl h2_hpack_table_lookup
    b.cs .Lhpack_field_err
    // lookup: x0 -> name, x1 = name len, x2 -> value, x3 = value len
    mov x4, x3
    mov x3, x2
    mov x2, x1
    mov x1, x0
    add x0, x21, x6             // next = input + consumed
    b .Lhpack_field_ok

.Lhpack_field_not_indexed:
    tbz w6, #6, .Lhpack_field_not_incremental
    // ── literal with incremental indexing (§6.2.1) — decoded and
    // inserted into the dynamic table once the value is known (below);
    // the name index uses a 6-bit prefix ──
    mov x1, #6
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    mov x6, x1                  // prefix bytes consumed
    mov x23, #1                 // do_insert
    cbz x0, .Lhpack_field_inc_new_name
    bl h2_hpack_table_lookup    // indexed name
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr — survives the string decode
    mov x20, x1                 // name len
    add x0, x21, x6             // the value string follows the index
    b .Lhpack_field_literal_value
.Lhpack_field_inc_new_name:
    // the value string follows the name string in the input block — x6
    // (the index prefix bytes) is clobbered by the name decode, so save
    // the name string's input start first
    add x22, x21, x6
    add x0, x21, x6             // the name string follows the index
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr
    mov x20, x1                 // name len
    add x0, x22, x2             // the value string follows the name
    b .Lhpack_field_literal_value

.Lhpack_field_not_incremental:
    tbz w6, #5, .Lhpack_field_literal
    // ── dynamic table size update (§6.3) ──
    mov x1, #5
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    mov x9, #H2_HPACK_HEADER_TABLE_SIZE
    cmp x0, x9
    b.hi .Lhpack_field_bad      // above our advertised max — COMPRESSION_ERROR
    add x19, x21, x1            // next = input + consumed — survives the
                                 // resize call (h2_hpack_dyn_resize never
                                 // touches x19-x27)
    bl h2_hpack_dyn_resize      // x0 = new size, unchanged since decode_int
    // not a header field — name = 0 tells the caller to just advance
    mov x0, x19
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    b .Lhpack_field_ok

.Lhpack_field_literal:
    // ── literal without indexing (§6.2.2) / never indexed (§6.2.3) ──
    // 4-bit name index; 0 means a new name string follows
    mov x1, #4
    bl h2_hpack_decode_int
    b.cs .Lhpack_field_err
    mov x6, x1                  // prefix bytes consumed
    mov x23, #0                 // do_insert
    cbz x0, .Lhpack_field_new_name
    bl h2_hpack_table_lookup    // indexed name
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr — survives the string decode
    mov x20, x1                 // name len
    add x0, x21, x6             // the value string follows the index
    b .Lhpack_field_literal_value
.Lhpack_field_new_name:
    // the value string follows the name string in the input block — x6
    // (the index prefix bytes) is clobbered by the name decode, so save
    // the name string's input start first
    add x22, x21, x6
    add x0, x21, x6             // the name string follows the index
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    mov x19, x0                 // name ptr
    mov x20, x1                 // name len
    add x0, x22, x2             // the value string follows the name
.Lhpack_field_literal_value:
    // remember where the value string starts in the input block — the
    // decode may put a Huffman-expanded value in h2_hpack_str_buf, so
    // `next` must come from the input position, never the value pointer
    mov x22, x0
    bl h2_hpack_decode_string
    b.cs .Lhpack_field_err
    // decode_string: x0 -> value, x1 = value len, x2 = consumed — stash
    // all three in the x19-x27 range so they survive a possible
    // h2_hpack_dyn_insert call below (it saves/restores x19-x27 itself)
    mov x24, x0                 // value ptr
    mov x25, x1                 // value len
    mov x26, x2                 // consumed
    cbz x23, .Lhpack_field_no_insert
    mov x0, x19
    mov x1, x20
    mov x2, x24
    mov x3, x25
    bl h2_hpack_dyn_insert
.Lhpack_field_no_insert:
    mov x3, x24                 // value ptr
    mov x4, x25                 // value len
    add x0, x22, x26            // next = value start + consumed
    mov x1, x19                 // name ptr
    mov x2, x20                 // name len

.Lhpack_field_ok:
    ldr x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #80
    cmn xzr, xzr                // success — carry clear
    ret

.Lhpack_field_bad:
    cmp xzr, xzr                // failure — carry set
    mov x0, #H2_ERR_COMPRESSION_ERROR
.Lhpack_field_err:
    ldr x30, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #80
    ret                         // carry + error already set
