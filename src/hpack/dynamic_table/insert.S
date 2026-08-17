#include "../../defs.S"

.extern memcpy

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_dyn_insert
//
// Description: Insert one entry into the HPACK dynamic table (RFC 7541
//   §2.3.2, §4.4), called for every "literal with incremental indexing"
//   field (§6.2.1) the decoder sees. The name/value bytes are copied
//   into the table's own arena — they may point into the input block
//   or into h2_hpack_str_buf (a Huffman-decoded string), neither of
//   which stays valid past the current header block decode, but a
//   dynamic-table entry must survive for the rest of the connection.
//
//   If the entry doesn't fit even in an empty table (its RFC size
//   exceeds the current maximum), the whole table is evicted and the
//   entry is *not* added — not an error (§4.4). Otherwise entries are
//   evicted oldest-first until it fits, the freed arena space is
//   compacted back to the front with one memcpy (src > dst is always
//   safe for a forward copy — nothing gets overwritten before it's
//   read), and the new entry is appended.
//
// Input/Arguments:
//   x0 — name pointer
//   x1 — name length
//   x2 — value pointer
//   x3 — value length
//
// Output/Returns:
//   (none — insertion never fails; an oversized entry just empties the
//   table per §4.4, which is not an error condition)
//
// Clobbered Registers:
//   x0-x4, x9-x13 (x19-x27, x30 saved/restored)
//
// Stack Usage:
//   96 bytes: stp x19, x20, [sp, #-96]!; stp x21, x22, [sp, #16];
//   stp x23, x24, [sp, #32]; stp x25, x26, [sp, #48];
//   str x27, [sp, #64]; str x30, [sp, #72]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_dyn_insert
h2_hpack_dyn_insert:
    stp x19, x20, [sp, #-96]!
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    str x27, [sp, #64]
    str x30, [sp, #72]
    mov x19, x0             // name ptr
    mov x20, x1             // name len
    mov x21, x2             // value ptr
    mov x22, x3             // value len

    add x23, x20, x22
    add x23, x23, #32       // entry_size (RFC 7541 §4.1)

    ldr_l x9, h2_hpack_dyn_max, x10
    cmp x23, x9
    b.hi .Ldyn_ins_too_big

    // ── evict oldest entries until this one fits (§4.4) ──
    ldr_l x24, h2_hpack_dyn_size, x10     // running RFC-size total
    ldr_l x25, h2_hpack_dyn_count, x10    // running entry count
    ldr_l x26, h2_hpack_dyn_tail, x10     // running oldest-slot index
    mov x27, #0                            // bytes freed so far

.Ldyn_ins_evict_loop:
    add x9, x24, x23
    ldr_l x10, h2_hpack_dyn_max, x11
    cmp x9, x10
    b.hi .Ldyn_ins_evict_one
    mov x9, #H2_HPACK_DYN_CAP_ENTRIES
    cmp x25, x9
    b.lo .Ldyn_ins_evict_done
.Ldyn_ins_evict_one:
    adr_l x9, h2_hpack_dyn_entries
    lsl x10, x26, #4
    add x9, x9, x10
    ldr x11, [x9, #H2_HPACK_DYN_ENTRY_NAME_LEN]
    ldr x12, [x9, #H2_HPACK_DYN_ENTRY_VALUE_LEN]
    add x13, x11, x12
    add x27, x27, x13       // freed bytes += name_len + value_len
    add x13, x13, #32
    sub x24, x24, x13       // dyn_size -= entry's RFC size
    sub x25, x25, #1        // dyn_count -= 1
    add x26, x26, #1
    and x26, x26, #(H2_HPACK_DYN_CAP_ENTRIES - 1)
    b .Ldyn_ins_evict_loop
.Ldyn_ins_evict_done:

    // ── compact the arena if anything was evicted ──
    ldr_l x9, h2_hpack_dyn_used, x10
    sub x9, x9, x27          // bytes still live, after eviction
    cbz x27, .Ldyn_ins_no_compact
    adr_l x0, h2_hpack_dyn_bytes
    adr_l x1, h2_hpack_dyn_bytes
    add x1, x1, x27
    mov x2, x9
    bl memcpy
.Ldyn_ins_no_compact:
    mov x27, x9              // insertion offset = live bytes after compaction

    // ── append the new entry's bytes: name, then value ──
    adr_l x0, h2_hpack_dyn_bytes
    add x0, x0, x27
    mov x1, x19
    mov x2, x20
    bl memcpy
    adr_l x0, h2_hpack_dyn_bytes
    add x9, x27, x20
    add x0, x0, x9
    mov x1, x21
    mov x2, x22
    bl memcpy

    // ── append the entry descriptor at the new head slot ──
    add x9, x26, x25
    and x9, x9, #(H2_HPACK_DYN_CAP_ENTRIES - 1)
    adr_l x10, h2_hpack_dyn_entries
    lsl x11, x9, #4
    add x10, x10, x11
    str x20, [x10, #H2_HPACK_DYN_ENTRY_NAME_LEN]
    str x22, [x10, #H2_HPACK_DYN_ENTRY_VALUE_LEN]

    add x24, x24, x23        // dyn_size += entry_size
    add x25, x25, #1         // dyn_count += 1
    add x9, x27, x20
    add x9, x9, x22          // new dyn_used

    str_l x24, h2_hpack_dyn_size, x10
    str_l x25, h2_hpack_dyn_count, x10
    str_l x26, h2_hpack_dyn_tail, x10
    str_l x9,  h2_hpack_dyn_used, x10
    b .Ldyn_ins_done

.Ldyn_ins_too_big:
    // the entry alone exceeds the max — empty the table, don't add it
    // (§4.4); not an error
    str_l xzr, h2_hpack_dyn_size, x9
    str_l xzr, h2_hpack_dyn_used, x9
    str_l xzr, h2_hpack_dyn_count, x9
    str_l xzr, h2_hpack_dyn_tail, x9

.Ldyn_ins_done:
    ldr x30, [sp, #72]
    ldr x27, [sp, #64]
    ldp x25, x26, [sp, #48]
    ldp x23, x24, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #96
    ret
