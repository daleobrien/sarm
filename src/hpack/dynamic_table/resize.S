#include "../../defs.S"

.extern memcpy

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_dyn_resize
//
// Description: Apply a Dynamic Table Size Update (RFC 7541 §6.3): set
//   the dynamic table's current maximum and evict oldest-first until
//   the table fits within it — shrinking to 0 empties the table, and
//   growing back up never resurrects an evicted entry. The caller
//   (h2_hpack_decode_field) is responsible for rejecting a requested
//   size above what the server advertised (SETTINGS_HEADER_TABLE_SIZE)
//   before calling this; this function trusts x0 and just applies it.
//
// Input/Arguments:
//   x0 — new maximum size in bytes (0..H2_HPACK_HEADER_TABLE_SIZE)
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x0-x4, x9-x13
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]! — memcpy is bl'd for compaction
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_hpack_dyn_resize
    str x30, [sp, #-16]!
    str_l x0, h2_hpack_dyn_max, x9

    ldr_l x9, h2_hpack_dyn_size, x10    // running RFC-size total
    ldr_l x11, h2_hpack_dyn_count, x10  // running entry count
    ldr_l x12, h2_hpack_dyn_tail, x10   // running oldest-slot index
    mov x13, #0                          // bytes freed so far

.Ldyn_resize_loop:
    cmp x9, x0
    b.ls .Ldyn_resize_done
    adr_l x1, h2_hpack_dyn_entries
    lsl x2, x12, #4
    add x1, x1, x2
    ldr x2, [x1, #H2_HPACK_DYN_ENTRY_NAME_LEN]
    ldr x3, [x1, #H2_HPACK_DYN_ENTRY_VALUE_LEN]
    add x4, x2, x3
    add x13, x13, x4
    add x4, x4, #32
    sub x9, x9, x4
    sub x11, x11, #1
    add x12, x12, #1
    and x12, x12, #(H2_HPACK_DYN_CAP_ENTRIES - 1)
    b .Ldyn_resize_loop

.Ldyn_resize_done:
    str_l x9,  h2_hpack_dyn_size, x10
    str_l x11, h2_hpack_dyn_count, x10
    str_l x12, h2_hpack_dyn_tail, x10

    cbz x13, .Ldyn_resize_ret
    ldr_l x9, h2_hpack_dyn_used, x10
    sub x9, x9, x13
    str_l x9, h2_hpack_dyn_used, x10
    adr_l x0, h2_hpack_dyn_bytes
    adr_l x1, h2_hpack_dyn_bytes
    add x1, x1, x13
    mov x2, x9
    bl memcpy

.Ldyn_resize_ret:
    ldr x30, [sp], #16
    ret
ENDFUNC h2_hpack_dyn_resize
