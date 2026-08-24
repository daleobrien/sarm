#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_dyn_lookup
//
// Description: Resolve a dynamic-table index (RFC 7541 §2.3.3 — 1-based,
//   1 = most recently inserted entry, 2 = second most recent, ...) to
//   its name and value. The byte offset of the target entry isn't
//   stored anywhere; it's derived by walking from the oldest live entry
//   forward, summing name+value lengths, which also lands the walk
//   cursor on the target's own circular slot. h2_hpack_table_lookup is
//   this function's only caller — it already subtracts
//   H2_HPACK_STATIC_TABLE_SIZE from the raw wire index before calling.
//
// Input/Arguments:
//   x0 — dynamic-table index (1-based; 1 = newest)
//
// Output/Returns:
//   x0 — name pointer
//   x1 — name length
//   x2 — value pointer
//   x3 — value length
//   (carry clear = success / carry set = failure — index out of range,
//   x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x3, x9-x16
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_hpack_dyn_lookup
    cbz x0, .Ldyn_lookup_bad
    ldr_l x9, h2_hpack_dyn_count, x10
    cmp x0, x9
    b.hi .Ldyn_lookup_bad
    sub x12, x9, x0          // steps from the oldest entry to the target
    ldr_l x10, h2_hpack_dyn_tail, x11
    mov x11, #0              // byte offset accumulator
    mov x9, #0                // steps taken

.Ldyn_lookup_walk:
    cmp x9, x12
    b.eq .Ldyn_lookup_found
    adr_l x13, h2_hpack_dyn_entries
    lsl x14, x10, #4
    add x13, x13, x14
    ldr x15, [x13, #H2_HPACK_DYN_ENTRY_NAME_LEN]
    ldr x16, [x13, #H2_HPACK_DYN_ENTRY_VALUE_LEN]
    add x15, x15, x16
    add x11, x11, x15
    add x10, x10, #1
    and x10, x10, #(H2_HPACK_DYN_CAP_ENTRIES - 1)
    add x9, x9, #1
    b .Ldyn_lookup_walk

.Ldyn_lookup_found:
    // x10 = target's circular slot, x11 = its byte offset in the arena
    adr_l x13, h2_hpack_dyn_entries
    lsl x14, x10, #4
    add x13, x13, x14
    ldr x1, [x13, #H2_HPACK_DYN_ENTRY_NAME_LEN]
    ldr x3, [x13, #H2_HPACK_DYN_ENTRY_VALUE_LEN]
    adr_l x0, h2_hpack_dyn_bytes
    add x0, x0, x11
    add x2, x0, x1
    cmn xzr, xzr
    ret

.Ldyn_lookup_bad:
    cmp xzr, xzr
    mov x0, #H2_ERR_COMPRESSION_ERROR
    ret
ENDFUNC h2_hpack_dyn_lookup
