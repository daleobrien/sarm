#include "../defs.S"

.extern h2_hpack_static_lookup
.extern h2_hpack_dyn_lookup

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_table_lookup
//
// Description: Resolve an HPACK index (RFC 7541 §2.3.3) against the
//   combined address space: 1..H2_HPACK_STATIC_TABLE_SIZE (61) is the
//   static table (h2_hpack_static_lookup); anything above that is the
//   dynamic table (h2_hpack_dyn_lookup), addressed 1-based from the
//   most recently inserted entry. h2_hpack_decode_field calls this
//   wherever the wire format allows either table to answer — indexed
//   header fields (§6.1) and the indexed-name form of literal fields
//   (§6.2.1-§6.2.3).
//
// Input/Arguments:
//   x0 — index (1-based; 0 is never valid — the caller filters it)
//
// Output/Returns:
//   x0 — name pointer
//   x1 — name length
//   x2 — value pointer
//   x3 — value length
//   (carry clear = success / carry set = failure, x0 = H2_ERR_COMPRESSION_ERROR)
//
// Clobbered Registers:
//   x0-x3, x9 for a static index (h2_hpack_static_lookup); x0-x3, x9-x16
//   for a dynamic index (h2_hpack_dyn_lookup) — the link register is
//   untouched, both are tail calls
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_hpack_table_lookup
h2_hpack_table_lookup:
    cmp x0, #H2_HPACK_STATIC_TABLE_SIZE
    b.hi .Lhtl_dynamic
    b h2_hpack_static_lookup
.Lhtl_dynamic:
    sub x0, x0, #H2_HPACK_STATIC_TABLE_SIZE
    b h2_hpack_dyn_lookup
