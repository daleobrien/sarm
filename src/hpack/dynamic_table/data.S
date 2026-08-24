#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: HPACK dynamic table state (RFC 7541 §2.3.2)
//
// Description: A FIFO of at most H2_HPACK_DYN_CAP_ENTRIES entries,
//   newest inserted at the head, oldest evicted from the tail whenever
//   the running RFC-size total would exceed the current maximum. The
//   entry array (h2_hpack_dyn_entries) is a circular buffer indexed by
//   h2_hpack_dyn_tail/h2_hpack_dyn_count; each slot holds only the
//   name/value lengths — the bytes themselves live in
//   h2_hpack_dyn_bytes, a linear (non-circular) arena that insertions
//   always append to and evictions always free from the front,
//   compacted back to offset 0 with a single memmove whenever an
//   eviction happens (insert.S, resize.S). No entry stores its own
//   byte offset: it's derived by summing the lengths of the older live
//   entries, which is cheap because H2_HPACK_DYN_CAP_ENTRIES is small.
//
// Exported Symbols:
//   h2_hpack_dyn_max     — current negotiated maximum size, in bytes
//                          (RFC 7541 §4.1 accounting: name+value+32 per
//                          entry) — 0..H2_HPACK_HEADER_TABLE_SIZE
//   h2_hpack_dyn_size    — running total RFC-size of all live entries
//   h2_hpack_dyn_used    — bytes currently occupied in
//                          h2_hpack_dyn_bytes (name+value only, no
//                          per-entry overhead)
//   h2_hpack_dyn_count   — number of live entries
//   h2_hpack_dyn_tail    — circular slot index of the oldest live entry
//   h2_hpack_dyn_entries — the circular entry array
//   h2_hpack_dyn_bytes   — the byte arena
// ─────────────────────────────────────────────────────────────────────

.bss
.align 4
OBJECT h2_hpack_dyn_max
    .skip 8
ENDOBJ h2_hpack_dyn_max
OBJECT h2_hpack_dyn_size
    .skip 8
ENDOBJ h2_hpack_dyn_size
OBJECT h2_hpack_dyn_used
    .skip 8
ENDOBJ h2_hpack_dyn_used
OBJECT h2_hpack_dyn_count
    .skip 8
ENDOBJ h2_hpack_dyn_count
OBJECT h2_hpack_dyn_tail
    .skip 8
ENDOBJ h2_hpack_dyn_tail
OBJECT h2_hpack_dyn_entries
    .skip H2_HPACK_DYN_CAP_ENTRIES * H2_HPACK_DYN_ENTRY_SIZE
ENDOBJ h2_hpack_dyn_entries
OBJECT h2_hpack_dyn_bytes
    .skip H2_HPACK_HEADER_TABLE_SIZE
ENDOBJ h2_hpack_dyn_bytes

