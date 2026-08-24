#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_stream_find
//
// Description: Look a stream id up in the fixed stream table
//   (RFC 9113 §5.1). The scan runs over h2_stream_ids — the packed u32
//   index beside h2_streams — not over the entries themselves: 32 ids
//   are 128 bytes there against 1 KB of strided entry here, so the whole
//   search is two cache lines and the table itself is not touched until
//   a match is known. See the h2_stream_ids block in data.S.
//
//   Still a linear scan. At 32 entries that is two vector-width strides
//   of contiguous memory and a hash table would not pay for itself; it
//   is the memory shape that mattered, not the algorithm.
//
//   A zero id matches a free slot, exactly as it did when this scanned
//   the entries directly — wire ids are never zero (§5.1.1), so callers
//   that could hold a connection-level 0 must not reach here.
//
// Input/Arguments:
//   x0 — stream id
//
// Output/Returns:
//   x0 — stream entry, or 0 if the stream is not in the table
//   carry clear = success (not found is a valid result, not an error)
//
// Clobbered Registers:
//   x0, x2, x3, x9
//
//   Unchanged from the entry-scanning version on purpose. Callers hold
//   live values in the registers just outside this set across the call —
//   h2_handle_window_update keeps the frame's stream id in x4 and
//   compares it against the connection high-water mark on the not-found
//   path — so widening this list silently breaks them rather than
//   failing to build.
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

// The hit path turns a slot index straight into an entry pointer with a
// shift, so the entry stride has to stay a power of two.
.if H2S_SIZE != 32
.error "h2_stream_find: H2S_SIZE must be 32 for the lsl #5 index scaling"
.endif

.text
.align 2
FUNC h2_stream_find
    // Stored ids are 31-bit, so anything wider cannot be in the table.
    // Rejecting it here keeps the 32-bit comparisons below exactly as
    // faithful as the 64-bit ones they replace.
    lsr x2, x0, #31
    cbnz x2, .Lh2_find_miss
    mov w2, w0             // wanted id
    adr_l x9, h2_stream_ids
    mov x3, #0             // slot index
.Lh2_find_loop:
    ldr x0, [x9], #8       // two packed ids at once
    cmp w0, w2             // the lower slot
    b.eq .Lh2_find_hit
    add x3, x3, #1
    lsr x0, x0, #32
    cmp w0, w2             // the upper slot
    b.eq .Lh2_find_hit
    add x3, x3, #1
    cmp x3, #H2_MAX_STREAMS
    b.lo .Lh2_find_loop
.Lh2_find_miss:
    mov x0, #0             // not found
    cmn xzr, xzr           // success — carry clear
    ret
.Lh2_find_hit:
    adr_l x0, h2_streams
    add x0, x0, x3, lsl #5 // index * H2S_SIZE
    cmn xzr, xzr
    ret
ENDFUNC h2_stream_find
