#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_hpack_dyn_reset
//
// Description: Reset the HPACK dynamic table to empty, with its
//   maximum restored to what the server advertises
//   (SETTINGS_HEADER_TABLE_SIZE, h2_settings_frame). Called once per
//   connection (h2_connection_loop, alongside the other per-connection
//   h2 state resets) — the server handles one connection at a time, so
//   a previous connection's dynamic-table entries must not leak into
//   the next one's decode.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   (none)
//
// Clobbered Registers:
//   x9, x10
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC h2_hpack_dyn_reset
    mov     x9, #H2_HPACK_HEADER_TABLE_SIZE
    str_l   x9, h2_hpack_dyn_max, x10
    str_l   xzr, h2_hpack_dyn_size, x9
    str_l   xzr, h2_hpack_dyn_used, x9
    str_l   xzr, h2_hpack_dyn_count, x9
    str_l   xzr, h2_hpack_dyn_tail, x9
    ret
ENDFUNC h2_hpack_dyn_reset
