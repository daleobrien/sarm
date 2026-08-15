#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: transport module state
//
// Description: Shared state for the transport seam (transport_read /
//   transport_write, PLAN.MD §1.2-§1.3).
//
// Exported Symbols:
//   transport_mode — the active transport (TRANSPORT_PLAIN /
//     TRANSPORT_TLS, see config.S). Initialised from the TRANSPORT_MODE
//     compile-time default, so PLAIN is the mode every connection starts
//     with; a future runtime switch can write this before any connection
//     I/O. transport_read/transport_write dispatch on it.
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
.global transport_mode
transport_mode: .quad TRANSPORT_MODE
