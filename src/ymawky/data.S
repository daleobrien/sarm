#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared server-loop state
//
// Description: Data shared between the accept loop (main.S) and the
//   connection handler (child.S). Everything else in the original
//   ymawky.S data section was single-user and lives with its function.
//
// Exported Symbols:
//   one — constant 1 used by setsockopt() (SO_REUSEADDR, SO_NOSIGPIPE)
// ─────────────────────────────────────────────────────────────────────

.data
.align 2 // one is a .word (4 bytes)
one: .word 1

.global one
