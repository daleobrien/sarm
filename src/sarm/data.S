#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: shared server-loop state
//
// Description: Data shared between the accept loop (main.S) and the
//   connection handler (child.S). Everything else in the original
//   sarm.S data section was single-user and lives with its function.
//
// Exported Symbols:
//   one — constant 1 used by setsockopt() (SO_REUSEADDR, SO_NOSIGPIPE)
// ─────────────────────────────────────────────────────────────────────

rodata
.align 4 // one is a .word (4 bytes) — pad it out to 16
OBJECT one
     .word 1
ENDOBJ one
.align 4

