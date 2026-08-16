#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_send_settings
//
// Description: Emit h2_settings_frame — the opening SETTINGS frame with
//   SETTINGS_HEADER_TABLE_SIZE = 4096 (the RFC 9113 §6.5.2 protocol
//   default), valid as the first frame of the server connection
//   preface (§3.5, §6.5). Delegates to write_all (util.S) so partial
//   writes are completed.
//
// Input/Arguments:
//   x0 — client file descriptor
//
// Output/Returns:
//   x0 — bytes written (h2_settings_frame_len) on success (carry clear)
//   x0 — errno (EPIPE, ECONNRESET, ...) on failure (carry set)
//
// Clobbered Registers:
//   x0, x1, x2, x8, x16 (syscall registers; see write_all)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_send_settings
h2_send_settings:
    adr_l x1, h2_settings_frame
    mov x2, #21                       // h2_settings_frame_len = 21 bytes
    b write_all
