// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_next_server_seq
//
// Description: Take the next record sequence number for server direction
//: return the current value of tls_server_seq and
//   increment that counter exactly once. RFC 8446 §5.3: the sequence
//   starts at zero and is incremented after every record read under
//   the current keys.
//
// Input/Arguments:
//   none
//
// Output/Returns:
//   x0 — the current sequence number (the counter now holds seq + 1)
//
// Clobbered Registers:
//   x0-x2
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

#include "../../defs.S"

.text
.align 2
FUNC tls_record_next_server_seq
    adr_l   x1, tls_server_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret
ENDFUNC tls_record_next_server_seq
