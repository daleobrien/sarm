// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_next_client_seq
//
// Description: Take the next record sequence number for client direction
//: return the current value of tls_client_seq and
//   increment that counter exactly once. RFC 8446 §5.3: the sequence
//   starts at zero and is incremented after every record written under
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
.global tls_record_next_client_seq
tls_record_next_client_seq:
    adr_l   x1, tls_client_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret
