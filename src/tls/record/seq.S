// ─────────────────────────────────────────────────────────────────────
// File: src/tls/record/seq.S — TLS sequence number management (RFC 8446 §5.3)
// ─────────────────────────────────────────────────────────────────────
#include "../../defs.S"


// ─────────────────────────────────────────────────────────────────────
// Function Name: tls_record_next_client_seq / tls_record_next_server_seq
//
// Description: Take the next record sequence number for one direction
//   (PLAN.MD §11.4): return the current value of the per-connection
//   counter (tls_client_seq / tls_server_seq in src/tls/data.S) and
//   increment that counter exactly once. RFC 8446 §5.3: the sequence
//   starts at zero and is incremented after every record read or
//   written under the current keys, independently per direction — so
//   the caller does `bl tls_record_next_server_seq; bl
//   tls_record_encrypt` with the returned value once per record. On a
//   key change the key schedule resets the counter to zero.
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

.text
.align 2
.global tls_record_next_client_seq
tls_record_next_client_seq:
    adr_l   x1, tls_client_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret

.align 2
.global tls_record_next_server_seq
tls_record_next_server_seq:
    adr_l   x1, tls_server_seq
    ldr     x0, [x1]
    add     x2, x0, #1
    str     x2, [x1]
    ret
