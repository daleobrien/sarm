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
//   tls_read_raw_buf/tls_read_stage_buf/tls_read_stage_len/
//     tls_read_stage_pos — TRANSPORT_TLS read-side staging (PLAN.MD
//     Phase 20): transport_read must hand back exactly the number of
//     plaintext bytes its caller asked for, but a decrypted
//     application_data record rarely lines up with that exactly, so
//     one record's worth of plaintext is decrypted into
//     tls_read_stage_buf and doled out across as many transport_read
//     calls as it takes. tls_read_raw_buf holds the ciphertext record
//     (header + ciphertext + tag) each read pulls off the wire before
//     it's decrypted in place into the stage buffer.
//   plain_read_stage_buf/plain_read_stage_len/plain_read_stage_pos —
//     TRANSPORT_PLAIN read-side staging (Plan.md Phase 2, Step 10):
//     the same problem and the same fix as the TLS staging above, one
//     layer down — h2c's 9-byte frame headers and their payloads
//     essentially never line up with what one real read() returns, so
//     one read()'s worth of bytes is staged here and doled out across
//     as many transport_read calls as it takes, instead of costing a
//     syscall per span. h2_connection_loop resets len/pos to 0 at the
//     start of every connection (see its own comment) — under `no_fork`
//     the same process serves connection after connection, so a
//     previous connection's unread staged bytes must never leak into
//     the next one.
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
.global transport_mode
transport_mode: .quad TRANSPORT_MODE

.align 4
.global tls_read_stage_len
.global tls_read_stage_pos
tls_read_stage_len: .quad 0
tls_read_stage_pos: .quad 0

.align 4
.global tls_read_raw_buf
tls_read_raw_buf: .skip 16448   // header(5) + TLS_MAX_PLAINTEXT + tag(16), rounded

.align 4
.global tls_read_stage_buf
tls_read_stage_buf: .skip 16384  // TLS_MAX_PLAINTEXT

// tls_write_record_buf — TRANSPORT_TLS write-side scratch: each
// transport_write call chunks its input into <= TLS_MAX_PLAINTEXT
// pieces, seals each into this buffer (tls_app_data_write needs an
// output buffer distinct from its plaintext input), and sends it with
// raw_write_all before sealing the next chunk.
.align 4
.global tls_write_record_buf
tls_write_record_buf: .skip 16448  // header(5) + TLS_MAX_PLAINTEXT + tag(16), rounded

.align 4
.global plain_read_stage_len
.global plain_read_stage_pos
plain_read_stage_len: .quad 0
plain_read_stage_pos: .quad 0

.align 4
.global plain_read_stage_buf
plain_read_stage_buf: .skip 16384
