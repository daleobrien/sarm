#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Data: transport module state
//
// Description: Shared state for the transport seam (transport_read /
//   transport_write).
//
// Exported Symbols:
//   transport_mode — the active transport (TRANSPORT_PLAIN /
//     TRANSPORT_TLS, see config.S). Initialised from the TRANSPORT_MODE
//     compile-time default, so PLAIN is the mode every connection starts
//     with; a future runtime switch can write this before any connection
//     I/O. transport_read/transport_write dispatch on it.
//   tls_read_raw_buf/tls_read_stage_buf/tls_read_stage_len/
//     tls_read_stage_pos — TRANSPORT_TLS read-side staging:
//     transport_read must hand back exactly the number of
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
//   transport_writev_scratch — TRANSPORT_TLS's fallback for
//     transport_writev (Plan.md Phase 2, Step 11): a TLS record has to
//     be sealed from one contiguous plaintext buffer, so the TLS branch
//     assembles the header + body here before handing the whole thing
//     to transport_write, exactly what a caller doing its own
//     copy-then-write_all did before transport_writev existed. Sized
//     for one full TLS_MAX_PLAINTEXT chunk plus the largest header part
//     h2_write_body can hand over: a 9-byte DATA frame header, behind a
//     staged HEADERS frame of at most H2_HEADERS_STAGE_MAX bytes.
// ─────────────────────────────────────────────────────────────────────

.data
.align 4
OBJECT transport_mode
                .quad TRANSPORT_MODE
ENDOBJ transport_mode

.align 4
OBJECT tls_read_stage_len
                    .quad 0
ENDOBJ tls_read_stage_len
OBJECT tls_read_stage_pos
                    .quad 0
ENDOBJ tls_read_stage_pos

.align 4
OBJECT tls_read_raw_buf
                  .skip 16448   // header(5) + TLS_MAX_PLAINTEXT + tag(16), rounded
ENDOBJ tls_read_raw_buf

.align 4
OBJECT tls_read_stage_buf
                    .skip 16384  // TLS_MAX_PLAINTEXT
ENDOBJ tls_read_stage_buf

// tls_write_record_buf — TRANSPORT_TLS write-side scratch: each
// transport_write call chunks its input into <= TLS_MAX_PLAINTEXT
// pieces, seals each into this buffer (tls_app_data_write needs an
// output buffer distinct from its plaintext input), and sends it with
// raw_write_all before sealing the next chunk.
.align 4
OBJECT tls_write_record_buf
                      .skip 16448  // header(5) + TLS_MAX_PLAINTEXT + tag(16), rounded
ENDOBJ tls_write_record_buf

.align 4
OBJECT plain_read_stage_len
                      .quad 0
ENDOBJ plain_read_stage_len
OBJECT plain_read_stage_pos
                      .quad 0
ENDOBJ plain_read_stage_pos

.align 4
OBJECT plain_read_stage_buf
                      .skip 16384
ENDOBJ plain_read_stage_buf

.align 4
OBJECT transport_writev_scratch
                          .skip 16672  // H2_HEADERS_STAGE_MAX(256) + header(9)
                                       // + TLS_MAX_PLAINTEXT(16384), rounded
ENDOBJ transport_writev_scratch
