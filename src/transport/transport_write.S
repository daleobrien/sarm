#include "../defs.S"

.extern raw_write_all
.extern tls_app_data_write
.extern memcpy

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_write_now
//
// Description: The unbuffered transport write primitive — this is what
//   transport_write was before the write-side staging went in front of
//   it, unchanged, and it is still what actually reaches the wire.
//   Writes content to a
//   file descriptor, retrying partial writes until all nbytes are
//   written. Dispatches on the runtime `transport_mode`:
//   TRANSPORT_PLAIN tail-calls raw_write_all
//   directly; TRANSPORT_TLS chunks the input into pieces of at most
//   TLS_MAX_PLAINTEXT bytes, seals each with tls_app_data_write into
//   tls_write_record_buf, and sends the sealed record with
//   raw_write_all before sealing the next chunk — an ordinary large
//   H2 response body becomes a short run of application_data records
//   this way, transparently to every existing caller (write_all,
//   h2_send_goaway, etc.).
//
// Input/Arguments:
//   x0 -> file descriptor (same as write() syscall)
//   x1 -> buffer
//   x2 -> nbytes
//
// Output/Returns:
//   x0 -> total number of bytes written on success (carry clear)
//   x0 -> errno / TLS_RECORD_ERR_* on failure (carry set)
//
// Clobbered Registers:
//   x0-x12, x16, x19-x24, x30 (x19-x24, x30 saved/restored), v0-v7,
//   v16-v30, NZCV — a superset covering both paths (raw_write_all only
//   touches x0-x2/x9/x25/x26; the TLS path additionally uses
//   everything tls_app_data_write clobbers)
//
//   The vector half reaches v30, not v21: v22-v28 are the H^2..H^4 GHASH
//   subkey powers and their rolled cross terms, v29-v30 the Karatsuba
//   accumulators in .Lgcm_ghash_run. This said v16-v21 because it was
//   written before the 4-block GHASH and never widened with it; v8-v11
//   was wrong the other way, since AAPCS64 makes d8-d15 callee-saved and
//   nothing on either path touches them.
//
// Stack Usage:
//   64 bytes: x19-x24, x30 (padded) — only used by the TLS path;
//   raw_write_all carries its own 16-byte frame for the PLAIN path.
//   x23 (this chunk's plaintext length) has to be a register that
//   survives across *two* further calls (tls_app_data_write, then
//   raw_write_all) rather than the usual caller-scratch x9/x10 —
//   raw_write_all's own doc header lists x9 as one of the registers
//   it clobbers, so x9 does not survive that second call.
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC transport_write_now
    ldr_l   x9, transport_mode
    cbnz    x9, .Ltransport_write_tls
    b       raw_write_all
.Ltransport_write_tls:
    sub     sp, sp, #64
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    mov     x19, x0             // fd
    mov     x20, x1             // cursor
    mov     x21, x2             // bytes remaining
    mov     x22, #0             // total sealed and sent so far

.Ltw_tls_loop:
    cbz     x21, .Ltw_tls_done
    mov     x23, #TLS_MAX_PLAINTEXT
    cmp     x21, x23
    csel    x23, x21, x23, lo   // chunk = min(remaining, TLS_MAX_PLAINTEXT)

    mov     x0, x20
    mov     x1, x23
    adr_l   x2, tls_write_record_buf
    bl      tls_app_data_write
    b.cs    .Ltw_tls_fail
    mov     x24, x0             // sealed record length

    mov     x0, x19
    adr_l   x1, tls_write_record_buf
    mov     x2, x24
    bl      raw_write_all
    b.cs    .Ltw_tls_fail

    add     x20, x20, x23
    sub     x21, x21, x23
    add     x22, x22, x23
    b       .Ltw_tls_loop

.Ltw_tls_done:
    cmn     xzr, xzr            // success — carry clear
    mov     x0, x22
.Ltw_tls_ret:
    ldr     x30, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #64
    ret
.Ltw_tls_fail:
    // x0 already holds the failing call's error code; carry is
    // already set by the b.cs we fell through from.
    b       .Ltw_tls_ret
ENDFUNC transport_write_now


// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_flush
//
// Description: Put whatever transport_write has staged on the wire, as
//   one write (in TRANSPORT_TLS, sealed as one record), and empty the
//   stage. A no-op when nothing is staged, which is the common case at
//   most of its call sites, so it is cheap to call defensively.
//
//   Safe to drop anywhere: it saves x19-x24 as well as x30, so unlike
//   transport_write_now it does not disturb a caller's callee-saved
//   registers. That is what lets transport_read call it mid-loop with
//   its own cursor and count live in x19-x22.
//
// Input/Arguments:
//   x0 -> file descriptor
//
// Output/Returns:
//   x0 -> bytes flushed on success (carry clear), 0 if nothing was
//         staged; errno / TLS_RECORD_ERR_* on failure (carry set)
//
// Clobbered Registers:
//   x0-x12, x16, v0-v7, v16-v30, NZCV (x19-x24, x30 saved/restored)
//
// Stack Usage:
//   64 bytes: x19-x24, x30 (padded)
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC transport_flush
    ldr_l   x9, write_stage_len
    cbz     x9, .Ltf_empty
    // Empty the stage *before* the write, not after. If the write
    // fails the connection is over; bytes left staged here would be
    // picked up by a later flush and put on the wire behind whatever
    // came after them, which is worse than losing them.
    str_l   xzr, write_stage_len, x10
    sub     sp, sp, #64
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    str     x30, [sp, #48]
    adr_l   x1, write_stage_buf
    mov     x2, x9                  // x0 (fd) is the caller's, untouched
    bl      transport_write_now
    ldr     x30, [sp, #48]          // none of these disturb NZCV, so the
    ldp     x23, x24, [sp, #32]     // carry transport_write_now set is
    ldp     x21, x22, [sp, #16]     // still ours to return
    ldp     x19, x20, [sp]
    add     sp, sp, #64
    ret
.Ltf_empty:
    mov     x0, #0
    cmn     xzr, xzr                // success — carry clear
    ret
ENDFUNC transport_flush


// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_write
//
// Description: The transport write primitive, as every caller sees it.
//   While transport_write_buffering is off this is exactly
//   transport_write_now and costs one branch; while it is on, the bytes
//   are copied into write_stage_buf and the call returns without a
//   syscall, and they go out on the next transport_flush.
//
//   Why. sarm answers one request per write syscall, and on an h2c
//   connection it answers about fifty of them per wakeup — the measured
//   0.02 context switches per request on a c6g.metal says the frame loop
//   parses that many requests out of one read() before it blocks again.
//   Every one of those responses paid its own el0_svc, its own
//   tcp_sendmsg_locked and, under TLS, its own AES-GCM record with a
//   16-byte tag and a GHASH setup that a 200-byte response cannot
//   amortise. Nothing needed those to be separate syscalls: the frames
//   are already sitting in memory with nowhere to be until the loop runs
//   dry. Staging them turns ~50 writes into one.
//
//   The kernel was already coalescing the *packets* — that is what Nagle
//   does on the h2 path, and removing it cost 64% of h2c throughput
//   (see the note in src/sarm/child.S). This coalesces the syscalls and
//   the TLS records, which Nagle cannot do for us, and does it in the
//   one place that knows when the batch has actually ended.
//
//   ORDERING. Everything that reaches the socket must go through here
//   (or through transport_writev, which stages into the same buffer), or
//   it will overtake bytes still staged. That is why the staging sits at
//   the transport seam rather than in the h2 layer: h2_send_goaway,
//   h2_send_rst_stream, h2_send_settings and the PING ACK writer all
//   funnel through write_all -> transport_write already, so they are
//   ordered correctly without knowing this exists.
//
//   DEADLOCK. Staged bytes must never still be staged while this end
//   blocks waiting for the peer. transport_read flushes before every
//   refill read, which covers every blocking read the connection makes;
//   child_end flushes before close(2) so the last response is not lost
//   with the socket.
//
// Input/Arguments:
//   x0 -> file descriptor (same as write() syscall)
//   x1 -> buffer
//   x2 -> nbytes
//
// Output/Returns:
//   x0 -> bytes written on success (carry clear); on the buffered path,
//         bytes *accepted* — they are on their way, not yet on the wire.
//         No caller in this tree distinguishes the two: they check the
//         carry and pass the count on, and write_all's contract was
//         already "all of it or an error".
//   x0 -> errno / TLS_RECORD_ERR_* on failure (carry set)
//
// Clobbered Registers:
//   x0-x12, x16, x19-x24, x30 (x19-x24, x30 saved/restored by the
//   callees), v0-v7, v16-v30, NZCV — unchanged from before, since the
//   unbuffered path is reached by a plain branch and the buffered one
//   calls only memcpy and transport_flush.
//
// Stack Usage:
//   32 bytes on the buffered path; the unbuffered path branches away
//   before touching the stack and carries transport_write_now's own.
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
FUNC transport_write
    ldr_l   x9, transport_write_buffering
    cbz     x9, transport_write_now     // buffering off — straight to the wire
    cbz     x2, .Ltw_buf_nothing

    ldr_l   x9, write_stage_len
    add     x10, x9, x2
    mov     x11, #WRITE_STAGE_SIZE
    cmp     x10, x11
    b.ls    .Ltw_buf_append             // fits behind what is already staged

    // Too big for the room left. Flush first — those bytes were written
    // before ours and have to leave first — then reconsider with an
    // empty stage.
    sub     sp, sp, #32
    stp     x0, x1, [sp]
    stp     x2, x30, [sp, #16]
    bl      transport_flush
    ldp     x2, x30, [sp, #16]
    b.cs    .Ltw_buf_flush_failed       // x0 = errno, carry set
    ldp     x0, x1, [sp]
    add     sp, sp, #32
    mov     x11, #WRITE_STAGE_SIZE
    cmp     x2, x11
    b.hi    transport_write_now         // larger than the stage will ever
                                        // hold — send it straight through
    mov     x9, #0                      // the stage is empty now
    b       .Ltw_buf_append

.Ltw_buf_flush_failed:
    add     sp, sp, #32                 // add does not touch NZCV
    ret

.Ltw_buf_append:
    // memcpy(write_stage_buf + x9, x1, x2), keeping x2 and the offset
    sub     sp, sp, #32
    stp     x2, x30, [sp]
    str     x9, [sp, #16]
    adr_l   x0, write_stage_buf
    add     x0, x0, x9                  // x1 (src) and x2 (n) are already set
    bl      memcpy
    ldp     x2, x30, [sp]
    ldr     x9, [sp, #16]
    add     sp, sp, #32
    add     x9, x9, x2
    str_l   x9, write_stage_len, x10
    mov     x0, x2                      // bytes accepted
    cmn     xzr, xzr                    // success — carry clear
    ret

.Ltw_buf_nothing:
    mov     x0, #0
    cmn     xzr, xzr                    // success — carry clear
    ret
ENDFUNC transport_write
