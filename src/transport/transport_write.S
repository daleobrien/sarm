#include "../defs.S"

.extern raw_write_all
.extern tls_app_data_write

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_write
//
// Description: The transport write primitive. Writes content to a
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
FUNC transport_write
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
ENDFUNC transport_write
