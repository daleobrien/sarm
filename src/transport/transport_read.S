#include "../defs.S"

.extern raw_read_exact
.extern tls_read_record
.extern tls_app_data_read

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_read
//
// Description: The transport read primitive. Reads exactly len bytes
//   from the fd into buf. Dispatches on the runtime `transport_mode`
//   (PLAN.MD §1.3, Phase 20): TRANSPORT_PLAIN tail-calls
//   raw_read_exact directly; TRANSPORT_TLS decrypts application_data
//   records (tls_read_record + tls_app_data_read) into
//   tls_read_stage_buf and serves callers out of that staged plaintext
//   across as many calls as it takes, pulling and decrypting a fresh
//   record whenever the stage buffer runs dry — a decrypted record
//   essentially never lines up with exactly what one caller asked for
//   (H2 in particular reads a 9-byte frame header, then the payload
//   length that header names, neither of which is a whole
//   TLS_MAX_PLAINTEXT record). Any non-application_data record
//   (alerts, a stray handshake message) or a decrypt failure closes
//   the read side with carry set — this server does not support TLS
//   renegotiation, key updates, or post-handshake messages of any
//   kind (PLAN.MD Phase 20 scope).
//
// Input/Arguments:
//   x0 — fd, x1 — buffer, x2 — length
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 — errno / TLS_RECORD_ERR_* on failure (carry set); 0 on EOF
//
// Clobbered Registers:
//   x0-x12, x19-x24, x30 (x19-x24, x30 saved/restored), v0-v7,
//   v16-v21, NZCV — a superset covering both paths (raw_read_exact
//   only touches x0-x4/x9/x19-x21; the TLS path additionally uses
//   everything tls_read_record/tls_app_data_read clobber)
//
// Stack Usage:
//   48 bytes: x19-x22, x30 (padded) — only used by the TLS path;
//   raw_read_exact carries its own 32-byte frame for the PLAIN path
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global transport_read
transport_read:
    ldr_l   x9, transport_mode
    cbnz    x9, .Ltransport_read_tls
    b       raw_read_exact
.Ltransport_read_tls:
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x19, x0             // fd
    mov     x20, x1             // caller's buffer (cursor)
    mov     x21, x2             // bytes still wanted

.Ltr_tls_loop:
    cbz     x21, .Ltr_tls_done

    // ldr_l's default scratch register is x9 — an explicit, distinct
    // scratch (x13) on the second call keeps it from clobbering the
    // first call's result before the subs below reads it.
    ldr_l   x9, tls_read_stage_len
    ldr_l   x10, tls_read_stage_pos, x13
    subs    x22, x9, x10        // bytes staged and unread
    b.gt    .Ltr_tls_drain

    // stage buffer empty — pull and decrypt the next record
    mov     x0, x19
    adr_l   x1, tls_read_raw_buf
    mov     x2, #16448
    bl      tls_read_record
    b.cs    .Ltr_tls_fail
    cmp     x0, #TLS_RECORD_APPLICATION_DATA
    b.ne    .Ltr_tls_fail_generic
    mov     x9, x3              // total record length

    adr_l   x0, tls_read_raw_buf
    mov     x1, x9
    adr_l   x2, tls_read_stage_buf
    bl      tls_app_data_read
    b.cs    .Ltr_tls_fail
    cmp     x1, #TLS_RECORD_APPLICATION_DATA
    b.ne    .Ltr_tls_fail_generic

    adr_l   x9, tls_read_stage_len
    str     x0, [x9]
    adr_l   x9, tls_read_stage_pos
    str     xzr, [x9]
    b       .Ltr_tls_loop

.Ltr_tls_drain:
    // copy min(x21 wanted, x22 staged) bytes from the stage buffer
    cmp     x21, x22
    csel    x9, x21, x22, lo    // x9 = bytes to copy this round
    ldr_l   x10, tls_read_stage_pos, x13  // explicit scratch — x9 must survive
    adr_l   x11, tls_read_stage_buf
    add     x11, x11, x10       // source = stage_buf + pos
    mov     x12, #0
.Ltr_tls_copy_loop:
    cmp     x12, x9
    b.eq    .Ltr_tls_copy_done
    ldrb    w13, [x11, x12]
    strb    w13, [x20, x12]
    add     x12, x12, #1
    b       .Ltr_tls_copy_loop
.Ltr_tls_copy_done:
    add     x20, x20, x9
    sub     x21, x21, x9
    add     x10, x10, x9
    adr_l   x14, tls_read_stage_pos
    str     x10, [x14]
    b       .Ltr_tls_loop

.Ltr_tls_done:
    cmn     xzr, xzr            // success — carry clear
    mov     x0, #0
    b       .Ltr_tls_ret
.Ltr_tls_fail_generic:
    mov     x0, #TLS_RECORD_ERR_TYPE
.Ltr_tls_fail:
    cmp     xzr, xzr            // failure — carry set
.Ltr_tls_ret:
    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret
