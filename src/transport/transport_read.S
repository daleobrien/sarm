#include "../defs.S"

.extern tls_read_record
.extern tls_app_data_read

// ─────────────────────────────────────────────────────────────────────
// Function Name: transport_read
//
// Description: The transport read primitive. Reads exactly len bytes
//   from the fd into buf. Dispatches on the runtime `transport_mode`
//   (PLAN.MD §1.3, Phase 20): TRANSPORT_PLAIN stages whatever one real
//   read() returns in plain_read_stage_buf and serves callers out of
//   it across as many calls as it takes (Plan.md Phase 2, Step 10);
//   TRANSPORT_TLS decrypts application_data records (tls_read_record +
//   tls_app_data_read) into tls_read_stage_buf and serves callers out
//   of that staged plaintext the same way, pulling and decrypting a
//   fresh record whenever its stage buffer runs dry. Neither a raw
//   read() nor a decrypted record lines up with exactly what one
//   caller asked for (H2 in particular reads a 9-byte frame header,
//   then the payload length that header names, neither of which is a
//   whole read() or a whole TLS_MAX_PLAINTEXT record) — staging
//   amortizes that mismatch to well under one syscall per span instead
//   of exactly one. Any non-application_data record on the TLS side
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
//   x0-x14, x16, x19-x24, x30 (x19-x24, x30 saved/restored), v0-v11,
//   v16-v21, NZCV — a superset covering both paths (the PLAIN path
//   only touches x0-x2/x9-x14/x16/x19-x22; the TLS path additionally
//   uses everything tls_read_record/tls_app_data_read clobber)
//
// Stack Usage:
//   48 bytes: x19-x22, x30 (padded) — shared by both paths
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global transport_read
transport_read:
    ldr_l   x9, transport_mode
    cbnz    x9, .Ltransport_read_tls

    // ── TRANSPORT_PLAIN: stage one real read()'s worth of bytes and
    //    serve callers out of it, refilling whenever it runs dry ──
    sub     sp, sp, #48
    stp     x19, x20, [sp]
    stp     x21, x22, [sp, #16]
    str     x30, [sp, #32]
    mov     x19, x0             // fd
    mov     x20, x1             // caller's buffer (cursor)
    mov     x21, x2             // bytes still wanted

.Ltr_plain_loop:
    cbz     x21, .Ltr_plain_done

    ldr_l   x9, plain_read_stage_len
    ldr_l   x10, plain_read_stage_pos, x13
    subs    x22, x9, x10        // bytes staged and unread
    b.gt    .Ltr_plain_drain

    // stage buffer empty — one real (not "exact") read() off the wire
    SCWINUM SYS_read
    mov     x0, x19
    adr_l   x1, plain_read_stage_buf
    mov     x2, #16384
    SCWISVC
    SCERR
    b.cs    .Ltr_plain_ioerr
    cbz     x0, .Ltr_plain_eof

    adr_l   x9, plain_read_stage_len
    str     x0, [x9]
    adr_l   x9, plain_read_stage_pos
    str     xzr, [x9]
    b       .Ltr_plain_loop

.Ltr_plain_drain:
    // copy min(x21 wanted, x22 staged) bytes from the stage buffer
    cmp     x21, x22
    csel    x9, x21, x22, lo    // x9 = bytes to copy this round
    ldr_l   x10, plain_read_stage_pos, x13  // explicit scratch — x9 must survive
    adr_l   x11, plain_read_stage_buf
    add     x11, x11, x10       // source = stage_buf + pos
    mov     x12, #0
.Ltr_plain_copy_loop:
    cmp     x12, x9
    b.eq    .Ltr_plain_copy_done
    ldrb    w13, [x11, x12]
    strb    w13, [x20, x12]
    add     x12, x12, #1
    b       .Ltr_plain_copy_loop
.Ltr_plain_copy_done:
    add     x20, x20, x9
    sub     x21, x21, x9
    add     x10, x10, x9
    adr_l   x14, plain_read_stage_pos
    str     x10, [x14]
    b       .Ltr_plain_loop

.Ltr_plain_done:
    cmn     xzr, xzr            // success — carry clear
    mov     x0, #0
    b       .Ltr_plain_ret
.Ltr_plain_ioerr:
    cmp     x0, #EINTR
    b.eq    .Ltr_plain_loop     // nothing was consumed — retry the read
    cmp     xzr, xzr            // failure — carry set
    b       .Ltr_plain_ret
.Ltr_plain_eof:
    mov     x0, #0
    cmp     xzr, xzr            // failure — carry set
.Ltr_plain_ret:
    ldr     x30, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp]
    add     sp, sp, #48
    ret

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
