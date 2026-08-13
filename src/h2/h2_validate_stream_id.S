// This file is part of ymawky.
// Copyright (C) 2026 imtomt
//
// ymawky is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// ymawky is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ymawky. If not, see <https://www.gnu.org/licenses/>.

#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: h2_validate_stream_id
//
// Description: Reject the three classes of bad client stream id (RFC
//   9113 §5.1.1):
//     - zero, which is reserved for connection-level frames
//     - even numbers, which belong to server-initiated streams
//     - a brand-new stream id that does not exceed every client stream
//       id the connection has already seen
//   All three are PROTOCOL_ERROR connection errors. Existing streams
//   keep their id, so frames addressed to a live stream are unaffected
//   by the high-water mark.
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — connection state
//
// Output/Returns:
//   x0 — 0 on success (carry clear)
//   x0 = H2_ERR_PROTOCOL_ERROR on failure (carry set)
//
// Clobbered Registers:
//   x0-x5, x9, x30 (saved/restored)
//
// Stack Usage:
//   16 bytes: str x30, [sp, #-16]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_validate_stream_id
h2_validate_stream_id:
    str x30, [sp, #-16]!   // save our return address — find clobbers x30
    ldr w4, [x0, #H2F_STREAM_ID]
    cbz w4, .Lh2_bad_stream_id
    tst w4, #1
    b.eq .Lh2_bad_stream_id
    ldr w5, [x1, #H2C_LAST_STREAM_ID]
    mov x0, x4
    bl h2_stream_find
    cbnz x0, .Lh2_ok_stream_id // exists — nothing to check
    cmp w4, w5                   // new stream must increase (§5.1.1)
    b.ls .Lh2_bad_stream_id
.Lh2_ok_stream_id:
    ldr x30, [sp], #16    // restore the return address
    cmn xzr, xzr
    mov x0, #0
    ret
.Lh2_bad_stream_id:
    ldr x30, [sp], #16    // restore the return address
    cmp xzr, xzr
    mov x0, #H2_ERR_PROTOCOL_ERROR
    ret
