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
// Function Name: h2_send_settings
//
// Description: Emit h2_settings_frame — the opening SETTINGS frame with
//   SETTINGS_HEADER_TABLE_SIZE = 0 (dynamic table disabled), valid as
//   the first frame of the server connection preface (§3.5, §6.5).
//   Delegates to write_all (util.S) so partial writes are completed.
//
// Input/Arguments:
//   x0 — client file descriptor
//
// Output/Returns:
//   x0 — bytes written (h2_settings_frame_len) on success (carry clear)
//   x0 — errno (EPIPE, ECONNRESET, ...) on failure (carry set)
//
// Clobbered Registers:
//   x0, x1, x2, x8, x16 (syscall registers; see write_all)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
// h2_settings_frame — the server's opening SETTINGS frame (RFC 9113
// §3.5, §6.5): SETTINGS_HEADER_TABLE_SIZE = 0 (§6.5.2) tells the client
// its HPACK encoder may not use a dynamic table, and (Stage 12)
// SETTINGS_MAX_CONCURRENT_STREAMS = 32 advertises how many concurrent
// streams this endpoint permits (§5.1.2). Our decoder is
// static-table-only (hpack module) and rejects any dynamic-table
// representation, so advertising the table-size limit up front lets
// conforming clients avoid the COMPRESSION_ERROR entirely.
h2_settings_frame:
    .byte 0x00, 0x00, 0x0c            // payload length (24-bit) = 12
    .byte H2_FRAME_SETTINGS           // type = SETTINGS
    .byte 0x00                        // flags = 0
    .byte 0x00, 0x00, 0x00, 0x00      // stream id = 0
    .byte 0x00, H2_SETTINGS_HEADER_TABLE_SIZE // identifier (16-bit BE)
    .byte 0x00, 0x00, 0x00, 0x00      // value = 0 — dynamic table disabled
    .byte 0x00, H2_SETTINGS_MAX_CONCURRENT_STREAMS
    .byte 0x00, 0x00, 0x00, MAX_CONCURRENT_STREAMS  // value = 32
.equ h2_settings_frame_len, . - h2_settings_frame

.text
.align 2
.global h2_settings_frame
.global h2_send_settings
h2_send_settings:
    adr_l x1, h2_settings_frame
    mov x2, #h2_settings_frame_len    // header + both SETTINGS entries
    b write_all
