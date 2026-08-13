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
// Function Name: h2_stream_find
//
// Description: Linear scan of the fixed stream table (h2_streams) for
//   a stream id. 32 entries is small and the scan only runs per frame,
//   so a hash table is not worth it yet (RFC 9113 §5.1).
//
// Input/Arguments:
//   x0 — stream id
//
// Output/Returns:
//   x0 — stream entry, or 0 if the stream is not in the table
//   carry clear = success (not found is a valid result, not an error)
//
// Clobbered Registers:
//   x0, x2, x3, x9
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_stream_find
h2_stream_find:
    adr_l x9, h2_streams
    mov x2, #H2_MAX_STREAMS
.Lh2_find_loop:
    ldr x3, [x9]           // this entry's stream id
    cmp x3, x0
    b.eq .Lh2_find_hit
    add x9, x9, #H2S_SIZE
    subs x2, x2, #1
    b.ne .Lh2_find_loop
    mov x0, #0             // not found
    cmn xzr, xzr           // success — carry clear
    ret
.Lh2_find_hit:
    mov x0, x9
    cmn xzr, xzr
    ret
