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
// Function Name: h2_validate_frame
//
// Description: Reject frames that violate RFC 9113 §4.2: a payload
//   length above the 24-bit wire limit, or above the frame size this
//   endpoint is willing to receive (H2C_MAX_RX_FRAME_SIZE, 2^14 by
//   default). Both are FRAME_SIZE_ERROR connection errors.
//
// Input/Arguments:
//   x0 — parsed frame header
//   x1 — connection state
//
// Output/Returns:
//   x0 — 0 on success, H2_ERR_FRAME_SIZE_ERROR on failure
//   carry set on failure
//
// Clobbered Registers:
//   x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global h2_validate_frame
h2_validate_frame:
    ldr w2, [x0, #H2F_LENGTH]

    // absolute wire limit: the 24-bit length field caps at 2^24 - 1
    mov w3, #H2_MAX_FRAME_SIZE
    cmp w2, w3
    b.hi .Lh2_frame_size_error

    // what we're willing to receive (our own SETTINGS_MAX_FRAME_SIZE)
    ldr w3, [x1, #H2C_MAX_RX_FRAME_SIZE]
    cmp w2, w3
    b.hi .Lh2_frame_size_error

    cmn xzr, xzr // success — carry clear
    mov x0, #0
    ret

.Lh2_frame_size_error:
    cmp xzr, xzr // failure — carry set
    mov x0, #H2_ERR_FRAME_SIZE_ERROR
    ret
