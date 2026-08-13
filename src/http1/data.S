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
// Data: shared http1-module state
//
// Description: Buffer shared by the HTTP/1 response encoders
//   (http1_write_response, reply_status). The status-line strings and
//   status_table live in find_http_code.S (their only consumer); the
//   content-* header strings live in http1_write_response.S and the
//   error-page strings in reply_status.S. Length constants that are
//   needed as immediates across files live in defs.S.
//
// Exported Symbols:
//   header_buf — scratch the HTTP/1 encoder builds the header in
// ─────────────────────────────────────────────────────────────────────

.bss
.align 3
.equ header_buf_size, RESPONSE_HEADER_SIZE
header_buf:   .skip header_buf_size

.global header_buf
