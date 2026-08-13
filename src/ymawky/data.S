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
// Data: shared server-loop state
//
// Description: Data shared between the accept loop (main.S) and the
//   connection handler (child.S). Everything else in the original
//   ymawky.S data section was single-user and lives with its function.
//
// Exported Symbols:
//   one — constant 1 used by setsockopt() (SO_REUSEADDR, SO_NOSIGPIPE)
// ─────────────────────────────────────────────────────────────────────

.data
.align 2 // one is a .word (4 bytes)
one: .word 1

.global one
