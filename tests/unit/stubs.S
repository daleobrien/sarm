// Stub symbols for unit testing — provides minimal definitions for
// symbols that the tested .S files reference from other source files
// that we don't want to fully link.
// This file is part of ymawky.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only

#include "defs.S"

// ── stubs for embedded.S (lookup_embedded in file.S needs these) ───

.data
.align 3

// One empty entry (80 bytes) so lookup_embedded always returns not-found.
embedded_files:
    .skip 80

embedded_count:
    .quad 0

.global embedded_files
.global embedded_count

// ── stubs for header.S (L400/L403/L414/L500 in parse.S need this) ──

.text
.align 2

// reply_status is called by error paths in parse.S and file.S.
// Our tests shouldn't hit error paths, but the linker needs the symbol.
// We provide a stub that just returns (tests don't exercise error paths).
reply_status:
    ret

.global reply_status

// handle_fs_error — called by error paths in file/get code
handle_fs_error:
    ret

.global handle_fs_error

// build_header — called by get.S via reply_status
build_header:
    mov x0, #0
    ret

.global build_header

// header_buf — needed by build_header and reply_status.
// Tests won't use it but linker needs it.
.bss
.align 3
header_buf:
    .skip 512

.global header_buf
