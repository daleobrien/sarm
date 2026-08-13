// Stub symbols for the Stage 2 response unit tests (test_response.c).
//
// test_response links the REAL header.S (http1_write_response,
// reply_status), get.S (create_response), parse.S, file.S, data.S, and
// util.S. Unlike stubs.S — which stubs out the header/get functions for
// the other test suites — this file only provides the symbols that would
// otherwise live in the embedded table (embedded.S) and in ymawky.S.
// This file is part of ymawky.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only

#include "defs.S"

// ── stubs for embedded.S (lookup_embedded in file.S needs these) ───

.data
.align 3

// One empty entry (80 bytes) so lookup_embedded always returns not-found.
// This means reply_status's error-page lookup never finds a page, which
// matches the current build (no www/err/ files are embedded).
embedded_files:
    .skip 80

embedded_count:
    .quad 0

.global embedded_files
.global embedded_count

// ── stub for ymawky.S (reply_status tails into child_end) ───────────

.text
.align 2

// child_end — normally in ymawky.S, where it closes the client fd, logs
// request timing, and exits the child process (so it never returns). The
// test calls reply_status with flag=1, which returns via its own frame
// instead of reaching this symbol; this stub only exists so the linker
// can resolve the `b child_end` in get/head/reply_status.
child_end:
    ret

.global child_end
