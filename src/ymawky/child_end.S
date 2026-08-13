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
// Function Name: child_end
//
// Description: End of connection handling. Records the request end
//   timestamp in req_end, logs "Took: Nµs\n" via log_timing, closes the
//   client socket, closes file_des if it's open, and loops back to
//   accept the next connection.
//
// Input/Arguments:
//   (none)
//
// Output/Returns:
//   (never returns — branches to loop)
//
// Clobbered Registers:
//   x0, x1, x8 (syscall scratch; log_timing clobbers its own)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global child_end
child_end:
    // record end time for request timing log
    SCWINUM SYS_gettimeofday
    adr_l x0, req_end
    mov x1, #0
    SCWISVC
    SCERR

    // compute elapsed and write "Took: Nµs\n" to stdout
    bl log_timing

    // close(clientfd)
    SCWINUM SYS_close
    ldr_l x0, clientfd
    SCWISVC
    SCERR

    ldr_l x0, file_des
    cmn x0, #1
    b.eq 1f
    SCWINUM SYS_close
    // x0 is set
    SCWISVC
    SCERR
1:
    // loop back to accept the next connection instead of exiting
    b loop
