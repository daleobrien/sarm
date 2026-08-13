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
// Function Name: handle_fs_error
//
// Description: Handler for fstat64() failing. Routes to the proper HTTP
//   response based on errno.
//
// Input/Arguments:
//   x0 — errno
//
// Output/Returns:
//   none; branches to reply_status
//
// Clobbered Registers:
//   x0 (repurposed as the status code)
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// handler function for fstat64() failing. route to the proper HTTP reponse
// based on errno.
// TODO this should probably go in file.S?
// input
// x0 -> errno
//
// output
// none, branches to reply_status and quits.
.global handle_fs_error
handle_fs_error:
    cb eq, x0, #ENAMETOOLONG, L414
    cb eq, x0, #EINVAL, L400
    // 403 since it's caused by O_NOFOLLOW_ANY most likely. if we ever allow
    // symlinks, note that this should be 508.
    cb eq, x0, #ELOOP, L403
    cb eq, x0, #ENOTDIR, L404
    cb eq, x0, #ENOENT, L404
    cb eq, x0, #EACCES, L403
    cb eq, x0, #EPERM, L403
    cb eq, x0, #EROFS, L403
    cb eq, x0, #EISDIR, L403
    cb eq, x0, #EFAULT, L500
    cb eq, x0, #EBUSY, L409
    cb eq, x0, #ENOTEMPTY, L409
    cb eq, x0, #ENOSPC, L507
    cb eq, x0, #EDQUOT, L507
    cb eq, x0, #EFBIG, L413

    b L500

L400:
    mov x0, #400
    b reply_status
L403:
    mov x0, #403
    b reply_status
L404:
    mov x0, #404
    b reply_status
L409:
    mov x0, #409
    b reply_status
L413:
    mov x0, #413
    b reply_status
L414:
    mov x0, #414
    b reply_status
L500:
    mov x0, #500
    b reply_status
L507:
    mov x0, #507
    b reply_status
