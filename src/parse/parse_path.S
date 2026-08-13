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
// Function Name: parse_path
//
// Description: Extract the requested filename from a raw HTTP request
//   line ("GET /foo/bar HTTP/1.1"). The path is copied into filename_buf
//   prefixed with the docroot, consecutive slashes are collapsed, and a
//   query string (everything after the first '?') is copied raw into
//   query_buf. If the path is empty, the default filename (index.html)
//   is appended when x2 is true; otherwise the bare docroot is used.
//
// Input/Arguments:
//   x0 -> HTTP header from client ("GET /...")
//   x1 -> length of header
//   x2 -> boolean: 1 = default to "index.html", 0 = no default filename
//
// Output/Returns:
//   x0 -> string containing the requested file name
//   x1 -> length of said file name
//   (x2/x3 also carry the query pointer/length — see the Lparse_end block)
//
// Clobbered Registers:
//   x0-x5, x20-x25, x29, x30 (x20-x25 saved and restored)
//
// Stack Usage:
//   80 bytes: stp x29, x30, [sp, #-64]! plus a 16-byte
//   stp x0, x1, [sp, #-16]! pair around the memcpy call
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global parse_path
parse_path:
    // preserve link register so we can bl to other functions properly
    stp x29, x30, [sp, #-64]!
    stp x20, x21, [sp, #16]
    stp x22, x23, [sp, #32]
    stp x24, x25, [sp, #48]

    mov x22, x1 // save header length in x22
    mov x20, x2 // save bool option in x20.

    cmp x22, #16 // make sure the header is at least 16 bytes long
    b.lo L400

    mov x25, #0
    mov x23, #0
    mov x2, #1 // just has to be non-null, previous byte to make sure a space
               // precedes the '/'

// this is basically strchr
Lstrchr_loop:
    // load the current byte at the string pointer, and check if it's /
    ldrb w3, [x0]
    cmp w3, #'/'
    b.eq Lchar_found
    cmp w3, #'*'
    b.eq Lchar_found

    // if we haven't reached a / in the first 16 bytes, we'll fail
    cmp x23, #16
    b.eq Lno_match

    // if we reached a NULL byte in the first 16 bytes, it's definitely a
    // weird request header. so, let's just fail.
    cmp w3, #0
    b.eq Lno_match

    // if we got here, we gotta loop again. < 16 bytes in, no / reached, and no
    // NULL byte reached. increment string index and loop
    add x0, x0, #1 // increment the string pointer
    add x23, x23, #1 // increment the byte counter so we can quit at 16 bytes
    
    // save previous byte so we can check for preceding ' '
    mov w2, w3
    b Lstrchr_loop

// If we got here, we found a '/' or '*'. let's make sure the preceding byte,
// stored in x2, is a ' ' so we only match ' /' or ' *'. that way we avoid
// 'HTTP/1.1' "matching".
Lchar_found:
    cmp w2, #' '
    b.ne Lno_match

    // if / is the last char in the header, it's deffo malformed.
    add x23, x23, #1
    cmp x23, x22
    b.hi Lno_match

    cmp w3, #'*'
    b.eq Lasterisk

    add x0, x0, #1 // skip past the '/' which we're currently on

    // load in filename_buf to x1
    adr_l x1, filename_buf

    // gotta save x0 and x1, since memcpy changes the pointers
    stp x0, x1, [sp, #-16]!
    mov x0, x1
    adr_l x1, www_prefix
    mov x2, www_prefix_len
    bl memcpy
    ldp x0, x1, [sp], #16

    // zero out x2, which is used as both an index into filename_buf and as a
    // relative index (x2 + 4, to skip the starting "GET ") into the header
    mov x2, #0
    mov x4, www_prefix_len
    mov x24, #1 // x24 = is the last processed a slash? here, it is
Lfilename_loop:
    cmp x4, filename_buf_size // bounds check
    b.ge L414

    ldrb w3, [x0, x2] // load byte from header+index
    cbz w3, Lno_match // is it NULL? go to 4f if it is

    cmp w3, #' ' // is it a space?
    b.eq Lfilename_done // we're done once we reach a space

    cmp w3, #'\r'
    b.eq Lno_match

    cmp w3, #'\n'
    b.eq Lno_match

    // if x25 is set, that indicates that we've reached a ?. if we reached a ?,
    // we want to copy the rest of the URL exactly -- don't collapse multiple
    // slashes into a single slash. so just skip this block if x25 is set.
    cbnz x25, 1f
    cmp w3, #'/'
    b.eq Lslash
    mov x24, #0 // 0 means last char was not a slash, 1 means last char was
1:

    cmp w3, #'?' // is it a ? ?? we'll use that for query string.
    b.ne 1f
    cbnz x25, 1f // if x25 is already set, ignore it. query can have multiple ?
    // set x25 to the index immediately after the ?. we don't want the literal
    // first ? to appear in query_buf, so we add 1 to x4 to skip it
    add x25, x4, #1
1:
    // ok, we're not done
    strb w3, [x1, x4] // copy byte to filename_buf+index
    add x4, x4, #1 // increment the filename index
    add x2, x2, #1 // increment the header index
    add x23, x23, #1 // increment the total index

2:
    // bounds check!
    cmp x23, x22
    b.hi Lno_match

    b Lfilename_loop

// strip multiple /'s into a single /
Lslash:
    cmp x24, #0
    b.eq 3f

    // if the previous char was a slash, just skip this one
    mov x24, #1 // set x24 to mark we processed a slash
    add x2, x2, #1 // advance header index
    add x23, x23, #1 // advance total counter
    b 2b
3:
    // if the last char was not a slash, mark this char as being one, and copy
    // anyway.
    mov x24, #1
    b 1b

Lfilename_done:
    // is the length the same as the www/ prefix? if it is, we didn't actually
    // get a file.
    mov x5, www_prefix_len
    cmp x4, x5
    b.eq Lempty_filename

    strb wzr, [x1, x4] // null-terminate filename_buf
    mov x0, x1 // we want x0 to point to the filename string
    mov x1, x4 // x1 is the length of the filename
    b Lparse_end

Lempty_filename:
    mov x5, x1 // save filename_buf in x5
    mov x2, www_prefix_len

    // the default file name, "index.html", is only for GET requests. if it's a
    // DELETE/PUT/POST/anything else, just "www/" is enough. we'll let the
    // system handle the error elsewhere if it causes problems.
    cbz x20, Lno_default_file

    adr_l x0, filename_buf
    // skip past the www/
    add x0, x0, x2

    adr_l x1, default_file
    mov x2, default_file_len
    bl memcpy

    strb wzr, [x0] // null terminate

    mov x0, x5
    mov x1, www_prefix_len
    mov x2, default_file_len
    add x1, x1, x2

    b Lparse_end
Lno_default_file:
    mov x0, x5
    mov x1, www_prefix_len
    b Lparse_end

Lasterisk:
    // bounds check yuck
    add x23, x23, #1
    cmp x23, x22
    b.hi L400

    // make sure the next char is a space -- "OPTIONS *foo" is invalid"
    ldrb w2, [x0, #1]
    cmp w2, #' '
    b.ne L400

   // store * as the filename
    adr_l x0, filename_buf
    str w3, [x0]
    strb wzr, [x0, #1]

    // x0 is already set
    mov x1, #1 // filename is just one byte
    b Lparse_end

// no match was when we were parsing the header for request type. since we cant
// find a file without a /, just return NULL
Lno_match:
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    cmp xzr, xzr
    b Lparse_epilogue

Lparse_end:
    // set query string/len to 0 by default, but may be overwritten
    mov x2, #0
    mov x3, #0

    cbz x25, 9f // if x25 is NULL, just skip straight to the end

    // otherwise, we have to extract the parse string now.
    mov x20, x0 // save x0
    mov x21, x1 // and x1
    // x22 points at the index that contains the ?, rather than one-past it
    ;mov x22, x25
    sub x22, x25, #1

    adr_l x0, filename_buf
    adr_l x2, query_buf
1:
    // x25 is index into filename where ? appears, from earlier in parse_path
    cmp x25, x21 // x21 is length of filename from parse_path
    b.hs 2f

    cmp x3, query_buf_size
    b.hs L414

    ldrb w1, [x0, x25]
    strb w1, [x2, x3]
    strb wzr, [x0, x25] // now make that NULL in filename_str

    add x25, x25, #1
    add x3, x3, #1
    b 1b

2:
    mov x0, x20 // restore x0
    strb wzr, [x0, x22] // NULL the ? in filename
    ;mov x1, x21 // and x1
    ;sub x1, x21, x25 // filename length = total length - query string offset
    mov x1, x22
9:
qsrchdone:
    cmn xzr, xzr // clear carry in case. it gets set in the other error paths.
Lparse_epilogue:
parsebp:
    // restore the link register and ret
    ldp x24, x25, [sp, #48]
    ldp x22, x23, [sp, #32]
    ldp x20, x21, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

// trampolines for conditional branches to reply_* in errors.S (which is too
// far for b.cond / cbz to reach directly).
L400:
    mov x0, #400
    mov x1, #0
    b reply_status
L414:
    mov x0, #414
    mov x1, #0
    b reply_status
