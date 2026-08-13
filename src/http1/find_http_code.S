#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: find_http_code
//
// Description: Look up an HTTP status code in the status_table and
//   return the matching status-line string and its length. Returns
//   0/0 when the code is not in the table. The status-line strings
//   (header_200 … header_507) and status_table live in this file;
//   header_500/header_500_len are exported for http1_write_response's
//   "unknown status" fallback.
//
// Input/Arguments:
//   x0 — status code
//
// Output/Returns:
//   x1 — string pointer (0 if not found)
//   x2 — length (0 if not found)
//
// Clobbered Registers:
//   x1, x2, x3, x4
//
// Stack Usage:
//   none
// ─────────────────────────────────────────────────────────────────────

.data
header_200: .ascii "HTTP/1.1 200 OK"
.equ header_200_len, . - header_200

header_201: .ascii "HTTP/1.1 201 Created"
.equ header_201_len, . - header_201

header_204: .ascii "HTTP/1.1 204 No Content"
.equ header_204_len, . - header_204

header_206: .ascii "HTTP/1.1 206 Partial Content"
.equ header_206_len, . - header_206

header_400: .ascii "HTTP/1.1 400 Bad Request"
.equ header_400_len, . - header_400

header_403: .ascii "HTTP/1.1 403 Forbidden"
.equ header_403_len, . - header_403

header_404: .ascii "HTTP/1.1 404 Not Found"
.equ header_404_len, . - header_404

header_408: .ascii "HTTP/1.1 408 Request Timeout"
.equ header_408_len, . - header_408

header_409: .ascii "HTTP/1.1 409 Conflict"
.equ header_409_len, . - header_409

header_411: .ascii "HTTP/1.1 411 Length Required"
.equ header_411_len, . - header_411

header_413: .ascii "HTTP/1.1 413 Content Too Large"
.equ header_413_len, . - header_413

header_414: .ascii "HTTP/1.1 414 URI Too Long"
.equ header_414_len, . - header_414

header_416: .ascii "HTTP/1.1 416 Range Not Satisfiable"
.equ header_416_len, . - header_416

header_418: .ascii "HTTP/1.1 418 I'm a teapot"
.equ header_418_len, . - header_418

header_431: .ascii "HTTP/1.1 431 Request Header Fields Too Large"
.equ header_431_len, . - header_431

.global header_500
header_500: .ascii "HTTP/1.1 500 Internal Server Error"
.equ header_500_len, . - header_500
.global header_500_len

header_501: .ascii "HTTP/1.1 501 Not Implemented"
.equ header_501_len, . - header_501

header_502: .ascii "HTTP/1.1 502 Bad Gateway"
.equ header_502_len, . - header_502

header_503: .ascii "HTTP/1.1 503 Service Unavailable"
.equ header_503_len, . - header_503

header_505: .ascii "HTTP/1.1 505 HTTP Version Not Supported"
.equ header_505_len, . - header_505

header_507: .ascii "HTTP/1.1 507 Insufficient Storage"
.equ header_507_len, . - header_507

.align 3
// lookup table, like the MIME one, for headers. 24 bytes per entry, 8 bytes
// per each element
status_table:
    //    status, str pointer, length
    .quad 200,    header_200,  header_200_len
    .quad 201,    header_201,  header_201_len
    .quad 204,    header_204,  header_204_len
    .quad 206,    header_206,  header_206_len
    .quad 400,    header_400,  header_400_len
    .quad 403,    header_403,  header_403_len
    .quad 404,    header_404,  header_404_len
    .quad 408,    header_408,  header_408_len
    .quad 409,    header_409,  header_409_len
    .quad 411,    header_411,  header_411_len
    .quad 413,    header_413,  header_413_len
    .quad 414,    header_414,  header_414_len
    .quad 416,    header_416,  header_416_len
    .quad 418,    header_418,  header_418_len
    .quad 431,    header_431,  header_431_len
    .quad 500,    header_500,  header_500_len
    .quad 501,    header_501,  header_501_len
    .quad 502,    header_502,  header_502_len
    .quad 503,    header_503,  header_503_len
    .quad 505,    header_505,  header_505_len
    .quad 507,    header_507,  header_507_len

    .quad 0 // mark the end

.text
.align 2
// input
// x0 -> status code
//
// returns
// x1 -> string pointer
// x2 -> length
.global find_http_code
find_http_code:
    adr_l x3, status_table
1:
    // load the first element
    ldr x4, [x3]
    cbz x4, 3f

    // found the matching entry
    cmp x4, x0
    b.eq 2f

    // jump to the next entry
    add x3, x3, #24
    b 1b

2:
    ldr x1, [x3, #8]
    ldr x2, [x3, #16]
    ret

3:
    mov x1, #0
    mov x2, #0
    ret
