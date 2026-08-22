#include "../../defs.S"

rodata
.align 4
header_200: .ascii "HTTP/1.1 200 OK"
.equ header_200_len, . - header_200

.align 4
header_201: .ascii "HTTP/1.1 201 Created"
.equ header_201_len, . - header_201

.align 4
header_204: .ascii "HTTP/1.1 204 No Content"
.equ header_204_len, . - header_204

.align 4
header_206: .ascii "HTTP/1.1 206 Partial Content"
.equ header_206_len, . - header_206

.align 4
header_400: .ascii "HTTP/1.1 400 Bad Request"
.equ header_400_len, . - header_400

.align 4
header_403: .ascii "HTTP/1.1 403 Forbidden"
.equ header_403_len, . - header_403

.align 4
header_404: .ascii "HTTP/1.1 404 Not Found"
.equ header_404_len, . - header_404

.align 4
header_408: .ascii "HTTP/1.1 408 Request Timeout"
.equ header_408_len, . - header_408

.align 4
header_409: .ascii "HTTP/1.1 409 Conflict"
.equ header_409_len, . - header_409

.align 4
header_411: .ascii "HTTP/1.1 411 Length Required"
.equ header_411_len, . - header_411

.align 4
header_413: .ascii "HTTP/1.1 413 Content Too Large"
.equ header_413_len, . - header_413

.align 4
header_414: .ascii "HTTP/1.1 414 URI Too Long"
.equ header_414_len, . - header_414

.align 4
header_416: .ascii "HTTP/1.1 416 Range Not Satisfiable"
.equ header_416_len, . - header_416

.align 4
header_418: .ascii "HTTP/1.1 418 I'm a teapot"
.equ header_418_len, . - header_418

.align 4
header_431: .ascii "HTTP/1.1 431 Request Header Fields Too Large"
.equ header_431_len, . - header_431

.global header_500
.align 4
header_500: .ascii "HTTP/1.1 500 Internal Server Error"
.equ header_500_len, . - header_500
.global header_500_len

.align 4
header_501: .ascii "HTTP/1.1 501 Not Implemented"
.equ header_501_len, . - header_501

.align 4
header_502: .ascii "HTTP/1.1 502 Bad Gateway"
.equ header_502_len, . - header_502

.align 4
header_503: .ascii "HTTP/1.1 503 Service Unavailable"
.equ header_503_len, . - header_503

.align 4
header_505: .ascii "HTTP/1.1 505 HTTP Version Not Supported"
.equ header_505_len, . - header_505

.align 4
header_507: .ascii "HTTP/1.1 507 Insufficient Storage"
.equ header_507_len, . - header_507

.align 4
// lookup table, like the MIME one, for headers. 32 bytes per entry, 8 bytes
// per each element, 8 bytes padding — so every entry starts 16-aligned
//
// The middle element is the status line's offset from the table's own
// address, not its address: an absolute address here would be a
// load-time relocation, and the Linux build is a position-independent
// executable with no dynamic linker to apply one (docs/SECURITY.md
// Step 13). find_http_code adds the table base back.
.global status_table
status_table:
    //    status, str offset from status_table, length
    .quad 200,    (header_200 - status_table),  header_200_len
    .quad 0 // padding — 32-byte entries keep every entry 16-aligned
    .quad 201,    (header_201 - status_table),  header_201_len
    .quad 0
    .quad 204,    (header_204 - status_table),  header_204_len
    .quad 0
    .quad 206,    (header_206 - status_table),  header_206_len
    .quad 0
    .quad 400,    (header_400 - status_table),  header_400_len
    .quad 0
    .quad 403,    (header_403 - status_table),  header_403_len
    .quad 0
    .quad 404,    (header_404 - status_table),  header_404_len
    .quad 0
    .quad 408,    (header_408 - status_table),  header_408_len
    .quad 0
    .quad 409,    (header_409 - status_table),  header_409_len
    .quad 0
    .quad 411,    (header_411 - status_table),  header_411_len
    .quad 0
    .quad 413,    (header_413 - status_table),  header_413_len
    .quad 0
    .quad 414,    (header_414 - status_table),  header_414_len
    .quad 0
    .quad 416,    (header_416 - status_table),  header_416_len
    .quad 0
    .quad 418,    (header_418 - status_table),  header_418_len
    .quad 0
    .quad 431,    (header_431 - status_table),  header_431_len
    .quad 0
    .quad 500,    (header_500 - status_table),  header_500_len
    .quad 0
    .quad 501,    (header_501 - status_table),  header_501_len
    .quad 0
    .quad 502,    (header_502 - status_table),  header_502_len
    .quad 0
    .quad 503,    (header_503 - status_table),  header_503_len
    .quad 0
    .quad 505,    (header_505 - status_table),  header_505_len
    .quad 0
    .quad 507,    (header_507 - status_table),  header_507_len
    .quad 0

    .quad 0 // mark the end
