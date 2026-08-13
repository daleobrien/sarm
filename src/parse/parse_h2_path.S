#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: parse_h2_path
//
// Description: Build the docroot-prefixed filename from an HTTP/2 :path
//   value (RFC 9113 §8.3.1), mirroring parse_path's assembly logic so
//   both protocols produce the same internal path. The path is
//   origin-form ("/a/b?q") or asterisk-form ("*"). Multiple slashes
//   collapse into one, the query (everything after the first '?') is
//   copied raw into query_buf, and an empty path ("/") becomes
//   DOCROOT + DEFAULT_FILE for GET/HEAD or the bare DOCROOT otherwise.
//
//   Unlike parse_path, the input is an already-extracted path string
//   rather than a raw request line, and errors are reported with carry
//   set instead of replying 400/414 — the HTTP/2 layer turns them into
//   a stream error.
//
// Input/Arguments:
//   x0 -> path value
//   x1 -> path value length
//   x2 -> default-file flag: 1 = append DEFAULT_FILE when the path is
//         empty (GET/HEAD), 0 = leave the bare docroot (OPTIONS)
//
// Output/Returns:
//   success (carry clear):
//     x0 -> filename string (filename_buf, NUL-terminated)
//     x1 -> filename length
//     x2 -> query string (query_buf), or 0 if there is none
//     x3 -> query string length (0 if there is none)
//   failure (carry set): x0 = 0 (malformed or oversized path)
//
// Clobbered Registers:
//   x0-x9, x19-x24, x29, x30 (x19-x24 saved and restored)
//
// Stack Usage:
//   64 bytes: stp x29, x30, [sp, #-64]!
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
.global parse_h2_path
parse_h2_path:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    mov x19, x0             // path ptr
    mov x20, x1             // path len
    mov x21, x2             // default-file flag

    // asterisk-form — the whole path is "*"
    cmp x20, #1
    b.ne 1f
    ldrb w3, [x19]
    cmp w3, #'*'
    b.eq .Lh2p_asterisk
1:
    // origin-form must start with '/'
    cbz x20, .Lh2p_bad
    ldrb w3, [x19]
    cmp w3, #'/'
    b.ne .Lh2p_bad

    // filename_buf = DOCROOT + path (slash collapsing as in parse_path)
    adr_l x22, filename_buf
    adr_l x23, www_prefix
    mov x24, www_prefix_len
    mov x0, x22
    mov x1, x23
    mov x2, x24
    bl memcpy
    mov x4, x24             // filename_buf write index
    mov x2, #1              // path read index — past the leading '/'
    mov x6, #1              // last char was a slash (the prefix ends in one)
    mov x7, #0              // query start index in filename_buf (0 = none)
.Lh2p_fname_loop:
    cmp x2, x20             // past the end of the path?
    b.hs .Lh2p_fname_done
    cmp x4, filename_buf_size
    b.ge .Lh2p_bad          // filename would overflow
    ldrb w3, [x19, x2]
    cmp w3, #'?'
    b.eq .Lh2p_query_start
    cmp w3, #'/'
    b.eq .Lh2p_slash
    // an ordinary character
    strb w3, [x22, x4]
    add x4, x4, #1
    mov x6, #0              // last char was not a slash
    add x2, x2, #1
    b .Lh2p_fname_loop
.Lh2p_slash:
    cbnz x6, 1f             // previous char was a slash — collapse it
    strb w3, [x22, x4]      // keep this slash
    add x4, x4, #1
    mov x6, #1
1:
    add x2, x2, #1
    b .Lh2p_fname_loop
.Lh2p_query_start:
    mov x7, x4              // the query begins here
    add x2, x2, #1          // skip the '?'
    // copy the rest of the path raw into query_buf — the query is
    // never percent-decoded, matching parse_path/HTTP/1
    adr_l x8, query_buf
    mov x9, #0
.Lh2p_query_loop:
    cmp x2, x20
    b.hs .Lh2p_query_done
    cmp x9, query_buf_size
    b.ge .Lh2p_bad
    ldrb w3, [x19, x2]
    strb w3, [x8, x9]
    add x2, x2, #1
    add x9, x9, #1
    b .Lh2p_query_loop
.Lh2p_query_done:
    strb wzr, [x8, x9]      // NUL-terminate the query
    strb wzr, [x22, x7]     // cut the query out of the filename
    mov x0, x22
    mov x1, x7
    mov x2, x8
    mov x3, x9
    b .Lh2p_ok
.Lh2p_fname_done:
    strb wzr, [x22, x4]     // NUL-terminate the filename
    mov x0, x22
    mov x1, x4
    mov x2, #0              // no query
    mov x3, #0
    mov x5, www_prefix_len
    cmp x4, x5
    b.eq .Lh2p_empty        // the path was empty — apply the default file
    b .Lh2p_ok
.Lh2p_empty:
    cbz x21, .Lh2p_no_default
    // append DEFAULT_FILE (e.g. index.html) for GET/HEAD
    adr_l x8, default_file
    mov x9, default_file_len
    mov x5, #0
.Lh2p_def_loop:
    cmp x5, x9
    b.hs .Lh2p_def_done
    ldrb w3, [x8, x5]
    strb w3, [x22, x4]
    add x4, x4, #1
    add x5, x5, #1
    b .Lh2p_def_loop
.Lh2p_def_done:
    strb wzr, [x22, x4]
    mov x0, x22
    mov x1, x4
    mov x2, #0              // no query
    mov x3, #0              // ... and no query length
    b .Lh2p_ok
.Lh2p_no_default:
    // OPTIONS "/" — the bare docroot
    mov x0, x22
    mov x1, www_prefix_len
    b .Lh2p_ok
.Lh2p_asterisk:
    adr_l x22, filename_buf
    mov w3, #'*'
    strb w3, [x22]
    strb wzr, [x22, #1]
    mov x0, x22
    mov x1, #1
    mov x2, #0
    mov x3, #0
    b .Lh2p_ok
.Lh2p_bad:
    cmp xzr, xzr            // failure — carry set
    mov x0, #0
    b .Lh2p_epilogue
.Lh2p_ok:
    cmn xzr, xzr            // success — carry clear
.Lh2p_epilogue:
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret
