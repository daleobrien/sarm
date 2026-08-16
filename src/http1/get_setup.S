#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: get_setup
//
// Description: Setup for the "GET" and "HEAD" methods. Resolves the
//   resource (embedded table lookup) and fills the embedded_* globals
//   the response builders read.
//
// Input/Arguments:
//   none; reads the parsed `request` struct (REQ_PATH)
//
// Output/Returns:
//   x0 — length of file
//   x1 — file type (w1 can be S_IFREG or S_IFDIR)
//
// Clobbered Registers:
//   x0–x6, x9, x10 (x19/x20 saved and restored)
//
// Stack Usage:
//   32 bytes: stp x29, x30, [sp, #-32]! + stp x19, x20, [sp, #16]
// ─────────────────────────────────────────────────────────────────────

.text
.align 2
// setup for the "GET" and "HEAD" methods. resolves the resource (embedded
// table lookup) and fills the embedded_* globals the response builders
// read.
// none, uses .bss data
//
// output
// x0 -> length of file
// x1 -> file type, w1 can be S_IFREG or S_IFDIR
// NOTE this function opens a file and doesn't close it -- it saves the open
// file descriptor in file_des, which is in data.S's .data. child_end should
// close it, but be aware!
.global get_setup
get_setup:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]

    // the request was already parsed into the `request` struct by
    // parse_request (sarm.S dispatch) — read the path from there.
    adr_l x9, request
    ldr x0, [x9, #REQ_PATH]

    ldrb w1, [x0]
    cmp w1, #'*'
    b.eq L400

    // try embedded content lookup first
    str_l xzr, resource_type, x10
    ldr x0, [x9, #REQ_PATH]
    ldr x1, [x9, #REQ_PATH_LENGTH]
    bl lookup_embedded
    b.cc Lembedded_found

    // not found in embedded table — 404
    b L404

Lembedded_found:
    // x0 = content_ptr, x1 = content_size, x2 = ct_ptr, x3 = ct_len, x4 = gzip, x5 = etag, x6 = etag_len
    str_l x0, embedded_content
    str_l x2, embedded_ct
    str_l x3, embedded_ct_len
    str_l x4, embedded_gzip
    str_l x5, embedded_etag
    str_l x6, embedded_etag_len
    mov x9, #1
    str_l x9, resource_type, x10
    mov x9, #-1
    str_l x9, file_des

    mov x0, x1   // return content_size
    mov w1, #S_IFREG

    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret

// local trampoline: b.cond/cbz can't reach reply_status across files
L400:
    mov x0, #400
    mov x1, #0
    b reply_status
L404:
    mov x0, #404
    mov x1, #0
    b reply_status
