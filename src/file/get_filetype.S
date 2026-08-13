#include "../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: get_filetype
//
// Description: Given a filename, extract the extension and return the
//   corresponding MIME content-type string. Entries are grouped by
//   first character of the extension (after the dot) for fast
//   first-character dispatch, then a small linear scan within the
//   group. Returns a fallback "text/plain; charset=utf-8" string when
//   the extension is unknown or missing. Calls streqn_i and strlen.
//
// Input/Arguments:
//   x0 -> filename
//   x1 -> filename length
//
// Output/Returns:
//   x0 -> content-type string (e.g. text/html)
//   x1 -> length of content-type string
//
// Clobbered Registers:
//   x0, x1, x2, x19, x20, x21, x22, x23 (x19-x23 saved and restored)
//
// Stack Usage:
//   64 bytes: stp x29, x30, [sp, #-64]!
// ─────────────────────────────────────────────────────────────────────

.macro mime_entry ext, mime
99:
    .asciz "\ext"
    .space 8 - (. - 99b)  // pad to offset 8 from entry start
    .asciz "\mime"
    .space 96 - (. - 99b) // pad to offset 96 from entry start
.endm

.data
// table of file extension / corresponding MIME types.
// this table is offset by 96 bytes per entry; 8 bytes for the extension, and
// 88 bytes for the MIME type string.
//
// entries are grouped by first character of the extension (after the dot)
// for first-character dispatch in get_filetype.

// ── group a: .aac, .apng, .avi, .avif ──
file_types_a:
    mime_entry ".aac",   "audio/aac"
    mime_entry ".apng",  "image/apng"
    mime_entry ".avi",   "video/x-msvideo"
    mime_entry ".avif",  "image/avif"

// ── group b: .bmp, .bz2 ──
file_types_b:
    mime_entry ".bmp",   "image/bmp"
    mime_entry ".bz2",   "application/x-bzip2"

// ── group c: .css, .csv ──
file_types_c:
    mime_entry ".css",   "text/css; charset=utf-8"
    mime_entry ".csv",   "text/csv; charset=utf-8"

// ── group d: .doc, .docx ──
file_types_d:
    mime_entry ".doc",   "application/msword"
    mime_entry ".docx",  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

// ── group e: .epub ──
file_types_e:
    mime_entry ".epub",  "application/epub+zip"

// ── group f: .flac ──
file_types_f:
    mime_entry ".flac",  "audio/flac"

// ── group g: .gif, .gz ──
file_types_g:
    mime_entry ".gif",   "image/gif"
    mime_entry ".gz",    "application/gzip"

// ── group h: .htm, .html ──
file_types_h:
    mime_entry ".htm",   "text/html; charset=utf-8"
    mime_entry ".html",  "text/html; charset=utf-8"

// ── group i: .ico ──
file_types_i:
    mime_entry ".ico",   "image/x-icon"

// ── group j: .jpg, .jpeg, .js, .json ──
file_types_j:
    mime_entry ".jpg",   "image/jpeg"
    mime_entry ".jpeg",  "image/jpeg"
    mime_entry ".js",    "text/javascript; charset=utf-8"
    mime_entry ".json",  "application/json"

// ── group m: .m4a, .map, .mjs, .mkv, .mov, .mp3, .mp4 ──
file_types_m:
    mime_entry ".m4a",   "audio/mp4"
    mime_entry ".map",   "application/json"
    mime_entry ".mjs",   "text/javascript; charset=utf-8"
    mime_entry ".mkv",   "video/x-matroska"
    mime_entry ".mov",   "video/quicktime"
    mime_entry ".mp3",   "audio/mpeg"
    mime_entry ".mp4",   "video/mp4"

// ── group o: .ogg, .opus, .otf ──
file_types_o:
    mime_entry ".ogg",   "audio/ogg"
    mime_entry ".opus",  "audio/opus"
    mime_entry ".otf",   "font/otf"

// ── group p: .pdf, .png ──
file_types_p:
    mime_entry ".pdf",   "application/pdf"
    mime_entry ".png",   "image/png"

// ── group r: .rar, .rtf ──
file_types_r:
    mime_entry ".rar",   "application/vnd.rar"
    mime_entry ".rtf",   "application/rtf"

// ── group s: .svg ──
file_types_s:
    mime_entry ".svg",   "image/svg+xml"

// ── group t: .tar, .tiff, .ttf, .txt ──
file_types_t:
    mime_entry ".tar",   "application/x-tar"
    mime_entry ".tiff",  "image/tiff"
    mime_entry ".ttf",   "font/ttf"
    mime_entry ".txt",   "text/plain; charset=utf-8"

// ── group w: .wav, .wasm, .webm, .webp, .woff, .woff2 ──
file_types_w:
    mime_entry ".wav",   "audio/wav"
    mime_entry ".wasm",  "application/wasm"
    mime_entry ".webm",  "video/webm"
    mime_entry ".webp",  "image/webp"
    mime_entry ".woff",  "font/woff"
    mime_entry ".woff2", "font/woff2"

// ── group x: .xml ──
file_types_x:
    mime_entry ".xml",   "text/xml; charset=utf-8"

// ── group z: .zip ──
file_types_z:
    mime_entry ".zip",   "application/zip"

// ── group 7: .7z ──
file_types_7:
    mime_entry ".7z",    "application/x-7z-compressed"

unknown_ct: .ascii "text/plain; charset=utf-8"
.equ unknown_ct_len, . - unknown_ct

.text
.align 2
.global get_filetype
get_filetype:
    // push the link register to the stack sorta. since we bl strcmp, we need
    // to preserve it
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    str x23, [sp, #48]
    mov x19, x0 // save the start pointer
    add x0, x0, x1 // now x0 points to one past the end of the string

1:
    // are we at the start again? if so, no file extension was present.
    cmp x0, x19
    b.eq Lreturn_unknown

    sub x0, x0, #1

    ldrb w20, [x0]
    cmp w20, #'.'
    b.eq Lfound_extension

    b 1b

// Ok, now x0 is pointing at the '.' in the filename
Lfound_extension:
    mov x21, x0 // save pointer to '.'
    mov x22, x1 // save filename length

    // load first char after the dot and lowercase it
    ldrb w20, [x0, #1]
    cbz w20, Lreturn_unknown // "file." has no extension
    orr w20, w20, #0x20       // lowercase

    // first-character dispatch — skip the linear scan of all 43 entries
    cmp w20, #'a'
    b.eq Lmime_a
    cmp w20, #'b'
    b.eq Lmime_b
    cmp w20, #'c'
    b.eq Lmime_c
    cmp w20, #'d'
    b.eq Lmime_d
    cmp w20, #'e'
    b.eq Lmime_e
    cmp w20, #'f'
    b.eq Lmime_f
    cmp w20, #'g'
    b.eq Lmime_g
    cmp w20, #'h'
    b.eq Lmime_h
    cmp w20, #'i'
    b.eq Lmime_i
    cmp w20, #'j'
    b.eq Lmime_j
    cmp w20, #'m'
    b.eq Lmime_m
    cmp w20, #'o'
    b.eq Lmime_o
    cmp w20, #'p'
    b.eq Lmime_p
    cmp w20, #'r'
    b.eq Lmime_r
    cmp w20, #'s'
    b.eq Lmime_s
    cmp w20, #'t'
    b.eq Lmime_t
    cmp w20, #'w'
    b.eq Lmime_w
    cmp w20, #'x'
    b.eq Lmime_x
    cmp w20, #'z'
    b.eq Lmime_z
    cmp w20, #'7'
    b.eq Lmime_7

    b Lreturn_unknown

// group dispatch targets — each loads its table pointer and entry count,
// then jumps into the shared linear-search loop.
Lmime_a:
    adr_l x1, file_types_a
    mov x20, #4
    b Lmime_group_search

Lmime_b:
    adr_l x1, file_types_b
    mov x20, #2
    b Lmime_group_search

Lmime_c:
    adr_l x1, file_types_c
    mov x20, #2
    b Lmime_group_search

Lmime_d:
    adr_l x1, file_types_d
    mov x20, #2
    b Lmime_group_search

Lmime_e:
    adr_l x1, file_types_e
    mov x20, #1
    b Lmime_group_search

Lmime_f:
    adr_l x1, file_types_f
    mov x20, #1
    b Lmime_group_search

Lmime_g:
    adr_l x1, file_types_g
    mov x20, #2
    b Lmime_group_search

Lmime_h:
    adr_l x1, file_types_h
    mov x20, #2
    b Lmime_group_search

Lmime_i:
    adr_l x1, file_types_i
    mov x20, #1
    b Lmime_group_search

Lmime_j:
    adr_l x1, file_types_j
    mov x20, #4
    b Lmime_group_search

Lmime_m:
    adr_l x1, file_types_m
    mov x20, #7
    b Lmime_group_search

Lmime_o:
    adr_l x1, file_types_o
    mov x20, #3
    b Lmime_group_search

Lmime_p:
    adr_l x1, file_types_p
    mov x20, #2
    b Lmime_group_search

Lmime_r:
    adr_l x1, file_types_r
    mov x20, #2
    b Lmime_group_search

Lmime_s:
    adr_l x1, file_types_s
    mov x20, #1
    b Lmime_group_search

Lmime_t:
    adr_l x1, file_types_t
    mov x20, #4
    b Lmime_group_search

Lmime_w:
    adr_l x1, file_types_w
    mov x20, #6
    b Lmime_group_search

Lmime_x:
    adr_l x1, file_types_x
    mov x20, #1
    b Lmime_group_search

Lmime_z:
    adr_l x1, file_types_z
    mov x20, #1
    b Lmime_group_search

Lmime_7:
    adr_l x1, file_types_7
    mov x20, #1
    b Lmime_group_search

// shared small linear scan within a group.
// input:  x1 = ptr to first entry, x20 = entry count
// uses:   x21 = filename ptr (pointing to '.')
Lmime_group_search:
    mov x23, x1 // save table entry pointer
    mov x0, x21 // filename, from . and on
    mov x2, #8
    bl streqn_i

    cmp x0, #1
    b.eq Lmatch

    subs x20, x20, #1
    b.eq Lreturn_unknown

    add x1, x23, #96
    b Lmime_group_search

Lmatch:
    add x22, x23, #8
    mov x1, x22 // strlen takes x1
    bl strlen  // x0 is now length
    mov x1, x0 // we want to return length in x1
    mov x0, x22
    b Lreturn

Lreturn_unknown:
    adr_l x0, unknown_ct
    mov x1, unknown_ct_len
    b Lreturn
 
Lreturn:
    // restore the link register we pushed to the stack
    ldr x23, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret
