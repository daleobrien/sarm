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

#include "defs.S"

.macro mime_entry ext, mime
99:
    .asciz "\ext"
    .space 8 - (. - 99b)  // pad to offset 8 from entry start
    .asciz "\mime"
    .space 96 - (. - 99b) // pad to offset 96 from entry start
.endm

.global stat_fd
.global stat_path
.global get_filetype
.global check_path_traversal
.global check_path_safety
.global decode_url
.global lookup_embedded

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

// run fstat64() on file descirptor, returning file size and type
// input
// x0 -> file descriptor
//
// returns
// x0 -> 0 on success, otherwise, errno from stat64
// w1 -> file type
// x2 -> size
stat_fd:
    sub sp, sp, #160 // reserve stack buffer (stat requires 144 bytes, round up)
    SCWINUM SYS_fstat64

    mov x1, sp // stat buffer, on the stack
    SCWISVC
    SCERR
    b.cs Lstat_fd_failed

#ifdef __linux__
    // Linux: st_mode is u32 at offset 16, st_size is u64 at offset 48
    ldr w1, [sp, #16]
#else
    // macOS: st_mode is u16 at offset 4
    ldrh w1, [sp, #4]
#endif

    and w1, w1, #0xF000 // mask S_IFMT
#ifdef __linux__
    ldr x2, [sp, #48] // load st_size into x2
#else
    ldr x2, [sp, #96] // load st_size into x2
#endif

    mov x0, #0
    b Lstat_fd_end

Lstat_fd_failed:
    // x0 is already errno. these two movs aren't strictly necessary, but i
    // think it's nice to have it all zeroed out.
    mov x1, #0
    mov x2, #0
    mov x3, #0
    // fallthrough
Lstat_fd_end:
    add sp, sp, #160
    ret


// run stat64() on file path, returning file size and type
// input
// x0 -> file path
//
// returns
// x0 -> 0 on success, otherwise, errno from stat64
// w1 -> file type
// x2 -> size
stat_path:
    sub sp, sp, #160 // reserve stack buffer (stat requires 144 bytes, round up)
#ifdef __linux__
    SCWINUM SYS_newfstatat
    mov x3, #0              // flags = 0
    mov x2, sp              // buf = stack buffer
    mov x1, x0              // path (was in x0)
    mov x0, #AT_FDCWD       // dirfd = AT_FDCWD
#else
    SCWINUM SYS_stat64
    // x0 is already set (path)
    mov x1, sp // stat buffer, on the stack
#endif
    SCWISVC
    SCERR
    b.cs Lstat_path_failed

#ifdef __linux__
    // Linux: st_mode is u32 at offset 16, st_size is u64 at offset 48
    ldr w1, [sp, #16]
#else
    // macOS: st_mode is u16 at offset 4
    ldrh w1, [sp, #4]
#endif

    and w1, w1, #0xF000 // mask S_IFMT
#ifdef __linux__
    ldr x2, [sp, #48] // load st_size into x2
#else
    ldr x2, [sp, #96] // load st_size into x2
#endif
    mov x0, #0
    b Lstat_path_end

Lstat_path_failed:
    // x0 is already errno. these two movs aren't strictly necessary, but i
    // think it's nice to have it all zeroed out.
    mov x1, #0
    mov x2, #0
    mov x3, #0
    // fallthrough
Lstat_path_end:
    add sp, sp, #160
    ret


// checks for path traversal: GET /../../file.txt
// it does not do anything else. one "." is fine. more than two "..." is fine.
// two ".." in a file "foo..txt" is fine. but a path segment being just .. is
// no good!
// input
// x0 -> filename string
// x1 -> filename length
//
// returns
// x0 -> 1 if safe, 0 if unsafe
//
// clobbers
// x2 -> index into string
// x3 -> dot count per segment
// x4 -> segment length
check_path_traversal:
    mov x2, #0
    mov x3, #0
    mov x4, #0

Lloop:
    cmp x2, x1
    b.ge Lcheck_segment

    ldrb w5, [x0, x2]

    cmp w5, #'/'
    b.eq Lcheck_segment

    cmp w5, #0
    b.eq Lcheck_segment

    add x2, x2, #1
    add x4, x4, #1

    cmp w5, #'.'
    b.eq 2f

    b Lloop

2:
    add x3, x3, #1
    b Lloop

Lcheck_segment:
    cmp x3, x4
    b.eq Lequal_length

3:
    mov x3, #0
    mov x4, #0

    cmp x2, x1
    b.ge Lno_path_traversal

    add x2, x2, #1
    b Lloop

Lequal_length:
    cmp x3, #2
    b.eq Lpath_traversal

    b 3b

Lno_path_traversal:
    mov x0, #1
    ret

Lpath_traversal:
    mov x0, #0
    ret


// ensure a path only has printable ASCII characters.
//
// URL policy:
//     allowed bytes = 0x20–0x7E (printable ASCII)
//
// The only exclusions from this range are:
//   - Control characters (0x00–0x1F): NUL, SOH, STX, …, US
//   - DEL (0x7F) and everything above (non-ASCII)
//
// This is deliberately restrictive for a small server; it rejects all
// non-ASCII byte sequences including UTF-8 multi-byte characters.
//
// input
// x0 -> path to check
// x1 -> path length
//
// returns
// x0 -> 1 if safe, 0 if unsafe
check_path_safety:
    // if we've reached the end and no issues yet, it's safe
    cbz x1, Lsafe

    ldrb w3, [x0]

    // everything under and including 0x1F, "US" or Unit Separator.
    cmp w3, #0x1F
    b.le Lunsafe

    // everything including and after 0x7F, which is DELETE. everything after
    // that is not valid ascii anymore.
    cmp w3, #0x7F
    b.ge Lunsafe

    sub x1, x1, #1
    add x0, x0, #1
    b check_path_safety

Lsafe:
    mov x0, #1
    ret

Lunsafe:
    mov x0, #0
    ret


// given a filename, extract the extension and return MIME type.
// input
// x0 -> filename
// x1 -> filename length
//
// returns
// x0 -> content-type string (eg text/html)
// x1 -> length of content-type string
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


// convert %XX in URL to 0xXX raw bytes. %0a = newline, %20 = space, etc.
//
// SECURITY: This function is called BEFORE check_path_safety and
// check_path_traversal (see do_path_checks in parse.S). This ordering is
// deliberate: percent-encoded path-traversal sequences like %2e%2e%2f are
// decoded to ../ and then caught by check_path_traversal.
//
// The function rejects the following dangerous inputs by returning (0, 0):
//   - %00 (decoded null byte) — caught by cmp w4, #0 / b.eq Lbad_end
//   - %XX where X is not a hex digit — caught by hex_to_val setting x20=1
//   - Truncated % at end of string (fewer than 3 bytes remaining)
//
// If any of these are encountered, do_path_checks responds with HTTP 400.
//
// input
// x0 -> encoded string
// x1 -> length of encoded string
//
// returns
// x0 -> decoded string (decoded in-place), or 0 on rejection
// x1 -> length of decoded string, or 0 on rejection
decode_url:
    stp x29, x30, [sp, #-32]!
    str x20, [sp, #16]
    mov x2, x0 // write pointer
    mov x3, #0 // x3 is length of new string

Ldecode_loop:
    ldrb w4, [x0]
    // make sure we're not null
    cmp w4, #0
    b.eq Ldecode_end

    cmp w4, #'%'
    b.eq Lencoded_char

    strb w4, [x2, x3]
    add x3, x3, #1

    // make sure we're not reading beyond the length of the string
    sub x1, x1, #1
    cmp x1, #0
    b.eq Ldecode_end

    add x0, x0, #1 // increment along the new string to the next char
    b Ldecode_loop

Lencoded_char:
    cmp x1, #3
    b.lt Lbad_end

    // high nibble
    ldrb w4, [x0, #1]
    bl hex_to_val
    cbnz x20, Lbad_end

    lsl w5, w4, #4 // stash in w5

    // low nibble
    ldrb w4, [x0, #2]
    bl hex_to_val
    cbnz x20, Lbad_end

    orr w4, w5, w4 // combine w5 (high nibble) with w4 (low nibble)

    cmp w4, #0
    b.eq Lbad_end

    // now w4 contains the decoded byte
    strb w4, [x2, x3]

    add x3, x3, #1
    sub x1, x1, #3
    cmp x1, #0
    b.le Ldecode_end

    add x0, x0, #3
    b Ldecode_loop

hex_to_val:
    orr w4, w4, #0x20

    cmp w4, #'0'
    b.lt 2f
    cmp w4, #'9'
    b.le 1f

    cmp w4, #'a'
    b.lt 2f
    cmp w4, #'f'
    b.gt 2f

    mov x20, #0
    sub w4, w4, #'a' - 10
    ret
1:
    mov x20, #0
    sub w4, w4, #'0'
    ret
2:
    mov x20, #1
    ret

Ldecode_end:
    mov x0, x2
    mov x1, x3

    strb wzr, [x0, x1] // null terminate decoded string
    b Ldecode_epilogue

Lbad_end:
    mov x0, #0
    mov x1, #0
    b Ldecode_epilogue

Ldecode_epilogue:
    ldr x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret


// Look up a path in the embedded files table (generated by embed_www.sh).
// The table is sorted lexicographically by path, so we use binary search
// for O(log n) lookup instead of linear scan.
// input
// x0 -> path string (e.g. "www/index.html")
// x1 -> path length
//
// returns
// x0 -> content pointer
// x1 -> content size
// x2 -> content-type string pointer
// x3 -> content-type string length
// x4 -> gzip flag (1 = gzipped, 0 = raw)
// x5 -> ETag string pointer (e.g. "\"abc123...\"")
// x6 -> ETag string length
// carry set = not found, carry clear = found
lookup_embedded:
    stp x29, x30, [sp, #-64]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    mov x19, x0  // save path_ptr
    mov x20, x1  // save path_len

    // load entry count
    adr_l x9, embedded_count
    ldr x21, [x9]
    cbz x21, Lle_not_found  // empty table

    mov x22, #0              // low = 0
    sub x23, x21, #1         // high = count - 1
    adr_l x5, embedded_files // table base

Lle_binsearch:
    cmp x22, x23
    b.gt Lle_not_found  // low > high → not found

    // mid = (low + high) / 2
    add x6, x22, x23
    lsr x6, x6, #1

    // entry_ptr = table + mid * 72
    mov x7, #72
    mul x7, x6, x7
    add x7, x5, x7

    // load path_len from table entry
    ldr x8, [x7, #8]

    // String comparison using the shorter length for ordering,
    // since lengths may differ but lexicographic order still matters.
    mov x0, x19          // our path
    ldr x1, [x7]         // table path ptr
    mov x2, x20          // use our path length
    cmp x8, x20
    csel x2, x8, x2, lo  // x2 = min(entry_len, our_len)
    bl Lle_strcmp        // returns ordering in x0 (-1,0,1)
    cbz x0, Lle_equal_prefix

    // Different at some char — use comparison result directly
    b.lt Lle_go_lower    // our path < table → go lower
    b.gt Lle_go_higher   // our path > table → go higher
    b Lle_not_found

Lle_equal_prefix:
    // Characters matched up to min length. If lengths also match, found!
    cmp x8, x20
    b.eq Lle_found

    // Lengths differ. Shorter string comes first lexicographically.
    b.lt Lle_go_higher   // entry shorter → our path is later
    b.gt Lle_go_lower    // entry longer → our path is earlier

Lle_go_higher:
    add x22, x6, #1  // low = mid + 1
    b Lle_binsearch

Lle_go_lower:
    sub x23, x6, #1  // high = mid - 1
    b Lle_binsearch

Lle_found:
    // entry layout at x7:
    // +0:  path_ptr
    // +8:  path_len
    // +16: content_ptr
    // +24: content_size
    // +32: ct_ptr
    // +40: ct_len
    // +48: gzip flag
    // +56: etag_ptr
    // +64: etag_len
    ldr x0, [x7, #16]  // content_ptr
    ldr x1, [x7, #24]  // content_size
    ldr x2, [x7, #32]  // ct_ptr
    ldr x3, [x7, #40]  // ct_len
    ldr x4, [x7, #48]  // gzip flag
    ldr x5, [x7, #56]  // etag_ptr
    ldr x6, [x7, #64]  // etag_len

    cmn xzr, xzr  // clear carry
    b Lle_epilogue

Lle_not_found:
    cmp xzr, xzr  // set carry
    b Lle_epilogue

Lle_epilogue:
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

// Three-way string comparison for binary search ordering.
// input
// x0 -> str1
// x1 -> str2
// x2 -> max length
//
// returns
// x0 -> -1 if str1 < str2, 0 if equal, 1 if str1 > str2
Lle_strcmp:
    cbz x2, 1f
    ldrb w3, [x0]
    ldrb w4, [x1]
    cmp w3, w4
    b.lt 2f
    b.gt 3f
    // chars equal, continue
    subs x2, x2, #1
    b.eq 1f
    add x0, x0, #1
    add x1, x1, #1
    b Lle_strcmp
1:
    mov x0, #0   // equal
    ret
2:
    mov x0, #-1  // str1 < str2
    ret
3:
    mov x0, #1   // str1 > str2
    ret
