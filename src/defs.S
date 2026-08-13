#include "config.S"

// macros

#ifdef __linux__
// Linux GAS uses :pg_hi21: and :lo12: relocations
.macro adr_l, reg, sym
    adrp \reg, :pg_hi21:\sym
    add \reg, \reg, :lo12:\sym
.endm

.macro ldr_l reg, sym, scratch=x9
    adrp \scratch, :pg_hi21:\sym
    ldr \reg, [\scratch, :lo12:\sym]
.endm

.macro str_l src, sym, scratch=x9
    adrp \scratch, :pg_hi21:\sym
    str \src, [\scratch, :lo12:\sym]
.endm
#else
// Apple assembler uses @PAGE and @PAGEOFF relocations
.macro adr_l, reg, sym
    adrp \reg, \sym@PAGE
    add \reg, \reg, \sym@PAGEOFF
.endm

.macro ldr_l reg, sym, scratch=x9
    adrp \scratch, \sym@PAGE
    ldr \reg, [\scratch, \sym@PAGEOFF]
.endm

.macro str_l src, sym, scratch=x9
    adrp \scratch, \sym@PAGE
    str \src, [\scratch, \sym@PAGEOFF]
.endm
#endif

// (c)ompare and (b)ranch, (eq/ne/gt/etc), x0, x1, label
.macro cb cond, r1, r2, l
    cmp \r1, \r2
    b.\cond \l
.endm

// ── Platform-specific syscall helpers ─────────────────────────

#ifdef __linux__

// SCWINUM: set the syscall number in the platform-specific register.
.macro SCWINUM num
    mov x8, \num
.endm

// SCWISVC: execute the syscall instruction.
.macro SCWISVC
    svc #0
.endm

// SCERR: after a Linux syscall, convert negative-x0 errno to positive
// and set/clear C so that b.cs works identically to macOS.
.macro SCERR
    tbnz x0, #63, 9900f
    cmn xzr, xzr   // success: C=0
    b 9901f
9900:
    neg x0, x0     // errno now positive
    cmp xzr, xzr   // error: C=1
9901:
.endm

// syscalls
.equ SYS_exit,         93
.equ SYS_read,         63
.equ SYS_write,        64
.equ SYS_openat,       56
.equ SYS_close,        57
.equ SYS_getpid,       172
.equ SYS_accept4,      242
.equ SYS_kill,         129
.equ SYS_rt_sigaction, 134
.equ SYS_munmap,       215
.equ SYS_setitimer,    103
.equ SYS_socket,       198
.equ SYS_bind,         200
.equ SYS_setsockopt,   208
.equ SYS_listen,       201
.equ SYS_shutdown,     210
.equ SYS_mmap,         222
.equ SYS_clone,        220
.equ SYS_getdents64,   217
.equ SYS_newfstatat,   79
.equ SYS_fstat64,      80   // Linux fstat = 80
.equ SYS_nanosleep,    101
.equ SYS_writev,       66
.equ SYS_gettimeofday, 169

// socket stuff
.equ AF_INET,          2
.equ SOCK_STREAM,      1
.equ SOL_SOCKET,       1
.equ SO_REUSEADDR,     2
.equ SO_RCVTIMEO,      20
// Linux doesn't have SO_NOSIGPIPE; we ignore SIGPIPE instead.
.equ SO_NOSIGPIPE,     -1

// mmap
.equ PROT_READ,        1
.equ MAP_PRIVATE,      2

// open flags
.equ O_RDONLY,         0x0000
.equ O_NOFOLLOW,       0x20000  // Linux O_NOFOLLOW
.equ AT_FDCWD,         -100

// stat — Linux struct stat64 (arm64)
// st_mode is a u32 at offset 16, st_size is u64 at offset 48
.equ OFF_ST_MODE,      16
.equ S_IFREG,          0x8000
.equ S_IFDIR,          0x4000
.equ S_IXUSR,          0x40
.equ S_IXGRP,          0x08
.equ S_IXOTH,          0x01
.equ S_IXANY,          0x49

// getdents64 — Linux dirent64 struct
.equ OFF_D_INTO,       0
.equ OFF_D_SEEKOFF,    8
.equ OFF_D_RECLEN,     16
.equ OFF_D_TYPE,       18
.equ OFF_D_NAMLEN,     19   // NOTE: not present in Linux dirent64; we compute from d_name
.equ OFF_D_NAME,       19
.equ DT_DIR,           4

// clone flags for fork() replacement
.equ CLONE_CHILD_SETTID,  0x01000000
.equ CLONE_CHILD_CLEARTID, 0x00200000
.equ SIGCHLD_LINUX,          17

// errno values (Linux arm64)
.equ EPERM,          1
.equ ENOENT,         2
.equ ESRCH,          3
.equ EINTR,          4
.equ EIO,            5
.equ ENXIO,          6
.equ E2BIG,          7
.equ ENOEXEC,        8
.equ EBADF,          9
.equ ECHILD,         10
.equ EAGAIN,         11
.equ ENOMEM,         12
.equ EACCES,         13
.equ EFAULT,         14
.equ EBUSY,          16
.equ EEXIST,         17
.equ EXDEV,          18
.equ ENODEV,         19
.equ ENOTDIR,        20
.equ EISDIR,         21
.equ EINVAL,         22
.equ ENFILE,         23
.equ EMFILE,         24
.equ ENOTTY,         25
.equ ETXTBSY,        26
.equ EFBIG,          27
.equ ENOSPC,         28
.equ ESPIPE,         29
.equ EROFS,          30
.equ EMLINK,         31
.equ EPIPE,          32
.equ EDOM,           33
.equ ERANGE,         34
.equ EDEADLK,        35
.equ ENAMETOOLONG,   36
.equ ENOLCK,         37
.equ ENOSYS,         38
.equ ENOTEMPTY,      39
.equ ELOOP,          40
.equ ENOMSG,         42
.equ EIDRM,          43
.equ ECHRNG,         44
.equ EL2NSYNC,       45
.equ EL3HLT,         46
.equ EL3RST,         47
.equ ELNRNG,         48
.equ EUNATCH,        49
.equ ENOCSI,         50
.equ EL2HLT,         51
.equ EBADE,          52
.equ EBADR,          53
.equ EXFULL,         54
.equ ENOANO,         55
.equ EBADRQC,        56
.equ EBADSLT,        57
.equ EDEADLOCK,      58  // note: EDEADLOCK == EDEADLK on many archs
.equ EBFONT,         59
.equ ENOSTR,         60
.equ ENODATA,        61
.equ ETIME,          62
.equ ENOSR,          63
.equ ENONET,         64
.equ ENOPKG,         65
.equ EREMOTE,        66
.equ ENOLINK,        67
.equ EADV,           68
.equ ESRMNT,         69
.equ ECOMM,          70
.equ EPROTO,         71
.equ EMULTIHOP,      72
.equ EDOTDOT,        73
.equ EBADMSG,        74
.equ EOVERFLOW,      75
.equ ENOTUNIQ,       76
.equ EBADFD,         77
.equ EREMCHG,        78
.equ ELIBACC,        79
.equ ELIBBAD,        80
.equ ELIBSCN,        81
.equ ELIBMAX,        82
.equ ELIBEXEC,       83
.equ EILSEQ,         84
.equ ERESTART,       85
.equ ESTRPIPE,       86
.equ EUSERS,         87
.equ ENOTSOCK,       88
.equ EDESTADDRREQ,   89
.equ EMSGSIZE,       90
.equ EPROTOTYPE,     91
.equ ENOPROTOOPT,    92
.equ EPROTONOSUPPORT, 93
.equ ESOCKTNOSUPPORT,  94
.equ EOPNOTSUPP,     95
.equ EPFNOSUPPORT,   96
.equ EAFNOSUPPORT,   97
.equ EADDRINUSE,     98
.equ EADDRNOTAVAIL,  99
.equ ENETDOWN,       100
.equ ENETUNREACH,    101
.equ ENETRESET,      102
.equ ECONNABORTED,   103
.equ ECONNRESET,     104
.equ ENOBUFS,        105
.equ EISCONN,        106
.equ ENOTCONN,       107
.equ ESHUTDOWN,      108
.equ ETOOMANYREFS,   109
.equ ETIMEDOUT,      110
.equ ECONNREFUSED,   111
.equ EHOSTDOWN,      112
.equ EHOSTUNREACH,   113
.equ EALREADY,       114
.equ EINPROGRESS,    115
.equ ESTALE,         116
.equ EUCLEAN,        117
.equ ENOTNAM,        118
.equ ENAVAIL,        119
.equ EISNAM,         120
.equ EREMOTEIO,      121
.equ EDQUOT,         122
.equ ENOMEDIUM,      123
.equ EMEDIUMTYPE,    124
.equ ECANCELED,      125
.equ ENOKEY,         126
.equ EKEYEXPIRED,    127
.equ EKEYREVOKED,    128
.equ EKEYREJECTED,   129
.equ EOWNERDEAD,     130
.equ ENOTRECOVERABLE, 131
.equ ERFKILL,        132
.equ EHWPOISON,      133

// signals
.equ SIGALRM,        14
.equ SIGCHLD_,       17
.equ SIGPIPE_,       13
.equ SIG_IGN,        1

// For SA_NOCLDWAIT on Linux ARM64, we just set SIGCHLD to SIG_IGN
// which has the same effect on Linux (auto-reap children).
// SA_NOCLDWAIT is #defined as 2 for most Linux archs including arm64.
.equ SA_NOCLDWAIT,   2

// request type ids
.equ GET_ID,     0
.equ HEAD_ID,    1
.equ OPTIONS_ID, 2
.equ BREW_ID,    3
.equ UNKNOWN_ID, 4

// unified resource type constants (embedded vs filesystem)
.equ RES_NONE,     0
.equ RES_EMBEDDED, 1
.equ RES_FILE,     2

// ── Request context offsets ────────────────────────────────────
// Functions take a pointer to request_ctx in x19/x20.
// Access fields via:  ldr xn, [ctx, #CTX_xxx]
.equ CTX_HEADER_LEN,      0
.equ CTX_CLIENT_FD,       8
.equ CTX_FILENAME_STR,    16
.equ CTX_FILENAME_LEN,    24
.equ CTX_QUERY_STR,       32
.equ CTX_QUERY_LEN,       40
.equ CTX_DOCROOT_LEN,     48
.equ CTX_REQUEST_ID,      56
.equ CTX_RESOURCE_TYPE,   64
.equ CTX_EMBED_CONTENT,   72
.equ CTX_EMBED_CT,        80
.equ CTX_EMBED_CT_LEN,    88
.equ CTX_EMBED_GZIP,      96
.equ CTX_EMBED_ETAG,      104
.equ CTX_EMBED_ETAG_LEN,  112
.equ CTX_FILE_DES,        120
.equ CTX_REQUEST_BUF,     128  // points to buf

.equ REQUEST_CTX_SIZE,    136

.equ BUF_SIZE,   16384

// struct timeval offsets (64-bit)
.equ OFF_TV_SEC,  0
.equ OFF_TV_USEC, 8

#else
// ── macOS / Apple ARM64 ───────────────────────────────────────

// SCWINUM: set the syscall number. macOS uses x16.
.macro SCWINUM num
    mov x16, \num
.endm

// SCWISVC: execute the syscall instruction. macOS uses svc #0x80.
.macro SCWISVC
    svc #0x80
.endm

// SCERR: on macOS, the carry flag is already correct after svc #0x80.
.macro SCERR
.endm

// syscalls
.equ SYS_exit,         1
.equ SYS_fork,         2
.equ SYS_read,         3
.equ SYS_write,        4
.equ SYS_open,         5
.equ SYS_close,        6
.equ SYS_wait4,        7
.equ SYS_unlink,       10
.equ SYS_getpid,       20
.equ SYS_accept,       30
.equ SYS_getpeername,  31
.equ SYS_kill,         37
.equ SYS_pipe,         42
.equ SYS_sigaction,    46
.equ SYS_execve,       59
.equ SYS_munmap,       73
.equ SYS_setitimer,    83
.equ SYS_dup2,         90
.equ SYS_socket,       97
.equ SYS_bind,         104
.equ SYS_setsockopt,   105
.equ SYS_listen,       106
.equ SYS_shutdown,     134
.equ SYS_mmap,         197
.equ SYS_proc_info,    336
.equ SYS_stat64,       338
.equ SYS_fstat64,      339
.equ SYS_getdirentries64, 344
.equ SYS_unlinkat,     472
.equ SYS_renameatx_np, 488
.equ SYS_writev,       121
.equ SYS_gettimeofday, 116

// socket
.equ AF_INET,          2
.equ SOCK_STREAM,      1
.equ SOL_SOCKET,       0xFFFF
.equ SO_REUSEADDR,     4
.equ SO_RCVTIMEO,      0x1006
.equ SO_NOSIGPIPE,     0x1022

// mmap
.equ PROT_READ,        1
.equ MAP_PRIVATE,      2

// oflags
.equ O_RDONLY,         0x0000
.equ O_NOFOLLOW_ANY,   0x20000000
.equ AT_FDCWD,         -2

// stat
.equ OFF_ST_MODE,    4
.equ S_IFREG,        0x8000
.equ S_IFDIR,        0x4000
.equ S_IXUSR,        0x40
.equ S_IXGRP,        0x08
.equ S_IXOTH,        0x01
.equ S_IXANY,        0x49

// getdirentries64
.equ OFF_D_INTO,    0
.equ OFF_D_SEEKOFF, 8
.equ OFF_D_RECLEN,  16
.equ OFF_D_NAMLEN,  18
.equ OFF_D_TYPE,    20
.equ OFF_D_NAME,    21
.equ DT_DIR,        4

// proc stuff
.equ PROC_INFO_CALL_LISTPIDS, 1
.equ PROC_PPID_ONLY,          6

// errno values
.equ EPERM,          1
.equ ENOENT,         2
.equ EACCES,         13
.equ EFAULT,         14
.equ EBUSY,          16
.equ ENOTDIR,        20
.equ EISDIR,         21
.equ EROFS,          30
.equ ECONNABORTED,   53
.equ ECONNRESET,     54
.equ ETIMEDOUT,      60
.equ ELOOP,          62
.equ ENAMETOOLONG,   63
.equ EPIPE,          32
.equ ENETDOWN,       50
.equ ENETUNREACH,    51
.equ ENETRESET,      52
.equ EHOSTDOWN,      64
.equ EHOSTUNREACH,   65
.equ EAGAIN,         35
.equ EINTR,          4
.equ EFBIG,          27
.equ EDQUOT,         69
.equ ENOSPC,         28
.equ ENOTEMPTY,      66
.equ EINVAL,         22

// signals
.equ SIGALRM,        14
.equ SIGCHLD_,       20
.equ SIGPIPE_,       13
.equ SIG_IGN,        1
.equ SA_NOCLDWAIT,   0x0020

// request type ids
.equ GET_ID,     0
.equ HEAD_ID,    1
.equ OPTIONS_ID, 2
.equ BREW_ID,    3
.equ UNKNOWN_ID, 4

// unified resource type constants (embedded vs filesystem)
.equ RES_NONE,     0
.equ RES_EMBEDDED, 1
.equ RES_FILE,     2

// ── Request context offsets ────────────────────────────────────
// Functions take a pointer to request_ctx in x19/x20.
// Access fields via:  ldr xn, [ctx, #CTX_xxx]
.equ CTX_HEADER_LEN,      0
.equ CTX_CLIENT_FD,       8
.equ CTX_FILENAME_STR,    16
.equ CTX_FILENAME_LEN,    24
.equ CTX_QUERY_STR,       32
.equ CTX_QUERY_LEN,       40
.equ CTX_DOCROOT_LEN,     48
.equ CTX_REQUEST_ID,      56
.equ CTX_RESOURCE_TYPE,   64
.equ CTX_EMBED_CONTENT,   72
.equ CTX_EMBED_CT,        80
.equ CTX_EMBED_CT_LEN,    88
.equ CTX_EMBED_GZIP,      96
.equ CTX_EMBED_ETAG,      104
.equ CTX_EMBED_ETAG_LEN,  112
.equ CTX_FILE_DES,        120
.equ CTX_REQUEST_BUF,     128  // points to buf

.equ REQUEST_CTX_SIZE,    136

.equ BUF_SIZE,   16384

// struct timeval offsets (64-bit)
.equ OFF_TV_SEC,  0
.equ OFF_TV_USEC, 8

#endif

// ── Protocol-neutral request representation ─────────────────────────
// The seam between protocol parsers and the static handlers. A protocol
// parser (parse_request in parse.S for HTTP/1 today, an HTTP/2 HEADERS
// decoder later) fills this fixed-layout struct, and the handlers
// (get/head/options) consume it. Offsets are platform-independent.
// Storage lives in data.S as the `request` symbol.
.equ REQ_METHOD,       0    // method id: GET_ID / HEAD_ID / OPTIONS_ID
.equ REQ_PATH,         8    // ptr to docroot-prefixed, percent-decoded path
.equ REQ_PATH_LENGTH,  16
.equ REQ_QUERY,        24   // ptr to query string, or 0 if none
.equ REQ_QUERY_LENGTH, 32
.equ REQ_AUTHORITY,    40   // ptr to authority (Host) value, or 0 if none
.equ REQ_STREAM_ID,    48   // HTTP/2 stream id; HTTP/1 is always 0
.equ REQ_RANGE_PTR,    56   // ptr to the Range header value ("bytes=..."), or 0 (HTTP/2; Stage 10)
.equ REQ_RANGE_LEN,    64   // range value length
.equ REQ_FORBIDDEN,    72   // 1 = path rejected by server policy → reply 403 (Stage 10)
.equ REQUEST_SIZE,     80

// authority_buf (parse.S) holds a NUL-terminated copy of the request's
// authority — the HTTP/1 Host header or the HTTP/2 :authority
// pseudo-header. Both protocol parsers share the buffer and this bound.
.equ AUTHORITY_BUF_SIZE, 256

// ── Protocol-neutral response representation ─────────────────────────
// The seam between response generation and the protocol encoders. A
// handler (get/head/reply_status today, an HTTP/2 encoder later) fills
// this fixed-layout struct — resolve resource → create response — and
// the encoders (http1_write_response today) consume it. Offsets are
// platform-independent. Storage lives in data.S as the `response` symbol.
.equ RESP_STATUS,           0    // HTTP status code
.equ RESP_CONTENT_TYPE,     8    // ptr to content-type string
.equ RESP_CONTENT_TYPE_LEN, 16   // content-type string length
.equ RESP_CONTENT_LENGTH,   24   // total resource length (Content-Length, Content-Range total)
.equ RESP_BODY,             32   // ptr to body bytes to send
.equ RESP_BODY_LENGTH,      40   // body bytes to send (0 = headers only, e.g. HEAD)
.equ RESP_RANGE_START,      48   // inclusive start offset, -1 = no range
.equ RESP_RANGE_END,        56   // inclusive end offset, -1 = no range
.equ RESPONSE_SIZE,         64

// ── HTTP/2 frame engine (RFC 9113) ────────────────────────────────────
// Constants, struct offsets and defaults shared between the frame engine
// (http2.S) and the later stages (stream engine, HPACK, connection loop).

// connection modes — the protocol in use on a connection. HTTP/1 is the
// default (existing behaviour stays untouched); h2_verify_preface flips a
// connection to HTTP/2 once the client preface is confirmed.
.equ CONNECTION_HTTP1, 0
.equ CONNECTION_HTTP2, 1

// the 24-byte HTTP/2 client connection preface (RFC 9113 §3.4):
// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
.equ H2_PREFACE_LEN, 24

// frame types (§6)
.equ H2_FRAME_DATA,          0
.equ H2_FRAME_HEADERS,       1
.equ H2_FRAME_PRIORITY,      2
.equ H2_FRAME_RST_STREAM,    3
.equ H2_FRAME_SETTINGS,      4
.equ H2_FRAME_PUSH_PROMISE,  5
.equ H2_FRAME_PING,          6
.equ H2_FRAME_GOAWAY,        7
.equ H2_FRAME_WINDOW_UPDATE, 8
.equ H2_FRAME_CONTINUATION,  9

// frame flags (§6)
.equ H2_FLAG_ACK,         0x1  // SETTINGS/PING acknowledgement
.equ H2_FLAG_END_STREAM,  0x1  // DATA/HEADERS
.equ H2_FLAG_END_HEADERS, 0x4
.equ H2_FLAG_PADDED,      0x8
.equ H2_FLAG_PRIORITY,    0x20

// SETTINGS identifiers (§6.5.2)
.equ H2_SETTINGS_HEADER_TABLE_SIZE,       1
.equ H2_SETTINGS_ENABLE_PUSH,             2
.equ H2_SETTINGS_MAX_CONCURRENT_STREAMS,  3
.equ H2_SETTINGS_INITIAL_WINDOW_SIZE,     4
.equ H2_SETTINGS_MAX_FRAME_SIZE,          5
.equ H2_SETTINGS_MAX_HEADER_LIST_SIZE,    6

// error codes (§7)
.equ H2_ERR_NO_ERROR,            0
.equ H2_ERR_PROTOCOL_ERROR,      1
.equ H2_ERR_INTERNAL_ERROR,      2
.equ H2_ERR_FLOW_CONTROL_ERROR,  3
.equ H2_ERR_SETTINGS_TIMEOUT,    4
.equ H2_ERR_STREAM_CLOSED,       5
.equ H2_ERR_FRAME_SIZE_ERROR,    6
.equ H2_ERR_REFUSED_STREAM,      7
.equ H2_ERR_CANCEL,              8
.equ H2_ERR_COMPRESSION_ERROR,   9
.equ H2_ERR_CONNECT_ERROR,       10
.equ H2_ERR_ENHANCE_YOUR_CALM,   11
.equ H2_ERR_INADEQUATE_SECURITY, 12
.equ H2_ERR_HTTP_1_1_REQUIRED,   13

// frame header (§4.1) — one SETTINGS entry is 2-byte id + 4-byte value
.equ H2_WIRE_HEADER_LEN, 9
.equ H2_SETTINGS_ENTRY_LEN, 6
.equ H2_MAX_FRAME_SIZE,  0x00ffffff // 2^24 - 1, absolute wire limit
.equ H2_DEFAULT_MAX_FRAME_SIZE, 16384 // 2^14, initial SETTINGS_MAX_FRAME_SIZE
.equ H2_DEFAULT_HEADER_TABLE_SIZE, 4096
.equ H2_DEFAULT_INITIAL_WINDOW_SIZE, 65535 // 2^16 - 1

// parsed frame header struct (16 bytes) — filled by h2_parse_frame_header
.equ H2F_LENGTH,     0   // u32 payload length
.equ H2F_TYPE,       4   // u32 frame type
.equ H2F_FLAGS,      8   // u32 flags
.equ H2F_STREAM_ID,  12  // u32 stream id (31-bit, R bit masked off)
.equ H2F_SIZE,       16

// HTTP/2 connection state struct (h2_conn, 112 bytes)
.equ H2C_LAST_FRAME_TYPE,                0   // last dispatched frame type
.equ H2C_MAX_RX_FRAME_SIZE,              8   // max payload we accept (2^14 default)
.equ H2C_SETTINGS_HEADER_TABLE_SIZE,     16  // peer's settings — RFC 9113 §6.5.2 defaults
.equ H2C_SETTINGS_ENABLE_PUSH,           24
.equ H2C_SETTINGS_MAX_CONCURRENT_STREAMS, 32
.equ H2C_SETTINGS_INITIAL_WINDOW_SIZE,   40
.equ H2C_SETTINGS_MAX_FRAME_SIZE,        48
.equ H2C_SETTINGS_MAX_HEADER_LIST_SIZE,  56
.equ H2C_ACK_RECEIVED,                   64  // 1 once a SETTINGS ACK arrives
.equ H2C_LAST_STREAM_ID,                 72  // largest client-initiated stream id seen (§5.1.1)
.equ H2C_WINDOW,                         80  // u64 connection-level send window (§5.2; Stage 11)
.equ H2C_FD,                             88  // u64 client fd — the PING ACK / GOAWAY reply
                                            //   writers use (Stage 13; -1 when idle)
.equ H2C_GOAWAY_RECEIVED,                96  // u64 1 once a GOAWAY arrives from the client
                                            //   (§6.8; Stage 13) — new streams then refused
.equ H2C_GOAWAY_LAST_STREAM_ID,          104 // u64 the peer's last processed client stream id
.equ H2C_SIZE,                           112

// the largest a flow-control window may reach: 2^31 - 1 (RFC 9113 §5.2,
// §6.9). A WINDOW_UPDATE that would push a window above this is a
// FLOW_CONTROL_ERROR.
.equ H2_MAX_FLOW_WINDOW, 0x7fffffff

// ── HTTP/2 stream engine (RFC 9113 §5) ───────────────────────────────
// Stream states (§5.1), as observed by the receiving endpoint. Rows of
// the h2_stream_event transition table; HPACK/flow control stages later
// add the fields they need to each entry.
.equ H2_STREAM_IDLE,               0
.equ H2_STREAM_OPEN,               1
.equ H2_STREAM_HALF_CLOSED_REMOTE, 2
.equ H2_STREAM_HALF_CLOSED_LOCAL,  3
.equ H2_STREAM_CLOSED,             4

// stream events — the receive-side inputs to h2_stream_event
.equ H2_EVENT_RECV_HEADERS,    0
.equ H2_EVENT_RECV_DATA,       1
.equ H2_EVENT_RECV_END_STREAM, 2
.equ H2_EVENT_RECV_RST_STREAM, 3
.equ H2_EVENT_COUNT,           4

// the fixed stream table (§5.1.2): H2_MAX_STREAMS entries of H2S_SIZE
// bytes each. An entry is free when stream_id == 0 — wire stream ids
// are never zero, so 0 is unambiguous. Finished (CLOSED) entries are
// recycled by h2_stream_create once the connection outgrows its initial
// table, so one connection can serve far more than H2_MAX_STREAMS
// requests (Stage 12).
.equ H2_MAX_STREAMS, 32

// how many client-initiated streams may be open (not CLOSED) at once
// (RFC 9113 §5.1.2). The server advertises this in its opening SETTINGS
// frame and refuses a HEADERS frame that would open a new stream past
// the limit with GOAWAY(ENHANCE_YOUR_CALM). Matches the fixed stream
// table size, so the table can always hold a full quota of open streams.
.equ MAX_CONCURRENT_STREAMS, 32
.equ H2S_STREAM_ID,  0    // u64 stream id
.equ H2S_STATE,      8    // u64 one of H2_STREAM_*
.equ H2S_FLAGS,      16   // u64 frame flags (END_STREAM, ...)
.equ H2S_WINDOW,     24   // u64 stream send window (§5.2; Stage 11) — the
                          //   flow-control credit the client has granted this
                          //   stream; drained by DATA sends, replenished by
                          //   WINDOW_UPDATE. Initialised from the peer's
                          //   SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2).
.equ H2S_SIZE,       32

// ── HPACK (RFC 7541) — Stage 7 ──────────────────────────────────────
// Minimal HPACK: the RFC 7541 Appendix A static table plus the
// Appendix B static Huffman code. The dynamic table is disabled — the
// opening SETTINGS frame advertises SETTINGS_HEADER_TABLE_SIZE = 0
// (http2.S) and the decoder never stores entries: literal fields with
// incremental indexing (§6.2.1) are accepted but treated like the
// non-indexed forms, because an entry added to a zero-size table is
// evicted immediately. Huffman-coded strings (§5.2) are decoded with
// the fixed Appendix B table; decoded output goes into
// h2_hpack_str_buf (h2_hpack.S). Indices beyond the static table, size
// updates above 0 (§6.3) and padding violations are rejected with
// H2_ERR_COMPRESSION_ERROR (RFC 9113 §4.3).

.equ H2_HPACK_STATIC_TABLE_SIZE, 61  // RFC 7541 Appendix A
.equ H2_HPACK_HEADER_TABLE_SIZE,  0  // our decoder's dynamic-table max

// decoded Huffman strings land in this buffer (h2_hpack.S); the HPACK
// decode of one header block may produce at most this many decoded
// bytes. Fields keep pointers into it until h2_build_request copies
// out the pseudo-headers it needs.
.equ H2_HPACK_STR_BUF_SIZE, 4096

// one header-table entry (static or, later, dynamic) — 32 bytes
.equ H2_HPACK_ENTRY_NAME_PTR,  0
.equ H2_HPACK_ENTRY_NAME_LEN,  8
.equ H2_HPACK_ENTRY_VALUE_PTR, 16
.equ H2_HPACK_ENTRY_VALUE_LEN, 24
.equ H2_HPACK_ENTRY_SIZE,      32

// one decoded header field (h2_hpack_fields entry) — 32 bytes
.equ H2_HPACK_FIELD_NAME_PTR,  0
.equ H2_HPACK_FIELD_NAME_LEN,  8
.equ H2_HPACK_FIELD_VALUE_PTR, 16
.equ H2_HPACK_FIELD_VALUE_LEN, 24
.equ H2_HPACK_FIELD_SIZE,      32

// the fixed decode output area holds at most this many fields per block
.equ H2_HPACK_MAX_FIELDS, 32
