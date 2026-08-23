#include "config.S"

// macros

#ifdef __linux__
// ELF: a bare symbol on adrp already means its page, and :lo12: is the
// page offset. GNU as also spells the first one :pg_hi21:, but clang's
// integrated assembler does not accept that form, so the bare symbol is
// used here — it assembles under both, which is what lets the tree be
// cross-assembled for Linux from a macOS host.
.macro adr_l, reg, sym
    adrp \reg, \sym
    add \reg, \reg, :lo12:\sym
.endm

.macro ldr_l reg, sym, scratch=x9
    adrp \scratch, \sym
    ldr \reg, [\scratch, :lo12:\sym]
.endm

.macro str_l src, sym, scratch=x9
    adrp \scratch, \sym
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

// ── rodata — read-only static data (docs/SECURITY.md §13, Step 13) ───
// Everything this tree emits used to land in writable `.data`: the
// embedded assets, the certificate, the private scalar, the SHA-256
// round constants, the P-256 field constants and comb table, every
// dispatch table and every response string. A write primitive anywhere
// could rewrite served content, retarget a `br` through a handler
// table, or replace the key in place. None of that data is written by
// the server, so none of it needs to be writable.
//
// `rodata` opens the platform's read-only section. `.data` still means
// what it always did, and the files that use it are the ones that
// really do hold mutable state — connection state, staging buffers,
// scratch. docs/SECURITY.md §13 has the split, and
// tests/test_hardening.sh checks the resulting binary rather than the
// sources.
//
// Mach-O: __DATA_CONST,__const rather than __TEXT,__const, for two
// reasons. It holds pointers (the frame-handler and HPACK static
// tables) which need chained-fixup rebasing in a PIE, and __TEXT is
// r-x — data does not belong in an executable mapping. dyld applies the
// fixups and then drops __DATA_CONST to r-- (SG_READ_ONLY).
//
// ELF: .rodata, which the linker places in the r-- LOAD segment.
//
// -DSARM_NO_RODATA sends everything back to writable .data. It exists
// for one caller: tests/test_hardening.sh builds a control binary with
// it, so that "the constants are in a read-only section" is a check
// that has been seen to fail rather than a check that has only ever
// been seen to pass.
#ifdef SARM_NO_RODATA
.macro rodata
    .data
.endm
#elif defined(__linux__)
.macro rodata
    .section .rodata,"a",%progbits
.endm
#else
.macro rodata
    .section __DATA_CONST,__const
.endm
#endif

// (c)ompare and (b)ranch, (eq/ne/gt/etc), x0, x1, label
.macro cb cond, r1, r2, l
    cmp \r1, \r2
    b.\cond \l
.endm

// ── Checked length arithmetic (docs/SECURITY.md §3.5) ───────────────
// Bounds in this tree are enforced by comparing against a pre-computed
// end pointer, which is sound only while the sum that produced the
// compared value cannot wrap. These three macros make that reasoning
// local instead of global: the check sits on the instruction that does
// the arithmetic, so a reviewer does not have to re-derive the width of
// every input to know the result is trustworthy.
//
// docs/SECURITY.md §3.5 classifies every wire-derived length
// site in the tree and says which of them use these.

// ckadd — d = a + b, branching away on unsigned wraparound.
//   The `adds`/`b.cs` idiom from docs/SECURITY.md §3.5 "Integer overflow
//   in length arithmetic". Use for any sum of two attacker-influenced
//   lengths, whatever their nominal widths.
.macro ckadd d, a, b, l
    adds \d, \a, \b
    b.cs \l
.endm

// ckrange — d = base + len, branching away if that wraps *or* runs past
//   end. The whole "does this field fit?" question in one place: the
//   wrap check makes the comparison meaningful even when len is not
//   width-limited, which is exactly the case a length taken from the
//   wire stops guaranteeing the moment it is composed with anything.
//   `end` is one past the last readable byte, so base + len == end is
//   the largest field that fits.
.macro ckrange d, base, len, end, l
    adds \d, \base, \len
    b.cs \l
    cmp \d, \end
    b.hi \l
.endm

// ckfits — like ckrange but discards the sum: "len bytes fit between
//   base and end" as a pure predicate, for the cases that only need to
//   validate before reading and do not want the cursor yet.
.macro ckfits base, len, end, l, s=x9
    ckrange \s, \base, \len, \end, \l
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
.equ SYS_recvfrom,     207
// getrandom(buf, len, flags): the kernel CSPRNG without a file
// descriptor. flags = 0 blocks until the pool is seeded, which is
// the property /dev/urandom does not give you early in boot.
.equ SYS_getrandom,    278

// socket stuff
.equ AF_INET,          2
.equ SOCK_STREAM,      1
.equ SOL_SOCKET,       1
.equ MSG_PEEK,         0x02
.equ SO_REUSEADDR,     2
.equ SO_RCVTIMEO,      20
// Linux doesn't have SO_NOSIGPIPE; we ignore SIGPIPE instead.
.equ SO_NOSIGPIPE,     -1

// prlimit64(pid, resource, new_limit, old_limit) — arm64 Linux has no
// setrlimit; this is the only limit-setting call in the table.
.equ SYS_prlimit64,    261

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
.equ ENOTSUP,        95  // EOPNOTSUPP alias on Linux
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
// ITIMER_REAL — the wall-clock interval timer setitimer(2) arms.
// Expiry raises SIGALRM, whose default disposition is to terminate
// without a core dump. main.S arms it once per forked connection child
// (CONN_DEADLINE), which is what bounds that child's lifetime.
.equ ITIMER_REAL,    0

// RLIMIT_CORE — the core-dump size limit main.S sets to zero at startup
// (docs/SECURITY.md §13.2). A core of this process is a
// complete memory disclosure, private scalar and traffic keys included.
// The number is 4 on both platforms; only the syscall differs, because
// arm64 Linux has no setrlimit — the generic syscall table carries
// prlimit64(pid, resource, new, old) instead, with pid 0 meaning self.
.equ RLIMIT_CORE,    4
.equ SIGPIPE_,       13
.equ SIGINT_,        2
.equ SIGTERM_,       15
.equ SIG_IGN,        1

// For SA_NOCLDWAIT on Linux ARM64, we just set SIGCHLD to SIG_IGN
// which has the same effect on Linux (auto-reap children).
// SA_NOCLDWAIT is #defined as 2 for most Linux archs including arm64.
.equ SA_NOCLDWAIT,   2

// request type ids
.equ GET_ID,     0
.equ HEAD_ID,    1
.equ OPTIONS_ID, 2
.equ UNKNOWN_ID, 3

// resource type constants
.equ RES_NONE,     0
.equ RES_EMBEDDED, 1

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
// sigreturn(ucontext, infostyle) — the tail of a macOS signal
// trampoline. libc's _sigtramp calls it; a raw-syscall program that
// installs its own handler has to supply the trampoline (sa_tramp)
// and therefore this call too (Plan.md Phase 3, Step 16).
.equ SYS_sigreturn,    184
.equ SYS_execve,       59
.equ SYS_munmap,       73
.equ SYS_setitimer,    83
.equ SYS_setrlimit,    195
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
.equ SYS_recvfrom,     29
// getentropy(buf, len): the kernel CSPRNG without a file
// descriptor. Returns 0 on success and caps len at 256 bytes per
// call (EINVAL above that -- confirmed on this machine, not
// assumed), so callers loop.
.equ SYS_getentropy,   500

// sysctlbyname(name, namelen, oldp, oldlenp, newp, newlen) — the raw
// syscall takes the name length libc's wrapper would compute for you.
// Used only by detect_cpus (`--workers auto`, Plan.md Phase 3 Step 14).
.equ SYS_sysctlbyname, 274

// socket
.equ AF_INET,          2
.equ SOCK_STREAM,      1
.equ SOL_SOCKET,       0xFFFF
.equ SO_REUSEADDR,     4
.equ SO_RCVTIMEO,      0x1006
.equ SO_NOSIGPIPE,     0x1022
.equ MSG_PEEK,         0x02

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
.equ ENOTSUP,        45  // distinct from EOPNOTSUPP (102) on macOS

// signals
.equ SIGALRM,        14
.equ SIGCHLD_,       20
// ITIMER_REAL — see the Linux block above.
.equ ITIMER_REAL,    0

// RLIMIT_CORE — see the Linux block above. Same number, and macOS does
// have setrlimit(resource, &rlimit).
.equ RLIMIT_CORE,    4
.equ SIGPIPE_,       13
.equ SIGINT_,        2
.equ SIGTERM_,       15
.equ SIG_IGN,        1
.equ SA_NOCLDWAIT,   0x0020

// request type ids
.equ GET_ID,     0
.equ HEAD_ID,    1
.equ OPTIONS_ID, 2
.equ UNKNOWN_ID, 3

// resource type constants
.equ RES_NONE,     0
.equ RES_EMBEDDED, 1

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

// authority_buf (parse/data.S) holds a NUL-terminated copy of the
// request's authority — the HTTP/1 Host header or the HTTP/2 :authority
// pseudo-header. Both protocol parsers share the buffer and this bound.
.equ AUTHORITY_BUF_SIZE, 256

// ── parse module shared constants ────────────────────────────────────
// Sizes shared between parse_path and parse_h2_path (src/parse/). The
// buffers themselves live in src/parse/data.S; the length constants are
// per-file .equ values, so they live here (included by every file).
.equ www_prefix_len, 4        // strlen(DOCROOT) = "www/" — keep in sync with config.S
.equ default_file_len, 10     // strlen(DEFAULT_FILE) = "index.html" — keep in sync with config.S
.equ filename_buf_size, 4096  // PATH_MAX-sized filename buffer
.equ query_buf_size, 4096     // max query-string size

// ── util module shared constants ─────────────────────────────────────
// itoa (src/util/itoa.S) writes decimal digits backwards into a buffer
// the *caller* owns, so the size has to be visible to every call site.
// 20 bytes is the widest possible result: itoa divides with udiv, so the
// input is unsigned and UINT64_MAX formats as 20 digits.
// ITOA_BUF_STACK is that rounded up to the 16-byte stack alignment,
// which is what a caller reserving frame space should use.
.equ ITOA_BUF_SIZE,  20
.equ ITOA_BUF_STACK, 32

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
// §6.2 — the optional priority field on a HEADERS frame: 4-byte stream
// dependency (top bit exclusive) + 1-byte weight, ahead of the block
.equ H2_PRIORITY_FIELD_LEN, 5
.equ H2_MAX_FRAME_SIZE,  0x00ffffff // 2^24 - 1, absolute wire limit
.equ H2_DEFAULT_MAX_FRAME_SIZE, 16384 // 2^14, initial SETTINGS_MAX_FRAME_SIZE
.equ H2_DEFAULT_HEADER_TABLE_SIZE, 4096
.equ H2_DEFAULT_INITIAL_WINDOW_SIZE, 65535 // 2^16 - 1

// h2 module shared scratch buffers (src/h2/data.S). The size constants
// are per-file .equ values used by several h2 functions, so they live
// here (included by every file) rather than next to the .skip.
.equ h2_frame_buf_size, H2_WIRE_HEADER_LEN + H2_DEFAULT_MAX_FRAME_SIZE
// h2_wait_buf holds one *incoming* frame read by h2_write_body's
// flow-control wait loop: the 9-byte wire header first, then the payload
// over the top of it. h2_validate_frame caps that payload at
// H2C_MAX_RX_FRAME_SIZE, whose initial (and only) value is
// H2_DEFAULT_MAX_FRAME_SIZE, so the same sizing as h2_frame_buf covers
// both reads with room to spare.
.equ h2_wait_buf_size, H2_WIRE_HEADER_LEN + H2_DEFAULT_MAX_FRAME_SIZE
.equ h2_range_buf_size, 64  // copy of the request's Range header value
.equ h2_cr_buf_size, 64     // scratch for the content-range value

// H2_HEADERS_STAGE_MAX — the largest complete HEADERS frame (9-byte wire
// header + HPACK block) that h2_stage_headers will leave sitting in
// h2_frame_buf for h2_write_body to send in front of the first DATA
// frame, turning two write syscalls per response into one. A response's
// block is a few dozen bytes (:status, content-type, content-length, and
// at most content-range + content-encoding), so this is a ceiling that
// normal traffic never approaches; anything above it is written on its
// own, exactly as before. The bound is what lets h2_frame_buf hold
// HEADERS + the DATA header at once, and what keeps the TLS path's
// transport_writev_scratch sized (see src/transport/data.S).
.equ H2_HEADERS_STAGE_MAX, 256

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
.equ H2S_FLAGS,      16   // u64 frame flags (END_STREAM, ...), plus the
                          //   server-internal H2S_FLAG_SERVING above them
// Set while h2_process_request is writing this stream's response, and
// cleared when it finishes. Writing a response can block on flow control,
// and h2_write_body keeps dispatching client frames while it waits — so
// the "this stream's request is ready to serve" test (state ==
// HALF_CLOSED_REMOTE) can be true for a stream already being served, and
// a WINDOW_UPDATE arriving on it would otherwise re-enter the handler and
// send the response a second time, recursively. Deliberately above the
// 8-bit wire flags so it can share the field without colliding.
.equ H2S_FLAG_SERVING, 0x100
.equ H2S_WINDOW,     24   // u64 stream send window (§5.2; Stage 11) — the
                          //   flow-control credit the client has granted this
                          //   stream; drained by DATA sends, replenished by
                          //   WINDOW_UPDATE. Initialised from the peer's
                          //   SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2).
.equ H2S_SIZE,       32

// ── HPACK (RFC 7541) — Stage 7 ──────────────────────────────────────
// The RFC 7541 Appendix A static table plus the Appendix B static
// Huffman code, backed by a real, bounded dynamic table (§2.3.2, §4):
// the opening SETTINGS frame advertises SETTINGS_HEADER_TABLE_SIZE =
// H2_HPACK_HEADER_TABLE_SIZE (4096, the RFC 9113 §6.5.2 protocol
// default) and the decoder actually stores what a compliant encoder
// inserts. This isn't optional polish — a real client's encoder
// doesn't learn our preference until it has processed our SETTINGS
// frame (a round trip), so any requests it fires before then (exactly
// what a browser does: HEADERS for every same-page resource, back to
// back, on one connection) are encoded assuming the protocol default
// of 4096 is available. A decoder that never stores entries can't
// resolve the indexed references those early requests make to
// repeated header values (:authority, cookie, user-agent, ...), and
// HPACK's shared per-connection compression context means one
// unresolvable index poisons the *whole connection* (RFC 9113 §4.3) —
// not just the request that triggered it.
// Huffman-coded strings (§5.2) are decoded with the fixed Appendix B
// table; decoded output goes into h2_hpack_str_buf (h2_hpack.S).
// Indices beyond the combined static+dynamic space, size updates above
// our advertised maximum (§6.3) and padding violations are rejected
// with H2_ERR_COMPRESSION_ERROR (RFC 9113 §4.3).

.equ H2_HPACK_STATIC_TABLE_SIZE, 61  // RFC 7541 Appendix A
.equ H2_HPACK_HEADER_TABLE_SIZE,  H2_DEFAULT_HEADER_TABLE_SIZE  // our
    // decoder's dynamic-table max (4096) — also the byte capacity of
    // the dynamic table's arena (h2_hpack_dyn_bytes), since the raw
    // name+value bytes stored can never exceed the RFC size total,
    // which is itself capped at this max.

// one dynamic-table entry (h2_hpack_dyn_entries) — just the lengths;
// the bytes live in h2_hpack_dyn_bytes at an offset derived by summing
// the lengths of the older live entries (see dynamic_table/lookup.S)
.equ H2_HPACK_DYN_ENTRY_NAME_LEN,  0
.equ H2_HPACK_DYN_ENTRY_VALUE_LEN, 8
.equ H2_HPACK_DYN_ENTRY_SIZE,      16

// worst case: H2_HPACK_HEADER_TABLE_SIZE / 32 (the smallest possible
// RFC 7541 §4.1 entry size — empty name and value still cost the fixed
// 32-byte overhead). Must be a power of 2 — the FIFO index arithmetic
// (dynamic_table/*.S) wraps it with a mask, not a division.
.equ H2_HPACK_DYN_CAP_ENTRIES, (H2_HPACK_HEADER_TABLE_SIZE / 32)

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

// ── TLS 1.3 (RFC 8446) ─────────────────────────────────────────────
// Wire-format constants for the TLS 1.3 server. All values are
// platform-independent; the TLS connection state struct (tls_state) is
// defined further down.

// protocol versions (§4.1.2, §5.1). The ClientHello legacy_version and
// the record-layer legacy_record_version are both 0x0303 even for TLS
// 1.3 — the real version is negotiated through the supported_versions
// extension (0x0304). The record layer also accepts 0x0301 (TLS 1.0)
// because an initial ClientHello is carried in a 0x0301 record (§5.1).
.equ TLS_VERSION_1_0, 0x0301
.equ TLS_VERSION_1_2, 0x0303
.equ TLS_VERSION_1_3, 0x0304

// cipher suites (§B.4). The only suite this server implements.
.equ TLS_CIPHER_AES_128_GCM_SHA256, 0x1301

// named groups (§4.2.7 / RFC 7919 §A): X25519 for the ECDHE key
// exchange, secp256r1 (P-256) for the ECDSA certificate chain.
.equ NAMED_GROUP_SECP256R1, 0x0017
.equ NAMED_GROUP_X25519,    0x001D

// signature schemes (§4.2.3): ecdsa_secp256r1_sha256 — the scheme the
// server's CertificateVerify uses and the client must advertise.
.equ SIG_ECDSA_SECP256R1_SHA256, 0x0403

// ALPN (§3.3 / RFC 7301): the protocol this server negotiates is "h2"
// (2 bytes). The string itself lives in src/tls/data.S (tls_alpn_h2).
.equ TLS_ALPN_H2_LEN, 2

// SNI (RFC 6066 §3): the one hostname this server currently answers
// for — no virtual-host infrastructure yet. The
// string itself lives in src/tls/data.S (tls_sni_hostname).
.equ TLS_SNI_HOSTNAME_LEN, 9  // "localhost"

// record layer (§5): content types
.equ TLS_RECORD_CHANGE_CIPHER_SPEC, 20  // 0x14
.equ TLS_RECORD_ALERT,              21  // 0x15
.equ TLS_RECORD_HANDSHAKE,          22  // 0x16
.equ TLS_RECORD_APPLICATION_DATA,   23  // 0x17
.equ TLS_RECORD_HEADER_LEN, 5  // type(1) + legacy_record_version(2) + length(2)
.equ TLS_MAX_PLAINTEXT, 16384  // 2^14 — plaintext record payload limit (§5.2)

// record-layer limits (§5.2). A TLSPlaintext fragment is at most 2^14;
// a TLSCiphertext may reach 2^14 + 256 on the wire, but with AES-128-GCM
// (16-byte tag) and a single TLSInnerPlaintext.type byte the largest
// record this server can produce or open is 2^14 + 1 + 16.
.equ TLS_TAG_LEN,          16     // AES-128-GCM authentication tag (§5.3)
.equ TLS_INNER_TYPE_LEN,   1      // TLSInnerPlaintext.type (§5.2)
.equ TLS_MAX_CIPHERTEXT,   16640  // 2^14 + 256 — the wire limit (§5.2)
.equ TLS_MAX_AEAD,         16401  // 2^14 + 1 + 16 — AES-128-GCM record max

// record-layer error codes — the x0 return value of tls_record_parse /
// tls_record_write / tls_record_encrypt / tls_record_decrypt when the
// carry flag is set. Distinct from errno and from the alert
// descriptions above; later phases map them to RFC 8446 alerts
// (TLS_RECORD_ERR_LENGTH → record_overflow, TLS_RECORD_ERR_MAC →
// bad_record_mac, TLS_RECORD_ERR_* → decode_error/unexpected_message).
.equ TLS_RECORD_ERR_SHORT,   1  // fewer than TLS_RECORD_HEADER_LEN bytes
.equ TLS_RECORD_ERR_TYPE,    2  // content type not 20/21/22/23
.equ TLS_RECORD_ERR_VERSION, 3  // legacy_record_version not 0x0301/0x0303
.equ TLS_RECORD_ERR_LENGTH,  4  // fragment length exceeds the limit
.equ TLS_RECORD_ERR_BOUNDS,  5  // fragment runs past the buffer end
.equ TLS_RECORD_ERR_MAC,     6  // AEAD tag mismatch
.equ TLS_RECORD_ERR_INNER,   7  // no non-zero octet / bad inner type
.equ TLS_RECORD_ERR_EMPTY,   8  // zero-length handshake/alert content

// handshake message types (§4)
.equ TLS_HS_CLIENT_HELLO,         1
.equ TLS_HS_SERVER_HELLO,         2
.equ TLS_HS_NEW_SESSION_TICKET,   4
.equ TLS_HS_END_OF_EARLY_DATA,    5
.equ TLS_HS_ENCRYPTED_EXTENSIONS, 8
.equ TLS_HS_CERTIFICATE,          11
.equ TLS_HS_CERTIFICATE_REQUEST,  13
.equ TLS_HS_CERTIFICATE_VERIFY,   15
.equ TLS_HS_FINISHED,             20
.equ TLS_HS_KEY_UPDATE,           24
.equ TLS_HS_MESSAGE_HASH,         254
.equ TLS_HS_HEADER_LEN, 4  // type(1) + length(3)

// alert levels (§6.2)
.equ TLS_ALERT_WARNING, 1
.equ TLS_ALERT_FATAL,   2

// alert descriptions (§6.2) — the full RFC 8446 registry
.equ TLS_ALERT_CLOSE_NOTIFY,              0
.equ TLS_ALERT_UNEXPECTED_MESSAGE,        10
.equ TLS_ALERT_BAD_RECORD_MAC,            20
.equ TLS_ALERT_RECORD_OVERFLOW,           22
.equ TLS_ALERT_HANDSHAKE_FAILURE,         40
.equ TLS_ALERT_BAD_CERTIFICATE,           42
.equ TLS_ALERT_UNSUPPORTED_CERTIFICATE,   43
.equ TLS_ALERT_CERTIFICATE_REVOKED,       44
.equ TLS_ALERT_CERTIFICATE_EXPIRED,       45
.equ TLS_ALERT_CERTIFICATE_UNKNOWN,       46
.equ TLS_ALERT_ILLEGAL_PARAMETER,         47
.equ TLS_ALERT_UNKNOWN_CA,                48
.equ TLS_ALERT_ACCESS_DENIED,             49
.equ TLS_ALERT_DECODE_ERROR,              50
.equ TLS_ALERT_DECRYPT_ERROR,             51
.equ TLS_ALERT_PROTOCOL_VERSION,          70
.equ TLS_ALERT_INSUFFICIENT_SECURITY,     71
.equ TLS_ALERT_INTERNAL_ERROR,            80
.equ TLS_ALERT_INAPPROPRIATE_FALLBACK,    86
.equ TLS_ALERT_USER_CANCELED,             90
.equ TLS_ALERT_MISSING_EXTENSION,         109
.equ TLS_ALERT_UNSUPPORTED_EXTENSION,     110
.equ TLS_ALERT_UNRECOGNIZED_NAME,         112
.equ TLS_ALERT_BAD_CERT_STATUS_RESPONSE,  113
.equ TLS_ALERT_UNKNOWN_PSK_IDENTITY,      115
.equ TLS_ALERT_CERTIFICATE_REQUIRED,      116
.equ TLS_ALERT_NO_APPLICATION_PROTOCOL,   120

// extensions (§4.2) — the full RFC 8446 registry. The ClientHello
// parser (Phase 12) acts on a few of these and skips the rest by
// length.
.equ TLS_EXT_SERVER_NAME,                0
.equ TLS_EXT_MAX_FRAGMENT_LENGTH,        1
.equ TLS_EXT_STATUS_REQUEST,             5
.equ TLS_EXT_SUPPORTED_GROUPS,           10
.equ TLS_EXT_SIGNATURE_ALGORITHMS,       13
.equ TLS_EXT_USE_SRTP,                   14
.equ TLS_EXT_HEARTBEAT,                  15
.equ TLS_EXT_ALPN,                       16
.equ TLS_EXT_SIGNED_CERT_TIMESTAMP,      18
.equ TLS_EXT_CLIENT_CERT_TYPE,           19
.equ TLS_EXT_SERVER_CERT_TYPE,           20
.equ TLS_EXT_PADDING,                    21
.equ TLS_EXT_PRE_SHARED_KEY,             41
.equ TLS_EXT_EARLY_DATA,                 42
.equ TLS_EXT_SUPPORTED_VERSIONS,         43
.equ TLS_EXT_COOKIE,                     44
.equ TLS_EXT_PSK_KEY_EXCHANGE_MODES,     45
.equ TLS_EXT_CERTIFICATE_AUTHORITIES,    47
.equ TLS_EXT_OID_FILTERS,                48
.equ TLS_EXT_POST_HANDSHAKE_AUTH,        49
.equ TLS_EXT_SIGNATURE_ALGORITHMS_CERT,  50
.equ TLS_EXT_KEY_SHARE,                  51

// handshake state machine — the value of tls_state's handshake_state
// field. The server advances this in lockstep with the messages it
// sends and receives; phases 12-19 drive it. Names track the last
// message sent (TLS_HS_* handshake types above).
.equ TLS_HS_START,       0  // awaiting ClientHello
.equ TLS_HS_CH_RECEIVED, 1  // ClientHello received & validated
.equ TLS_HS_SH_SENT,     2  // ServerHello sent — handshake traffic keys live
.equ TLS_HS_EE_SENT,     3  // EncryptedExtensions sent
.equ TLS_HS_CERT_SENT,   4  // Certificate sent
.equ TLS_HS_CV_SENT,     5  // CertificateVerify sent
.equ TLS_HS_FIN_SENT,    6  // our Finished sent — awaiting the client's
.equ TLS_HS_CONNECTED,   7  // client Finished verified — application data
.equ TLS_HS_FAILED,      8  // handshake aborted — connection must close

// ── TLS connection state (tls_state) ───────────────────────────────
// Per-connection TLS 1.3 state. Fixed layout; storage
// lives in src/tls/data.S as `tls_state`, with one tls_* label per
// field so the unit test (test_tls.c) can verify each offset against
// real storage. Offsets are platform-independent. Only the state the
// server actually needs lives here — everything else stays stack-local
// in the phase that uses it.

// field sizes (bytes)
.equ TLS_RANDOM_LEN,    32  // client_random / server_random (§4.1.2)
.equ TLS_KEY_SHARE_LEN, 32  // X25519 public key (§4.2.8)
.equ TLS_SECRET_LEN,    32  // handshake/master secret — SHA-256-sized HKDF
                            //   output (RFC 8446 §7.1, with SHA-256)
.equ TLS_DIGEST_LEN,    32  // transcript hash — SHA-256 (§4.4.1)
.equ TLS_KEY_LEN,       16  // AES-128 key
.equ TLS_IV_LEN,        12  // AES-GCM nonce (§5.3)
.equ TLS_IV_STRIDE,     16  // storage stride per IV: 12 bytes + 4 pad so
                            //   the following 16-byte key stays 16-aligned
.equ TLS_SEQ_LEN,       8   // u64 record sequence number (§5.3)
.equ TLS_ALPN_BUF,      16  // negotiated ALPN name buffer ("h2" + NUL + pad)

// field offsets. Scalars are u64s; byte arrays are sized by the
// constants above. Every field starts 8-aligned, keys/seqs 16-aligned.
.equ TLS_FD,                0   // u64 client socket fd; -1 while unset
.equ TLS_HS_STATE,          8   // u64 one of TLS_HS_START..TLS_HS_FAILED
.equ TLS_CLIENT_RANDOM,     16  // 32 B — the client's random (§4.1.2)
.equ TLS_SERVER_RANDOM,     48  // 32 B — our random
.equ TLS_CLIENT_KEY_SHARE,  80  // 32 B — X25519 public key from the
                                //   client's key_share extension
.equ TLS_SERVER_KEY_SHARE,  112 // 32 B — our X25519 public key
.equ TLS_SHARED_SECRET,     144 // 32 B — ECDHE shared secret (X25519)
.equ TLS_TRANSCRIPT_HASH,   176 // 32 B — running SHA-256 of the handshake
                                //   (Phase 9)
.equ TLS_HANDSHAKE_SECRET,  208 // 32 B — HKDF-derived (Phase 10)
.equ TLS_MASTER_SECRET,     240 // 32 B — HKDF-derived (Phase 10)
.equ TLS_CLIENT_HS_KEY,     272 // 16 B — AES-128 handshake traffic key
.equ TLS_CLIENT_HS_IV,      288 // 12 B — handshake traffic IV
.equ TLS_SERVER_HS_KEY,     304 // 16 B — AES-128 handshake traffic key
.equ TLS_SERVER_HS_IV,      320 // 12 B — handshake traffic IV
.equ TLS_CLIENT_APP_KEY,    336 // 16 B — AES-128 application traffic key
.equ TLS_CLIENT_APP_IV,     352 // 12 B — application traffic IV
.equ TLS_SERVER_APP_KEY,    368 // 16 B — AES-128 application traffic key
.equ TLS_SERVER_APP_IV,     384 // 12 B — application traffic IV
.equ TLS_CLIENT_SEQ,        400 // u64 — client→server record sequence (§5.3)
.equ TLS_SERVER_SEQ,        408 // u64 — server→client record sequence
.equ TLS_ALPN_LEN,          416 // u64 — negotiated ALPN name length (0 = none)
.equ TLS_ALPN,              424 // 16 B — negotiated ALPN name ("h2")
.equ TLS_SESSION_ID_LEN,    440 // u64 — length of the client's
                                //   legacy_session_id, 0..32 (§4.1.2)
.equ TLS_SESSION_ID,        448 // 32 B — echoed verbatim in ServerHello's
                                //   legacy_session_id_echo (§4.1.3)
.equ TLS_SERVER_HS_TRAFFIC_SECRET, 480 // 32 B — server_handshake_traffic_
                                //   secret (Phase 10), persisted as the
                                //   Finished BaseKey (Phase 18, §4.4.4)
.equ TLS_CLIENT_HS_TRAFFIC_SECRET, 512 // 32 B — client_handshake_traffic_
                                //   secret (Phase 10), persisted as the
                                //   BaseKey for verifying the client's own
                                //   Finished (Phase 20, §4.4.4) — Phase 10
                                //   originally treated this as transient
                                //   scratch since nothing needed it again
                                //   until the live handshake driver does
.equ TLS_STATE_SIZE,        544

// ── SHA-256 streaming context (sha256_ctx) ──────────────────────────
// Streaming SHA-256: sha256_init / sha256_update /
// sha256_final operate on this fixed layout. Storage lives in
// src/crypto/data.S as `sha256_ctx`, with one sha256_ctx_* label per
// field so the unit test (test_sha256.c) can verify each offset against
// real storage. State words are plain native u32s holding big-endian
// values — the exact format sha256_h256 / sha256 use — so the
// compression function can work on the context in place.
.equ SHA256_CTX_STATE,   0   // 32 B — H0..H7 (native u32, big-endian value)
.equ SHA256_CTX_BITLEN,  32  // u64 — total message bits so far (FIPS 180-4
                             //   length field, mod 2^64)
.equ SHA256_CTX_BUF,     40  // 64 B — partial block (0..63 valid bytes)
.equ SHA256_CTX_BUFLEN,  104 // u64 — valid bytes in BUF
.equ SHA256_CTX_SIZE,    112

// ── HKDF input limits (RFC 5869 §2.3, RFC 8446 §7.1) ────────────────
// The bounds hkdf_expand and hkdf_expand_label enforce at runtime
// (Step 5). Each is a property of a fixed stack buffer or of a
// single-octet wire field, not a tuning knob: changing one means
// changing the buffer it protects.
.equ HKDF_EXPAND_MAX_INFO,  607  // 32 + info + 1 must fit the 640-byte
                                 //   assembled HMAC input buffer
.equ HKDF_EXPAND_MAX_OKM,   8160 // 255 * 32 — the counter is one octet
.equ HKDF_LABEL_MAX_LABEL,  249  // 6 + label must fit one octet
.equ HKDF_LABEL_MAX_CONTEXT, 255 // context length is one octet

