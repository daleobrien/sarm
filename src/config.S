// Default docroot, relative to sarm's current working environment.
// Note that this needs the trailing /.
// Default: www/
#define DOCROOT "www/"

// Directory to search for custom error HTML pages in the embedded table.
// Pages are embedded from www/err/ at build time — no filesystem reads.
// Note that this needs the trailing /.
// Default: www/err/
#define ERR_DIR "www/err/"

// When receiving a "GET /" request with no filename, what file should be GOT?
// Default: index.html
#define DEFAULT_FILE "index.html"

// Maximum size, in bytes, for a response header. Will usually be less.
// Default: 512 bytes
.equ RESPONSE_HEADER_SIZE, 512

// Maximum time, in seconds, without receiving any data before closing the
// connection. Also acts as the total header timeout — if a client takes
// longer than this between any two read() calls, the connection is closed.
// Default: 10 seconds
//
// Overridable at build time (`-DRECV_TIMEOUT_SECONDS=N`) so a test can
// exercise the timeout without waiting the shipped default — see the
// `variant` target in the Makefile and tests/test_limits.sh.
#ifndef RECV_TIMEOUT_SECONDS
#define RECV_TIMEOUT_SECONDS 10
#endif
.equ RECV_TIMEOUT, RECV_TIMEOUT_SECONDS

// Maximum total wall-clock lifetime, in seconds, of one connection —
// the hard ceiling on how long a single client can hold a forked child,
// counted from accept() and enforced by SIGALRM (setitimer(ITIMER_REAL)
// armed in main.S's Lmain_child).
//
// RECV_TIMEOUT alone does not bound this. It is a per-read timeout: a
// client that sends one byte every RECV_TIMEOUT-1 seconds restarts it
// forever, and so holds a process, a file descriptor and a 160 KB
// resident image for as long as it likes. The same is true of a TLS
// handshake dribbled a record at a time, and of the unbounded run of
// change_cipher_spec records RFC 8446 Appendix D.4 requires the server
// to tolerate. This is the bound that makes those finite — see
// docs/security/resource-limits.md (Step 12).
//
// It applies to the forked child only, never to a worker or to `no_fork`
// debug mode, so an expiry costs exactly one connection.
// Default: 120 seconds
//
// Overridable at build time (`-DCONN_DEADLINE_SECONDS=N`) for the same
// reason RECV_TIMEOUT is: tests/test_limits.sh asserts the mechanism on
// a short-deadline variant binary, and asserts this default separately
// by reading it out of this file.
#ifndef CONN_DEADLINE_SECONDS
#define CONN_DEADLINE_SECONDS 120
#endif
.equ CONN_DEADLINE, CONN_DEADLINE_SECONDS

// Maximum number of HTTP/1 requests served on one kept-alive connection
// before sarm sends Connection: close and ends it. Bounds how long a
// single forked child can occupy a process slot under keep-alive — see
// "The ceiling" in Plan.md.
// Default: 100
.equ HTTP1_KEEPALIVE_BUDGET, 100

// Upper bound on `--workers N` (Plan.md Phase 3, Step 14): the number of
// pre-forked processes that sit in accept() on the shared listening
// socket. Nothing stops you raising it, but past the core count the
// workers just take turns, and each one is another process the kernel
// wakes on an incoming connection.
//
// This replaces the old MAX_PROCS, which was vestigial: it bounded
// nothing (no code read it) and its comment described a proc_info()
// buffer in a sarm.S that no longer exists.
// Default: 64
.equ MAX_WORKERS, 64

// Allow GET /dir to list the directory's contents, or just 403?
// 0: Do not allow directory contents to be listed.
// 1 (or anything non-zero): Yes, allow directory contents to be listed
// Default: 1
.equ ALLOW_DIR_LISTING, 1

// ── Transport mode (PLAN.MD §1.3) ──────────────────────────────────
// The transport seam (src/transport/) can deliver bytes over raw TCP
// (TRANSPORT_PLAIN) or, once implemented in later phases, TLS
// (TRANSPORT_TLS). PLAIN is the default and the only mode with an
// implementation today. TRANSPORT_MODE is the compile-time default the
// runtime `transport_mode` global (src/transport/data.S) is initialised
// from, so a future runtime switch can override it without recompiling.
.equ TRANSPORT_PLAIN, 0
.equ TRANSPORT_TLS,   1
.equ TRANSPORT_MODE,  TRANSPORT_PLAIN
