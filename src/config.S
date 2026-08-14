// Default docroot, relative to ymawky's current working environment.
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
.equ RECV_TIMEOUT, 10

// Maximum number of active, concurrent processes allowed.
// This is entirely up to you and how many processes your computer can handle.
// Note that currently, proc_info() will fail to recognize greater than 512
// processes. This is because proc_info has to write into a buffer, we gave it
// 2048 bytes. 2048 / 4 = 512 max procs. If you want more, you gotta increase
// the buffer in ymawky.S. I'll leave that as an exercise to the reader.
// Default: 256
.equ MAX_PROCS, 256

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
