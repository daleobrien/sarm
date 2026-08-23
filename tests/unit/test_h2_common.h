// Shared helpers for the HTTP/2 unit tests (test_h2_*.c).
// Constants, struct layouts, asm wrappers and support functions that
// mirror src/defs.S, src/data.S and src/hpack/. Each test file
// includes this header and gets its own copy of every static helper,
// so the per-executable harness counters keep working unchanged.
//
// NOTE: avoids libc string.h/stdlib.h per test_harness.h guidance.

#ifndef TEST_H2_COMMON_H
#define TEST_H2_COMMON_H

#include "test_harness.h"

// ── HTTP/2 constants, mirroring defs.S ─────────────────────────────
#define H2_FRAME_DATA          0
#define H2_FRAME_HEADERS       1
#define H2_FRAME_PRIORITY      2
#define H2_FRAME_RST_STREAM    3
#define H2_FRAME_SETTINGS      4
#define H2_FRAME_PUSH_PROMISE  5
#define H2_FRAME_PING          6
#define H2_FRAME_GOAWAY        7
#define H2_FRAME_WINDOW_UPDATE 8
#define H2_FRAME_CONTINUATION  9

#define CONNECTION_HTTP1 0
#define CONNECTION_HTTP2 1

#define H2_PREFACE_LEN 24

#define H2_SETTINGS_HEADER_TABLE_SIZE       1
#define H2_SETTINGS_ENABLE_PUSH             2
#define H2_SETTINGS_MAX_CONCURRENT_STREAMS  3
#define H2_SETTINGS_INITIAL_WINDOW_SIZE     4
#define H2_SETTINGS_MAX_FRAME_SIZE          5
#define H2_SETTINGS_MAX_HEADER_LIST_SIZE    6

#define H2_FLAG_ACK         0x1
#define H2_FLAG_END_STREAM  0x1
#define H2_FLAG_END_HEADERS 0x4
#define H2_FLAG_PADDED      0x8
#define H2_FLAG_PRIORITY    0x20

// request type ids, mirroring defs.S
#define GET_ID     0
#define HEAD_ID    1
#define OPTIONS_ID 2
#define UNKNOWN_ID 3

#define H2_ERR_NO_ERROR          0
#define H2_ERR_PROTOCOL_ERROR     1
#define H2_ERR_FLOW_CONTROL_ERROR 3
#define H2_ERR_STREAM_CLOSED      5
#define H2_ERR_FRAME_SIZE_ERROR   6
#define H2_ERR_REFUSED_STREAM     7
#define H2_ERR_CANCEL             8
#define H2_ERR_COMPRESSION_ERROR  9
#define H2_ERR_ENHANCE_YOUR_CALM  11

// RFC 9113 §6.5.2 default values
#define H2_DEF_HEADER_TABLE_SIZE       4096
#define H2_DEF_ENABLE_PUSH             1
#define H2_DEF_MAX_CONCURRENT_STREAMS  0xffffffff
#define H2_DEF_INITIAL_WINDOW_SIZE     65535
#define H2_DEF_MAX_FRAME_SIZE          16384
#define H2_DEF_MAX_HEADER_LIST_SIZE    0xffffffff

// ── stream constants, mirroring defs.S (§5) ────────────────────────
#define H2_MAX_STREAMS 32

// the server's advertised and enforced concurrent-stream limit (§5.1.2)
#define MAX_CONCURRENT_STREAMS 32

#define H2_STREAM_IDLE               0
#define H2_STREAM_OPEN               1
#define H2_STREAM_HALF_CLOSED_REMOTE 2
#define H2_STREAM_HALF_CLOSED_LOCAL  3
#define H2_STREAM_CLOSED             4

#define H2_EVENT_RECV_HEADERS    0
#define H2_EVENT_RECV_DATA       1
#define H2_EVENT_RECV_END_STREAM 2
#define H2_EVENT_RECV_RST_STREAM 3

#define H2S_STREAM_ID 0
#define H2S_STATE     8
#define H2S_FLAGS     16
#define H2S_WINDOW    24
#define H2S_SIZE      32

#define H2_STREAMS_BYTES (H2_MAX_STREAMS * H2S_SIZE)

// ── HPACK constants, mirroring defs.S (RFC 7541) ────────────────────
#define H2_HPACK_STATIC_TABLE_SIZE 61 // RFC 7541 Appendix A
#define H2_HPACK_FIELD_SIZE 32
#define H2_HPACK_MAX_FIELDS 32

#define H2_HPACK_FIELDS_BYTES (H2_HPACK_MAX_FIELDS * H2_HPACK_FIELD_SIZE)

// ── the 24-byte client connection preface (RFC 9113 §3.4) ─────────
// 25 bytes with the NUL terminator; only the first 24 are sent.
static const uint8_t H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── libc declarations (avoid <unistd.h>/<sys/socket.h> per harness) ─
extern int socketpair(int domain, int type, int protocol, int sv[2]);
extern long read(int fd, void *buf, unsigned long n);
extern long write(int fd, const void *buf, unsigned long n);
extern int close(int fd);
extern int pipe(int *fds);
extern int fork(void);
extern int waitpid(int pid, int *status, int options);
extern int usleep(unsigned int usec);
extern int fcntl(int fd, int cmd, ...);

#define AF_UNIX   1
#define SOCK_STREAM 1

// fcntl command and flag for the non-blocking "nothing arrived" probe
// (Stage 13 — a PING ACK must not be answered).
#define F_SETFL 4
#define O_NONBLOCK 0x0004

// ── structs, mirroring the H2F_*/H2C_*/H2S_* offsets in defs.S ──────
typedef struct {
	uint32_t length;
	uint32_t type;
	uint32_t flags;
	uint32_t stream_id;
} h2_frame_header_t;

typedef struct {
	int64_t last_frame_type;
	int64_t max_rx_frame_size;
	int64_t settings_header_table_size;
	int64_t settings_enable_push;
	int64_t settings_max_concurrent_streams;
	int64_t settings_initial_window_size;
	int64_t settings_max_frame_size;
	int64_t settings_max_header_list_size;
	int64_t ack_received;
	int64_t last_stream_id;
	int64_t window;   // Stage 11 — connection-level send window (§5.2)
	int64_t fd;       // Stage 13 — client fd (PING ACK / GOAWAY reply writers)
	int64_t goaway_received;     // Stage 13 — 1 once a GOAWAY arrives (§6.8)
	int64_t goaway_last_stream_id; // Stage 13 — peer's last processed stream id
} h2_conn_t;

// one entry of the fixed stream table (h2_streams)
typedef struct {
	int64_t stream_id;
	int64_t state;
	int64_t flags;
	int64_t window;
} h2_stream_t;

// one decoded header field (h2_hpack_fields entry) — mirrors the
// H2_HPACK_FIELD_* layout in defs.S
typedef struct {
	const uint8_t *name;
	int64_t name_len;
	const uint8_t *value;
	int64_t value_len;
} h2_hpack_field_t;

// ── the protocol-neutral request struct, mirroring the REQ_* offsets in
// defs.S. Storage lives in data.S as the symbol `request`; test_request.c
// shares this layout.
typedef struct {
	int64_t method;
	const char *path;
	int64_t path_length;
	const char *query;
	int64_t query_length;
	const char *authority;
	int64_t stream_id;
	const char *range_ptr;   // Stage 10 — Range header value, or NULL
	int64_t range_len;
	int64_t forbidden;       // Stage 10 — 1 = server refused the path (403)
} request_t;

// ── Stage 9 — response encoder constants, mirroring defs.S ─────────
#define H2_WIRE_HEADER_LEN 9
#define H2_DEFAULT_MAX_FRAME_SIZE 16384

#define RESP_STATUS           0
#define RESP_CONTENT_TYPE     8
#define RESP_CONTENT_TYPE_LEN 16
#define RESP_CONTENT_LENGTH   24
#define RESP_BODY             32
#define RESP_BODY_LENGTH      40

// the protocol-neutral response struct, mirroring the RESP_* offsets in
// defs.S. test_response.c shares this layout.
typedef struct {
	int64_t status;
	const char *content_type;
	int64_t content_type_len;
	int64_t content_length;
	const char *body;
	int64_t body_length;
	int64_t range_start;
	int64_t range_end;
} response_t;

// ── globals from data.S consulted by the response encoder ──────────
extern int64_t clientfd          __asm__("clientfd");
extern int64_t resource_type     __asm__("resource_type");
extern int64_t embedded_gzip     __asm__("embedded_gzip");
extern int64_t embedded_etag     __asm__("embedded_etag");
extern int64_t embedded_etag_len __asm__("embedded_etag_len");

static inline const request_t *request_addr(void) {
	request_t *p;
	asm volatile(
		"adrp x0, request@PAGE\n"
		"add  x0, x0, request@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

#define REQ (request_addr())

#define LITLEN(s) ((int64_t)(sizeof(s) - 1))

// a minimal valid request header block: :method GET, :path / — both
// static-table indices, so this is the smallest block that passes
// h2_build_request's pseudo-header validation.
static const uint8_t H2_REQ_BLOCK[] = { 0x82, 0x84 };
#define H2_REQ_BLOCK_LEN ((int64_t)sizeof(H2_REQ_BLOCK))

// ── wire frame builders ────────────────────────────────────────────

// Write a 9-byte big-endian frame header (RFC 9113 §4.1).
static void put_wire_header(uint8_t *p, uint32_t length, uint8_t type,
                            uint8_t flags, uint32_t stream_id) {
	p[0] = (uint8_t)(length >> 16);
	p[1] = (uint8_t)(length >> 8);
	p[2] = (uint8_t)length;
	p[3] = type;
	p[4] = flags;
	p[5] = (uint8_t)(stream_id >> 24);
	p[6] = (uint8_t)(stream_id >> 16);
	p[7] = (uint8_t)(stream_id >> 8);
	p[8] = (uint8_t)stream_id;
}

// Write one 6-byte SETTINGS entry (2-byte id + 4-byte value, big-endian).
static void put_setting(uint8_t *p, uint16_t id, uint32_t value) {
	p[0] = (uint8_t)(id >> 8);
	p[1] = (uint8_t)id;
	p[2] = (uint8_t)(value >> 24);
	p[3] = (uint8_t)(value >> 16);
	p[4] = (uint8_t)(value >> 8);
	p[5] = (uint8_t)value;
}

// RFC 7541 §5.1 — encode an integer into a prefix of `bits` bits.
// Returns the number of bytes written; the first octet's bits above the
// prefix are zero (callers may OR in pattern bits).
static int put_hpack_int(uint8_t *p, uint32_t value, int bits) {
	int mask = (1 << bits) - 1;
	if (value < (uint32_t)mask) {
		p[0] = (uint8_t)value;
		return 1;
	}
	p[0] = (uint8_t)mask;
	value -= (uint32_t)mask;
	int n = 1;
	while (value >= 128) {
		p[n++] = (uint8_t)((value % 128) + 128);
		value /= 128;
	}
	p[n++] = (uint8_t)value;
	return n;
}

// ── wrappers for asm functions ─────────────────────────────────────

// h2_parse_frame_header(wire=x0, hdr=x1)
static inline void h2_parse_wrapper(const uint8_t *wire, h2_frame_header_t *hdr) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"bl h2_parse_frame_header\n"
		:: "r"(wire), "r"(hdr)
		: "x0", "x1", "x2", "x3", "x4", "x5", "memory");
}

// h2_validate_frame(hdr=x0, conn=x1) → (rc=x0, carry)
static inline int64_t h2_validate_wrapper(h2_frame_header_t *hdr,
                                          h2_conn_t *conn, int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_validate_frame\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(hdr), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "memory");
	*carry_out = carry;
	return rc;
}

// h2_dispatch_frame(hdr=x0, payload=x1, conn=x2) → (rc=x0, carry)
static inline int64_t h2_dispatch_wrapper(h2_frame_header_t *hdr,
                                          const uint8_t *payload,
                                          h2_conn_t *conn, int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"mov x2, %4\n"
		"bl h2_dispatch_frame\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(hdr), "r"(payload), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x30", "memory");
	*carry_out = carry;
	return rc;
}

// ── helpers ────────────────────────────────────────────────────────

// Restore the RFC 9113 §6.5.2 defaults into a test connection struct.
static void reset_conn(h2_conn_t *conn) {
	conn->last_frame_type = 0;
	conn->max_rx_frame_size = H2_DEF_MAX_FRAME_SIZE;
	conn->settings_header_table_size = H2_DEF_HEADER_TABLE_SIZE;
	conn->settings_enable_push = H2_DEF_ENABLE_PUSH;
	conn->settings_max_concurrent_streams = H2_DEF_MAX_CONCURRENT_STREAMS;
	conn->settings_initial_window_size = H2_DEF_INITIAL_WINDOW_SIZE;
	conn->settings_max_frame_size = H2_DEF_MAX_FRAME_SIZE;
	conn->settings_max_header_list_size = H2_DEF_MAX_HEADER_LIST_SIZE;
	conn->ack_received = 0;
	conn->last_stream_id = 0;
	conn->window = H2_DEF_INITIAL_WINDOW_SIZE; // connection window (§5.2)
	conn->fd = -1;                 // no connection attached (Stage 13)
	conn->goaway_received = 0;
	conn->goaway_last_stream_id = 0;
}

// ── h2_conn defaults baked into data.S ─────────────────────────────

static inline h2_conn_t *h2_conn_addr(void) {
	h2_conn_t *p;
	asm volatile(
		"adrp x0, h2_conn@PAGE\n"
		"add  x0, x0, h2_conn@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

// ── connection_mode / h2_preface accessors (data.S) ────────────────

static inline int64_t connection_mode_value(void) {
	int64_t v;
	asm volatile(
		"adrp x0, connection_mode@PAGE\n"
		"add  x0, x0, connection_mode@PAGEOFF\n"
		"ldr  %0, [x0]\n"
		: "=r"(v)
		:: "x0", "memory");
	return v;
}

static inline void set_connection_mode(int64_t mode) {
	asm volatile(
		"adrp x0, connection_mode@PAGE\n"
		"add  x0, x0, connection_mode@PAGEOFF\n"
		"str  %0, [x0]\n"
		:: "r"(mode)
		: "x0", "memory");
}

static inline const uint8_t *h2_preface_addr(void) {
	const uint8_t *p;
	asm volatile(
		"adrp x0, h2_preface@PAGE\n"
		"add  x0, x0, h2_preface@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

static inline const uint8_t *h2_settings_frame_addr(void) {
	const uint8_t *p;
	asm volatile(
		"adrp x0, h2_settings_frame@PAGE\n"
		"add  x0, x0, h2_settings_frame@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

// ── Stage 6 wrappers for asm functions ─────────────────────────────

static inline h2_stream_t *h2_streams_addr(void) {
	h2_stream_t *p;
	asm volatile(
		"adrp x0, h2_streams@PAGE\n"
		"add  x0, x0, h2_streams@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

// Zero the whole stream table — a fresh connection in tests.
static void reset_streams(void) {
	memset(h2_streams_addr(), 0, H2_STREAMS_BYTES);
}

// h2_stream_find(id=x0) → pointer to the entry, or NULL
static inline h2_stream_t *h2_stream_find_wrapper(int64_t id) {
	h2_stream_t *p;
	asm volatile(
		"mov x0, %1\n"
		"bl h2_stream_find\n"
		"mov %0, x0\n"
		: "=r"(p)
		: "r"(id)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x9", "memory");
	return p;
}

// h2_stream_create(id=x0, conn=x1) → (ptr=x0, carry)
static inline h2_stream_t *h2_stream_create_wrapper(int64_t id, h2_conn_t *conn,
                                                    int64_t *carry_out) {
	h2_stream_t *p;
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_stream_create\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(p), "=r"(carry)
		: "r"(id), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "memory");
	*carry_out = carry;
	return p;
}

// h2_validate_stream_id(hdr=x0, conn=x1) → (rc=x0, carry)
static inline int64_t h2_validate_stream_id_wrapper(h2_frame_header_t *hdr,
                                                    h2_conn_t *conn,
                                                    int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_validate_stream_id\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(hdr), "r"(conn)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x9", "memory");
	*carry_out = carry;
	return rc;
}

// h2_stream_event(stream=x0, event=x1) → (rc=x0, carry)
static inline int64_t h2_stream_event_wrapper(h2_stream_t *s, int64_t event,
                                              int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_stream_event\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(s), "r"(event)
		: "x0", "x1", "x2", "x3", "x4", "x9", "memory");
	*carry_out = carry;
	return rc;
}

// ── Stage 5 wrappers for asm functions ─────────────────────────────

// h2_verify_preface(fd=x0, buf=x1) → (rc=x0, carry)
static inline int64_t h2_verify_preface_wrapper(int64_t fd, uint8_t *buf,
                                                int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_verify_preface\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(fd), "r"(buf)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
		  "memory");
	*carry_out = carry;
	return rc;
}

// h2_send_settings(fd=x0) → (rc=x0, carry)
static inline int64_t h2_send_settings_wrapper(int64_t fd, int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"bl h2_send_settings\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(fd)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
		  "memory");
	*carry_out = carry;
	return rc;
}

// ── Stage 7 wrappers for asm functions (h2_hpack.S) ────────────────

// The HPACK decoders take the end of the enclosing header block and
// refuse to read past it (Step 5, docs/SECURITY.md §3.5). The
// _end wrappers below pass a real bound; the plain wrappers pass an
// unbounded one, so the Stage 7 tests keep asking exactly what they
// asked before the bound existed. The bound itself is what
// tests/security/test_overflow_hpack.c is for — with a guard page just
// past the block, so a read that escapes it faults instead of passing.
#define HPACK_NO_BOUND ((const uint8_t *)~(uintptr_t)0)

// h2_hpack_decode_int(ptr=x0, n=x1, end=x2) → (value=x0, consumed=x1, carry)
static inline int64_t h2_hpack_decode_int_end_wrapper(const uint8_t *p, int64_t n,
                                                      const uint8_t *end,
                                                      int64_t *consumed_out,
                                                      int64_t *carry_out) {
	int64_t value, consumed, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %3\n"
		"mov x1, %4\n"
		"mov x2, %5\n"
		"bl h2_hpack_decode_int\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"cset %2, cs\n"
		: "=r"(value), "=r"(consumed), "=r"(carry)
		: "r"(p), "r"(n), "r"(end)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "memory");
	*consumed_out = consumed;
	*carry_out = carry;
	return value;
}

static inline int64_t h2_hpack_decode_int_wrapper(const uint8_t *p, int64_t n,
                                                  int64_t *consumed_out,
                                                  int64_t *carry_out) {
	return h2_hpack_decode_int_end_wrapper(p, n, HPACK_NO_BOUND,
	                                       consumed_out, carry_out);
}

// h2_hpack_decode_string(ptr=x0, end=x1) → (str=x0, len=x1, consumed=x2, carry)
static inline const uint8_t *h2_hpack_decode_string_end_wrapper(const uint8_t *p,
                                                                const uint8_t *end,
                                                                int64_t *len_out,
                                                                int64_t *consumed_out,
                                                                int64_t *carry_out) {
	const uint8_t *s;
	int64_t len, consumed, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %4\n"
		"mov x1, %5\n"
		"bl h2_hpack_decode_string\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"cset %3, cs\n"
		: "=r"(s), "=r"(len), "=r"(consumed), "=r"(carry)
		: "r"(p), "r"(end)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		  "x19", "x20", "x21", "x22", "x30", "memory");
	*len_out = len;
	*consumed_out = consumed;
	*carry_out = carry;
	return s;
}

static inline const uint8_t *h2_hpack_decode_string_wrapper(const uint8_t *p,
                                                            int64_t *len_out,
                                                            int64_t *consumed_out,
                                                            int64_t *carry_out) {
	return h2_hpack_decode_string_end_wrapper(p, HPACK_NO_BOUND, len_out,
	                                          consumed_out, carry_out);
}

// h2_hpack_static_lookup(idx=x0) → (name=x0, name_len=x1, value=x2,
//                                  value_len=x3, carry)
static inline const uint8_t *h2_hpack_static_lookup_wrapper(int64_t idx,
                                                            int64_t *name_len_out,
                                                            const uint8_t **value_out,
                                                            int64_t *value_len_out,
                                                            int64_t *carry_out) {
	const uint8_t *name, *value;
	int64_t name_len, value_len, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %5\n"
		"bl h2_hpack_static_lookup\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"mov %3, x3\n"
		"cset %4, cs\n"
		: "=r"(name), "=r"(name_len), "=r"(value), "=r"(value_len),
		  "=r"(carry)
		: "r"(idx)
		: "x0", "x1", "x2", "x3", "x4", "x9", "memory");
	*name_len_out = name_len;
	*value_out = value;
	*value_len_out = value_len;
	*carry_out = carry;
	return name;
}

// h2_hpack_decode_field(ptr=x0) → (next=x0, name=x1, name_len=x2,
//                                  value=x3, value_len=x4, carry)
static inline const uint8_t *h2_hpack_decode_field_end_wrapper(const uint8_t *p,
                                                               const uint8_t *end,
                                                               const uint8_t **name_out,
                                                               int64_t *name_len_out,
                                                               const uint8_t **value_out,
                                                               int64_t *value_len_out,
                                                               int64_t *carry_out) {
	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %6\n"
		"mov x1, %7\n"
		"bl h2_hpack_decode_field\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"mov %3, x3\n"
		"mov %4, x4\n"
		"cset %5, cs\n"
		: "=r"(next), "=r"(name), "=r"(name_len), "=r"(value),
		  "=r"(value_len), "=r"(carry)
		: "r"(p), "r"(end)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
		  "x30", "memory");
	*name_out = name;
	*name_len_out = name_len;
	*value_out = value;
	*value_len_out = value_len;
	*carry_out = carry;
	return next;
}

static inline const uint8_t *h2_hpack_decode_field_wrapper(const uint8_t *p,
                                                           const uint8_t **name_out,
                                                           int64_t *name_len_out,
                                                           const uint8_t **value_out,
                                                           int64_t *value_len_out,
                                                           int64_t *carry_out) {
	return h2_hpack_decode_field_end_wrapper(p, HPACK_NO_BOUND, name_out,
	                                         name_len_out, value_out,
	                                         value_len_out, carry_out);
}

// h2_hpack_dyn_reset() — resets the dynamic table to empty, max restored
// to H2_HPACK_HEADER_TABLE_SIZE. Tests call this for a deterministic
// starting state, mirroring what h2_connection_loop does per connection.
static inline void h2_hpack_dyn_reset_wrapper(void) {
	asm volatile("bl h2_hpack_dyn_reset" ::: "x9", "x10", "memory");
}

// h2_hpack_table_lookup(idx=x0) → (name=x0, name_len=x1, value=x2,
//                                  value_len=x3, carry)
static inline const uint8_t *h2_hpack_table_lookup_wrapper(int64_t idx,
                                                            int64_t *name_len_out,
                                                            const uint8_t **value_out,
                                                            int64_t *value_len_out,
                                                            int64_t *carry_out) {
	const uint8_t *name, *value;
	int64_t name_len, value_len, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %5\n"
		"bl h2_hpack_table_lookup\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"mov %3, x3\n"
		"cset %4, cs\n"
		: "=r"(name), "=r"(name_len), "=r"(value), "=r"(value_len),
		  "=r"(carry)
		: "r"(idx)
		: "x0", "x1", "x2", "x3", "x4", "x9", "x10", "x11", "x12", "x13",
		  "x14", "x15", "x16", "memory");
	*name_len_out = name_len;
	*value_out = value;
	*value_len_out = value_len;
	*carry_out = carry;
	return name;
}

// h2_hpack_dyn_insert(name=x0, name_len=x1, value=x2, value_len=x3)
static inline void h2_hpack_dyn_insert_wrapper(const uint8_t *name,
                                               int64_t name_len,
                                               const uint8_t *value,
                                               int64_t value_len) {
	asm volatile(
		"mov x0, %0\n"
		"mov x1, %1\n"
		"mov x2, %2\n"
		"mov x3, %3\n"
		"bl h2_hpack_dyn_insert\n"
		:
		: "r"(name), "r"(name_len), "r"(value), "r"(value_len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x30", "memory");
}

// h2_hpack_dyn_resize(new_max=x0)
static inline void h2_hpack_dyn_resize_wrapper(int64_t new_max) {
	asm volatile(
		"mov x0, %0\n"
		"bl h2_hpack_dyn_resize\n"
		:
		: "r"(new_max)
		: "x0", "x1", "x2", "x3", "x4", "x9", "x10", "x11", "x12", "x13",
		  "x30", "memory");
}

// h2_hpack_decode_block(ptr=x0, len=x1) → (count=x0, carry)
static inline int64_t h2_hpack_decode_block_wrapper(const uint8_t *p, int64_t len,
                                                    int64_t *carry_out) {
	int64_t count, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_hpack_decode_block\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(count), "=r"(carry)
		: "r"(p), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x19", "x20", "x21", "x22", "x30", "memory");
	*carry_out = carry;
	return count;
}

// h2_huffman_decode(ptr=x0, len=x1) → (str=x0, out_len=x1, consumed=x2,
//                                     carry)
static inline const uint8_t *h2_huffman_decode_wrapper(const uint8_t *p, int64_t n,
                                                      int64_t *len_out,
                                                      int64_t *consumed_out,
                                                      int64_t *carry_out) {
	const uint8_t *s;
	int64_t len, consumed, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %4\n"
		"mov x1, %5\n"
		"bl h2_huffman_decode\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"cset %3, cs\n"
		: "=r"(s), "=r"(len), "=r"(consumed), "=r"(carry)
		: "r"(p), "r"(n)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		  "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x30", "memory");
	*len_out = len;
	*consumed_out = consumed;
	*carry_out = carry;
	return s;
}

// ── Stage 8 wrappers for asm functions ──────────────────────────────

// h2_build_request(stream_id=x0, count=x1) → (rc=x0, carry). The function
// runs parse_h2_path (parse.S), decode_url / check_path_* (file.S) and
// memcpy (util.S), so the clobber list covers every register those touch.
static inline int64_t h2_build_request_wrapper(int64_t stream_id, int64_t count,
                                              int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_build_request\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(stream_id), "r"(count)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x30", "memory");
	*carry_out = carry;
	return rc;
}

// parse_request(buf=x0, len=x1) → carry — the HTTP/1 side of the 8.4
// equivalence tests (parse.o, the same function the server uses).
static inline int64_t parse_request_wrapper(const char *buf, int64_t len) {
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"bl parse_request\n"
		"cset %0, cs\n"
		: "=r"(carry)
		: "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
		  "memory");
	return carry;
}

// ── Stage 9 wrappers for asm functions ──────────────────────────────

// h2_probe(buf=x0, n=x1) → (rc=x0)
static inline int64_t h2_probe_wrapper(const uint8_t *buf, int64_t n) {
	int64_t rc;
	asm volatile(
		"mov x0, %1\n"
		"mov x1, %2\n"
		"bl h2_probe\n"
		"mov %0, x0\n"
		: "=r"(rc)
		: "r"(buf), "r"(n)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x9", "x30", "memory");
	return rc;
}

// h2_write_headers(fd=x0, resp=x1, stream_id=x2, flags=x3) → (carry)
static inline int64_t h2_write_headers_wrapper(int64_t fd, const response_t *resp,
                                              int64_t stream_id, int64_t flags) {
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"mov x2, %3\n"
		"mov x3, %4\n"
		"bl h2_write_headers\n"
		"cset %0, cs\n"
		: "=r"(carry)
		: "r"(fd), "r"(resp), "r"(stream_id), "r"(flags)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		  "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x30", "memory");
	return carry;
}

// h2_write_body(fd=x0, resp=x1, stream_id=x2, staged=x3) → (carry).
// staged is the length of a HEADERS frame already sitting in
// h2_frame_buf; these tests exercise the body on its own, so it is 0.
static inline int64_t h2_write_body_wrapper(int64_t fd, const response_t *resp,
                                           int64_t stream_id) {
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"mov x2, %3\n"
		"mov x3, #0\n"
		"bl h2_write_body\n"
		"cset %0, cs\n"
		: "=r"(carry)
		: "r"(fd), "r"(resp), "r"(stream_id)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		  "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x30", "memory");
	return carry;
}

// h2_process_request(stream_id=x0, fd=x1) → (rc=x0, carry). Runs
// lookup_embedded (file.S), create_response (get.S) and the encoder,
// so the clobber list covers every register those touch.
static inline int64_t h2_process_request_wrapper(int64_t stream_id, int64_t fd,
                                                int64_t *carry_out) {
	int64_t rc, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl h2_process_request\n"
		"mov %0, x0\n"
		"cset %1, cs\n"
		: "=r"(rc), "=r"(carry)
		: "r"(stream_id), "r"(fd)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x30",
		  "memory");
	*carry_out = carry;
	return rc;
}

// h2_parse_range(ptr=x0, len=x1) → (start=x0, end=x1, carry)
static inline int64_t h2_parse_range_wrapper(const char *v, int64_t len,
                                             int64_t *end_out, int64_t *carry_out) {
	int64_t start, end, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %3\n"
		"mov x1, %4\n"
		"bl h2_parse_range\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"cset %2, cs\n"
		: "=r"(start), "=r"(end), "=r"(carry)
		: "r"(v), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
		  "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x30", "memory");
	*end_out = end;
	*carry_out = carry;
	return start;
}

// h2_resolve_range(start=x0, end=x1, size=x2) → (start=x0, end=x1,
//                                                status=x2)
static inline int64_t h2_resolve_range_wrapper(int64_t start, int64_t end,
                                               int64_t size, int64_t *end_out,
                                               int64_t *status_out) {
	int64_t s, e, st;
	asm volatile(
		"mov x0, %3\n"
		"mov x1, %4\n"
		"mov x2, %5\n"
		"bl h2_resolve_range\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		: "=r"(s), "=r"(e), "=r"(st)
		: "r"(start), "r"(end), "r"(size)
		: "x0", "x1", "x2", "x3", "x4", "x5", "memory");
	*end_out = e;
	*status_out = st;
	return s;
}

// h2_connection_loop(fd=x0, buf=x1, n=x2) → (carry). Runs the whole
// connection lifecycle: preface verification, SETTINGS, the frame loop
// and the request processing hook (h2_process_request → encoders).
static inline int64_t h2_connection_loop_wrapper(int64_t fd, uint8_t *buf,
                                                int64_t n) {
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"mov x2, %3\n"
		"bl h2_connection_loop\n"
		"cset %0, cs\n"
		: "=r"(carry)
		: "r"(fd), "r"(buf), "r"(n)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "x19", "x20", "x21", "x22", "x23", "x30", "memory");
	return carry;
}

static inline h2_hpack_field_t *h2_hpack_fields_addr(void) {
	h2_hpack_field_t *p;
	asm volatile(
		"adrp x0, h2_hpack_fields@PAGE\n"
		"add  x0, x0, h2_hpack_fields@PAGEOFF\n"
		"mov  %0, x0\n"
		: "=r"(p)
		:: "x0");
	return p;
}

// Zero the whole decoded-field area — a fresh decode in tests.
static void reset_fields(void) {
	memset(h2_hpack_fields_addr(), 0, H2_HPACK_FIELDS_BYTES);
}

// ── stream state helpers ───────────────────────────────────────

static h2_stream_t *stream_in_state(h2_conn_t *conn, int64_t id,
                                    int64_t state) {
	reset_streams();
	reset_conn(conn);
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(id, conn, &carry);
	if (s == NULL)
		return NULL;
	s->state = state;
	return s;
}

// ── HPACK decode helpers ───────────────────────────────────────

static void check_field(const char *label, int64_t carry,
                        const uint8_t *name, int64_t name_len,
                        const uint8_t *value, int64_t value_len,
                        const char *exp_name, const char *exp_value) {
	size_t en = 0, ev = 0;
	while (exp_name[en]) en++;
	while (exp_value[ev]) ev++;
	if (carry != 0) {
		_FAIL("%s — decode failed (carry set)", label);
	} else if (name_len != (int64_t)en ||
	           memcmp(name, exp_name, (unsigned long)en) != 0) {
		_FAIL("%s — wrong name", label);
	} else if (value_len != (int64_t)ev ||
	           memcmp(value, exp_value, (unsigned long)ev) != 0) {
		_FAIL("%s — wrong value", label);
	} else {
		_PASS(label);
	}
}

static void check_string(const char *label, int64_t carry, const uint8_t *s,
                         int64_t len, const char *exp, int64_t consumed,
                         int64_t exp_consumed) {
	size_t n = 0;
	while (exp[n]) n++;
	if (carry != 0) {
		_FAIL("%s — decode failed (carry set)", label);
	} else if (len != (int64_t)n || memcmp(s, exp, (unsigned long)n) != 0) {
		_FAIL("%s — wrong string", label);
	} else if (consumed != exp_consumed) {
		_FAIL("%s — consumed %lld, expected %lld", label,
		      (long long)consumed, (long long)exp_consumed);
	} else {
		_PASS(label);
	}
}

static void check_int(const char *label, const uint8_t *bytes, int64_t prefix,
                      int64_t exp_value, int64_t exp_consumed) {
	int64_t consumed, carry;
	int64_t got = h2_hpack_decode_int_wrapper(bytes, prefix, &consumed, &carry);
	if (carry != 0) {
		_FAIL("%s — decode failed (carry set)", label);
	} else if (got != exp_value) {
		_FAIL("%s — value %lld, expected %lld", label,
		      (long long)got, (long long)exp_value);
	} else if (consumed != exp_consumed) {
		_FAIL("%s — consumed %lld, expected %lld", label,
		      (long long)consumed, (long long)exp_consumed);
	} else {
		_PASS(label);
	}
}

static void check_field_error(const char *label, const uint8_t *next,
                              int64_t carry) {
	if (carry != 1 || (int64_t)(uintptr_t)next != H2_ERR_COMPRESSION_ERROR)
		_FAIL("%s — expected COMPRESSION_ERROR (carry=%lld, x0=%p)", label,
		      (long long)carry, (const void *)next);
	else
		_PASS(label);
}

// ── request-building helpers ────────────────────────────────────

static h2_hpack_field_t field(const char *name, const char *value) {
	h2_hpack_field_t f;
	size_t nl = 0, vl = 0;
	while (name[nl]) nl++;
	while (value[vl]) vl++;
	f.name = (const uint8_t *)name;
	f.name_len = (int64_t)nl;
	f.value = (const uint8_t *)value;
	f.value_len = (int64_t)vl;
	return f;
}

static void set_fields(const h2_hpack_field_t *fields, int n) {
	memcpy(h2_hpack_fields_addr(), fields,
	       (unsigned long)n * sizeof(h2_hpack_field_t));
}

// ── response-scanning helpers ───────────────────────────────────

static int64_t slen(const char *s) {
	int64_t n = 0;
	while (s[n]) n++;
	return n;
}

static inline void get_filetype_wrapper(const char *filename, int64_t len,
                                        const char **out_ct, int64_t *out_ct_len) {
	const char *ct;
	int64_t ct_len;
	asm volatile(
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl get_filetype\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		: "=r"(ct), "=r"(ct_len)
		: "r"(filename), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x19", "x20", "x21", "x22", "x23",
		  "memory");
	*out_ct = ct;
	*out_ct_len = ct_len;
}

// ── helpers for decoding h2_write_headers' HPACK blocks ────────────
// The encoder emits exactly four representations: 0x88 (:status 200),
// 0x08 <len> <digits> (literal :status), 0x0f <idx-15> <len> <value>
// (literal with a static name index > 15: content-type 31,
// content-length 28, content-range 30, content-encoding 26).

typedef struct {
	long count;
	long idx[8];
	const uint8_t *val[8];
	long vlen[8];
} hdr_scan_t;

static void hdr_collect(long idx, const uint8_t *v, long vlen, void *ctx) {
	hdr_scan_t *s = (hdr_scan_t *)ctx;
	if (s->count < 8) {
		s->idx[s->count] = idx;
		s->val[s->count] = v;
		s->vlen[s->count] = vlen;
		s->count++;
	}
}

// Decode a block produced by h2_write_headers into hdr_scan_t; returns
// the number of block bytes consumed (so the DATA frame offset can be
// derived as 9 + block length).
static long scan_block(const uint8_t *b, long len, hdr_scan_t *out) {
	memset(out, 0, sizeof(*out));
	long i = 0;
	while (i < len) {
		uint8_t c = b[i];
		if (c == 0x88) {
			hdr_collect(8, (const uint8_t *)"200", 3, out);
			i += 1;
		} else if (c == 0x08) {
			long sl = b[i + 1];
			hdr_collect(8, b + i + 2, sl, out);
			i += 2 + sl;
		} else if (c == 0x0f) {
			long idx = 15 + b[i + 1];
			long sl = b[i + 2];
			hdr_collect(idx, b + i + 3, sl, out);
			i += 3 + sl;
		} else {
			break;
		}
	}
	return i;
}

// The value of the header with the given static index, or NULL.
// (8 = :status, 28 = content-length, 30 = content-range,
//  31 = content-type, 26 = content-encoding)
static const uint8_t *scan_find(const hdr_scan_t *s, long idx, long *vlen_out) {
	for (long i = 0; i < s->count; i++) {
		if (s->idx[i] == idx) {
			*vlen_out = s->vlen[i];
			return s->val[i];
		}
	}
	return NULL;
}

// ── end-to-end request helper ───────────────────────────────────

static long serve_request(h2_hpack_field_t *fields, int n, uint8_t *out, long cap) {
	reset_streams();
	reset_fields();
	reset_conn(h2_conn_addr());
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_NOT_NULL("stream created", s);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry);
	ASSERT_EQ("headers event ok", 0, carry);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry);
	ASSERT_EQ("end_stream event ok", 0, carry);

	set_fields(fields, n);
	ASSERT_EQ("request built", 0, h2_build_request_wrapper(1, n, &carry));

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	ASSERT_EQ("process succeeds", 0, h2_process_request_wrapper(1, fds[1], &carry));
	close(fds[1]);
	long n_read = 0;
	while (n_read < cap) {
		long r = read(fds[0], out + n_read, (unsigned long)(cap - n_read));
		if (r <= 0) break;
		n_read += r;
	}
	close(fds[0]);
	return n_read;
}

// ── multiplexing helpers ────────────────────────────────────────

static long read_frame(int fd, uint8_t *buf, long cap, uint8_t *type_out,
                       uint8_t *flags_out, uint32_t *sid_out) {
	uint8_t hdr[H2_WIRE_HEADER_LEN];
	long n = 0;
	while (n < H2_WIRE_HEADER_LEN) {
		long r = read(fd, hdr + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
		if (r <= 0) return -1;
		n += r;
	}
	long len = ((long)hdr[0] << 16) | ((long)hdr[1] << 8) | hdr[2];
	if (len > cap) return -1;
	n = 0;
	while (n < len) {
		long r = read(fd, buf + n, (unsigned long)(len - n));
		if (r <= 0) return -1;
		n += r;
	}
	*type_out = hdr[3];
	*flags_out = hdr[4];
	*sid_out = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) |
	           ((uint32_t)hdr[7] << 8) | hdr[8];
	return len;
}

// Read the server's SETTINGS ACK, which follows its own SETTINGS whenever
// the client's preface flight carried a SETTINGS frame (RFC 9113 §6.5.3).
// Returns 0 if the next frame really was an empty SETTINGS ACK.
static int expect_settings_ack(int fd, uint8_t *buf, long cap) {
	uint8_t type = 0, flags = 0;
	uint32_t sid = 0;
	long len = read_frame(fd, buf, cap, &type, &flags, &sid);
	if (len != 0 || type != H2_FRAME_SETTINGS || sid != 0 ||
	    (flags & H2_FLAG_ACK) == 0)
		return -1;
	return 0;
}

static void send_all(int fd, const uint8_t *buf, long len) {
	long w = 0;
	while (w < len) {
		long r = write(fd, buf + w, (unsigned long)(len - w));
		if (r <= 0) _exit(1);
		w += r;
	}
}

static long put_request_headers(uint8_t *out, const char *path, long path_len,
                                uint8_t flags, uint32_t stream_id) {
	uint8_t block[256];
	long b = 0;
	block[b++] = 0x82;                 // :method GET
	block[b++] = 0x04;                 // literal without indexing, name = :path (4)
	block[b++] = (uint8_t)path_len;    // path < 128 in all these tests
	memcpy(block + b, path, (unsigned long)path_len);
	b += path_len;
	put_wire_header(out, (uint32_t)b, H2_FRAME_HEADERS, flags, stream_id);
	memcpy(out + H2_WIRE_HEADER_LEN, block, (unsigned long)b);
	return H2_WIRE_HEADER_LEN + b;
}

#endif // TEST_H2_COMMON_H
