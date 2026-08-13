// Unit tests for src/http2.S — Stages 4, 5, 6, 7 & 8.
// Stage 4: the HTTP/2 frame engine — h2_parse_frame_header (4.1),
// h2_validate_frame (4.2), h2_dispatch_frame (4.3), h2_handle_settings
// (4.4) and SETTINGS ACK (4.5). SETTINGS tests go through
// h2_dispatch_frame so the full header → handler path is exercised.
// Stage 5: the connection preface — h2_verify_preface reads exactly 24
// bytes and compares them with the HTTP/2 preface (3.4), flipping
// connection_mode; h2_send_settings emits the server's opening SETTINGS
// frame (3.5), captured over a real socketpair and verified byte-for-byte.
// Stage 6: stream management — the fixed stream table (6.1,
// h2_streams/h2_stream_find/h2_stream_create), stream id validation
// (6.2, h2_validate_stream_id), the receive-side state machine (6.3,
// h2_stream_event) and RST_STREAM handling (6.4). HEADERS/DATA handlers
// drive the machine through h2_dispatch_frame.
// Stage 7: minimal HPACK (src/h2_hpack.S) — the RFC 7541 Appendix A
// static table (7.1), integer decoding §5.1 (7.2), plain-string
// decoding §5.2 (7.3), indexed header fields §6.1 (7.4), literal
// header fields §6.2.2/§6.2.3 (7.5), and the disabled dynamic table
// (7.6): the opening SETTINGS frame advertises SETTINGS_HEADER_TABLE_SIZE
// = 0, and the decoder rejects every dynamic-table representation with
// COMPRESSION_ERROR.
// Stage 8: HEADERS → HPACK → the common request. h2_handle_headers
// extracts stream id, the header block and the END_STREAM/END_HEADERS
// flags and feeds the block to the HPACK decoder (8.1); h2_build_request
// decodes the request pseudo-headers :method/:path/:scheme/:authority
// into the protocol-neutral `request` struct (8.2); malformed requests
// — missing/empty :method, missing :path, duplicate pseudo-headers,
// undefined pseudo-headers, pseudo-headers after a regular header — are
// rejected with PROTOCOL_ERROR (8.3); and an HTTP/2 /index.html request
// produces byte-identical path/query/authority to the HTTP/1 parse of
// the same request (8.4), the one difference being REQ_STREAM_ID.
// Stage 10: complete static responses — HEAD (headers only, END_STREAM
// on the HEADERS frame), 404 (unresolved resource), 403 (a path the
// server refuses to serve), MIME types identical to HTTP/1's, and byte
// ranges — h2_parse_range / h2_resolve_range turn a `range` header into
// a 206 with content-range or a 416.
// Stage 11: DATA flow control (RFC 9113 §5.2, §6.9) — the connection
// window (h2_conn) and stream window (h2_streams entry) start at 65535,
// every DATA send drains both, h2_handle_window_update replenishes them
// (rejecting bad lengths, zero increments, idle streams and over-2^31
// windows, ignoring updates on CLOSED streams), and h2_write_body pauses
// for WINDOW_UPDATE when the credit runs out — so a file larger than the
// initial window (70000-byte www/big.bin stub) delivers end-to-end.
//
// NOTE: avoids libc string.h/stdlib.h per test_harness.h guidance.

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

// request type ids, mirroring defs.S
#define GET_ID     0
#define HEAD_ID    1
#define OPTIONS_ID 2
#define BREW_ID    3
#define UNKNOWN_ID 4

#define H2_ERR_PROTOCOL_ERROR     1
#define H2_ERR_FLOW_CONTROL_ERROR 3
#define H2_ERR_STREAM_CLOSED      5
#define H2_ERR_FRAME_SIZE_ERROR   6
#define H2_ERR_REFUSED_STREAM     7
#define H2_ERR_CANCEL             8
#define H2_ERR_COMPRESSION_ERROR  9

// RFC 9113 §6.5.2 default values
#define H2_DEF_HEADER_TABLE_SIZE       4096
#define H2_DEF_ENABLE_PUSH             1
#define H2_DEF_MAX_CONCURRENT_STREAMS  0xffffffff
#define H2_DEF_INITIAL_WINDOW_SIZE     65535
#define H2_DEF_MAX_FRAME_SIZE          16384
#define H2_DEF_MAX_HEADER_LIST_SIZE    0xffffffff

// ── stream constants, mirroring defs.S (§5) ────────────────────────
#define H2_MAX_STREAMS 32

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

#define AF_UNIX   1
#define SOCK_STREAM 1

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
		  "x8", "x9", "x10", "x11", "x30", "memory");
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
		  "x9", "memory");
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

// h2_hpack_decode_int(ptr=x0, n=x1) → (value=x0, consumed=x1, carry)
static inline int64_t h2_hpack_decode_int_wrapper(const uint8_t *p, int64_t n,
                                                  int64_t *consumed_out,
                                                  int64_t *carry_out) {
	int64_t value, consumed, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %3\n"
		"mov x1, %4\n"
		"bl h2_hpack_decode_int\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"cset %2, cs\n"
		: "=r"(value), "=r"(consumed), "=r"(carry)
		: "r"(p), "r"(n)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory");
	*consumed_out = consumed;
	*carry_out = carry;
	return value;
}

// h2_hpack_decode_string(ptr=x0) → (str=x0, len=x1, consumed=x2, carry)
static inline const uint8_t *h2_hpack_decode_string_wrapper(const uint8_t *p,
                                                            int64_t *len_out,
                                                            int64_t *consumed_out,
                                                            int64_t *carry_out) {
	const uint8_t *s;
	int64_t len, consumed, carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %4\n"
		"bl h2_hpack_decode_string\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"cset %3, cs\n"
		: "=r"(s), "=r"(len), "=r"(consumed), "=r"(carry)
		: "r"(p)
		: "x0", "x1", "x2", "x3", "x4", "x19", "x30", "memory");
	*len_out = len;
	*consumed_out = consumed;
	*carry_out = carry;
	return s;
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
static inline const uint8_t *h2_hpack_decode_field_wrapper(const uint8_t *p,
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
		"bl h2_hpack_decode_field\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		"mov %2, x2\n"
		"mov %3, x3\n"
		"mov %4, x4\n"
		"cset %5, cs\n"
		: "=r"(next), "=r"(name), "=r"(name_len), "=r"(value),
		  "=r"(value_len), "=r"(carry)
		: "r"(p)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x9",
		  "x19", "x20", "x21", "x30", "memory");
	*name_out = name;
	*name_len_out = name_len;
	*value_out = value;
	*value_len_out = value_len;
	*carry_out = carry;
	return next;
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
		: "x0", "x1", "x2", "x3", "x4", "x5", "x9", "memory");
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

// h2_write_body(fd=x0, resp=x1, stream_id=x2) → (carry)
static inline int64_t h2_write_body_wrapper(int64_t fd, const response_t *resp,
                                           int64_t stream_id) {
	int64_t carry;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %1\n"
		"mov x1, %2\n"
		"mov x2, %3\n"
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

static void test_h2_conn_defaults(void) {
	TEST_SUITE("h2_conn — RFC 9113 §6.5.2 defaults");

	h2_conn_t *conn = h2_conn_addr();
	ASSERT_EQ("max_rx_frame_size", H2_DEF_MAX_FRAME_SIZE, conn->max_rx_frame_size);
	ASSERT_EQ("header_table_size", H2_DEF_HEADER_TABLE_SIZE,
	          conn->settings_header_table_size);
	ASSERT_EQ("enable_push", H2_DEF_ENABLE_PUSH, conn->settings_enable_push);
	ASSERT_EQ("max_concurrent_streams", H2_DEF_MAX_CONCURRENT_STREAMS,
	          conn->settings_max_concurrent_streams);
	ASSERT_EQ("initial_window_size", H2_DEF_INITIAL_WINDOW_SIZE,
	          conn->settings_initial_window_size);
	ASSERT_EQ("max_frame_size", H2_DEF_MAX_FRAME_SIZE, conn->settings_max_frame_size);
	ASSERT_EQ("max_header_list_size", H2_DEF_MAX_HEADER_LIST_SIZE,
	          conn->settings_max_header_list_size);
	ASSERT_EQ("ack_received", 0, conn->ack_received);
	ASSERT_EQ("last_stream_id", 0, conn->last_stream_id);
	ASSERT_EQ("last_frame_type", 0, conn->last_frame_type);
	ASSERT_EQ("window", H2_DEF_INITIAL_WINDOW_SIZE, conn->window);
}

// ── 4.1 — frame header decoding ────────────────────────────────────

static void test_h2_parse_frame_header(void) {
	TEST_SUITE("h2_parse_frame_header — 4.1");

	uint8_t wire[9];
	h2_frame_header_t hdr;

	// a known SETTINGS frame: length=18, type=4, flags=0, stream 0
	put_wire_header(wire, 18, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("SETTINGS length decoded", 18, hdr.length);
	ASSERT_EQ("SETTINGS type decoded", H2_FRAME_SETTINGS, hdr.type);
	ASSERT_EQ("SETTINGS flags decoded", 0, hdr.flags);
	ASSERT_EQ("SETTINGS stream id decoded", 0, hdr.stream_id);

	// full 24-bit length, nonzero flags, R bit set in the stream id
	put_wire_header(wire, 0x123456, H2_FRAME_HEADERS, 0x5, 0x80000005u);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("full 24-bit length", 0x123456, hdr.length);
	ASSERT_EQ("type decoded", H2_FRAME_HEADERS, hdr.type);
	ASSERT_EQ("flags decoded", 0x5, hdr.flags);
	ASSERT_EQ("R bit masked — stream id 5", 5, hdr.stream_id);

	// extremes: zero length, max stream id, all flags
	put_wire_header(wire, 0, H2_FRAME_PING, 0xff, 0x7fffffffu);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("zero length", 0, hdr.length);
	ASSERT_EQ("all flags preserved", 0xff, hdr.flags);
	ASSERT_EQ("max stream id preserved", 0x7fffffff, hdr.stream_id);
}

// ── 4.2 — frame size validation ────────────────────────────────────

static void test_h2_validate_frame(void) {
	TEST_SUITE("h2_validate_frame — 4.2");

	h2_conn_t conn;
	reset_conn(&conn);
	h2_frame_header_t hdr;
	hdr.type = H2_FRAME_DATA; // type is irrelevant to size validation
	hdr.flags = 0;
	hdr.stream_id = 0;
	int64_t carry;

	hdr.length = 0;
	ASSERT_EQ("length 0 accepted", 0, h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	hdr.length = H2_DEF_MAX_FRAME_SIZE;
	ASSERT_EQ("length == default max accepted", 0,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	hdr.length = H2_DEF_MAX_FRAME_SIZE + 1;
	ASSERT_EQ("length > max → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// beyond the 24-bit wire limit
	hdr.length = 0x01000000u;
	ASSERT_EQ("length > 2^24-1 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	// the limit is per-connection — raise it and the frame becomes legal
	conn.max_rx_frame_size = 20000;
	hdr.length = 20000;
	ASSERT_EQ("conn limit raised → accepted", 0,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
}

// ── 4.3 — frame dispatcher ────────────────────────────────────────

static void test_h2_dispatch_frame(void) {
	TEST_SUITE("h2_dispatch_frame — 4.3");

	// Since Stage 6, stream-scoped frames (HEADERS, DATA, RST_STREAM)
	// are real: HEADERS on stream 1 opens the stream, DATA rides on it,
	// RST_STREAM closes it. Connection-scoped frames (SETTINGS, PING,
	// GOAWAY) keep stream id 0; the remaining stream-scoped types are
	// still stubs and accept any id. RST_STREAM needs its 4-byte
	// payload to pass the §6.4 length check. Since Stage 8 the HEADERS
	// payload is HPACK and must be a valid request block — the 2-byte
	// :method GET + :path / block from H2_REQ_BLOCK. Since Stage 11
	// WINDOW_UPDATE is real (§6.9): it needs its 4-byte increment, and
	// on stream 1 — closed by the RST_STREAM above — the update is
	// ignored, not an error (§5.1 closed).
	static const uint8_t types[] = {
		H2_FRAME_HEADERS, H2_FRAME_DATA, H2_FRAME_PRIORITY, H2_FRAME_RST_STREAM,
		H2_FRAME_SETTINGS, H2_FRAME_PUSH_PROMISE, H2_FRAME_PING, H2_FRAME_GOAWAY,
		H2_FRAME_WINDOW_UPDATE, H2_FRAME_CONTINUATION,
	};
	static const uint8_t streams[] = { 1, 1, 1, 1, 0, 1, 0, 0, 1, 1 };
	static const uint32_t lens[]   = { 2, 0, 0, 4, 0, 0, 0, 0, 4, 0 };
	uint8_t payload[6];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // HEADERS' HPACK block
	// WINDOW_UPDATE's 4-byte increment — nonzero so the §6.9 check passes
	payload[2] = 0x00; payload[3] = 0x00; payload[4] = 0x00; payload[5] = 0x10;
	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	h2_frame_header_t hdr;
	hdr.flags = 0;
	int64_t carry;

	for (int i = 0; i < 10; i++) {
		hdr.type = types[i];
		hdr.length = lens[i];
		hdr.stream_id = streams[i];
		ASSERT_EQ("handler returns success", 0,
		          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
		ASSERT_EQ("carry clear", 0, carry);
		ASSERT_EQ("frame reached its handler", types[i], conn.last_frame_type);
	}

	// unknown frame types are ignored, not errors (RFC 9113 §5.5)
	hdr.type = 0x0a;
	ASSERT_EQ("type 0x0a ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	hdr.type = 0xff;
	ASSERT_EQ("type 0xff ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("last dispatched unchanged", H2_FRAME_CONTINUATION,
	          conn.last_frame_type);
}

// ── 4.4 — SETTINGS parsing ─────────────────────────────────────────

static void test_h2_settings_store(void) {
	TEST_SUITE("h2_handle_settings — 4.4 store");

	uint8_t wire[9];
	uint8_t payload[18];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// client SETTINGS frame — three entries
	put_wire_header(wire, 18, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload + 0,  H2_SETTINGS_HEADER_TABLE_SIZE, 8192);
	put_setting(payload + 6,  H2_SETTINGS_ENABLE_PUSH, 0);
	put_setting(payload + 12, H2_SETTINGS_MAX_CONCURRENT_STREAMS, 100);

	reset_conn(&conn);
	ASSERT_EQ("first SETTINGS stored cleanly", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	ASSERT_EQ("header_table_size = 8192", 8192, conn.settings_header_table_size);
	ASSERT_EQ("enable_push = 0", 0, conn.settings_enable_push);
	ASSERT_EQ("max_concurrent_streams = 100", 100,
	          conn.settings_max_concurrent_streams);
	// untouched settings keep their RFC defaults
	ASSERT_EQ("initial_window_size default", H2_DEF_INITIAL_WINDOW_SIZE,
	          conn.settings_initial_window_size);
	ASSERT_EQ("max_frame_size default", H2_DEF_MAX_FRAME_SIZE,
	          conn.settings_max_frame_size);
	ASSERT_EQ("max_header_list_size default", H2_DEF_MAX_HEADER_LIST_SIZE,
	          conn.settings_max_header_list_size);

	// second SETTINGS frame — the remaining three settings
	put_setting(payload + 0,  H2_SETTINGS_INITIAL_WINDOW_SIZE, 123456);
	put_setting(payload + 6,  H2_SETTINGS_MAX_FRAME_SIZE, 65536);
	put_setting(payload + 12, H2_SETTINGS_MAX_HEADER_LIST_SIZE, 100000);

	ASSERT_EQ("second SETTINGS stored cleanly", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	ASSERT_EQ("initial_window_size = 123456", 123456,
	          conn.settings_initial_window_size);
	ASSERT_EQ("max_frame_size = 65536", 65536, conn.settings_max_frame_size);
	ASSERT_EQ("max_header_list_size = 100000", 100000,
	          conn.settings_max_header_list_size);
	// earlier values persist
	ASSERT_EQ("header_table_size persists", 8192, conn.settings_header_table_size);
	ASSERT_EQ("enable_push persists", 0, conn.settings_enable_push);
}

static void test_h2_settings_validation(void) {
	TEST_SUITE("h2_handle_settings — validation");

	uint8_t wire[9];
	uint8_t payload[12];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// unknown identifiers are ignored (§6.5.2)
	put_wire_header(wire, 12, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload + 0, 0x0a, 0xdeadbeefu); // unknown id
	put_setting(payload + 6, H2_SETTINGS_ENABLE_PUSH, 0);
	reset_conn(&conn);
	ASSERT_EQ("unknown id ignored", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("known setting still stored", 0, conn.settings_enable_push);

	// SETTINGS_MAX_FRAME_SIZE out of range → PROTOCOL_ERROR
	put_setting(payload + 0, H2_SETTINGS_MAX_FRAME_SIZE, 100); // < 2^14
	reset_conn(&conn);
	ASSERT_EQ("max_frame_size too small → PROTOCOL_ERROR",
	          H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	put_setting(payload + 0, H2_SETTINGS_MAX_FRAME_SIZE, 0x01000000u); // > 2^24-1
	reset_conn(&conn);
	ASSERT_EQ("max_frame_size too large → PROTOCOL_ERROR",
	          H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 → FLOW_CONTROL_ERROR
	put_setting(payload + 0, H2_SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000u);
	reset_conn(&conn);
	ASSERT_EQ("initial_window_size too large → FLOW_CONTROL_ERROR",
	          H2_ERR_FLOW_CONTROL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// payload length not a multiple of 6 → FRAME_SIZE_ERROR
	put_wire_header(wire, 7, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	payload[0] = 0x00; payload[1] = 0x01; payload[2] = 0;
	payload[3] = 0;    payload[4] = 0x20; payload[5] = 0x00;
	payload[6] = 0xff; // 7th byte — length % 6 != 0
	reset_conn(&conn);
	ASSERT_EQ("length not % 6 → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// SETTINGS on a stream (id != 0) → PROTOCOL_ERROR
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, 0, 5);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("SETTINGS on stream 5 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));

	// an empty non-ACK SETTINGS frame is valid
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("empty SETTINGS accepted", 0,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received stays 0", 0, conn.ack_received);
}

// ── 4.5 — SETTINGS ACK ─────────────────────────────────────────────

static void test_h2_settings_ack(void) {
	TEST_SUITE("h2_handle_settings — ACK (4.5)");

	uint8_t wire[9];
	uint8_t payload[6];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// SETTINGS + ACK with an empty payload → acknowledged
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("ACK accepted", 0, h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received set", 1, conn.ack_received);
	ASSERT_EQ("carry clear", 0, carry);

	// SETTINGS + ACK with a payload → FRAME_SIZE_ERROR
	put_wire_header(wire, 6, H2_FRAME_SETTINGS, H2_FLAG_ACK, 0);
	h2_parse_wrapper(wire, &hdr);
	put_setting(payload, H2_SETTINGS_ENABLE_PUSH, 0);
	reset_conn(&conn);
	ASSERT_EQ("ACK with payload → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("ack_received not set", 0, conn.ack_received);

	// SETTINGS + ACK on a stream → PROTOCOL_ERROR (stream check wins)
	put_wire_header(wire, 0, H2_FRAME_SETTINGS, H2_FLAG_ACK, 3);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("ACK on stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, NULL, &conn, &carry));
	ASSERT_EQ("ack_received not set", 0, conn.ack_received);

	// a plain SETTINGS frame must not set ack_received
	put_wire_header(wire, 6, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("non-ACK SETTINGS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("ack_received stays 0", 0, conn.ack_received);
}

// ── 4.2 end-to-end: malformed frames rejected without crashing ─────

static void test_h2_malformed_rejected(void) {
	TEST_SUITE("h2 — malformed frames rejected");

	uint8_t wire[9];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// oversized payload — caught at validation, before any dispatch
	put_wire_header(wire, H2_DEF_MAX_FRAME_SIZE + 1, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	reset_conn(&conn);
	ASSERT_EQ("oversized frame → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// 2^24 cannot be encoded on the wire, but a hand-built struct can —
	// still rejected
	hdr.length = 0x01000000u;
	ASSERT_EQ("length above 2^24-1 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_validate_wrapper(&hdr, &conn, &carry));

	// a malformed SETTINGS payload passes validation (size is fine) but
	// is rejected by the handler — no crash, connection error returned
	put_wire_header(wire, 7, H2_FRAME_SETTINGS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("SETTINGS length % 6 != 0 rejected", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, wire, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
}

// ── 5.1 — connection mode ──────────────────────────────────────────

static void test_connection_mode_default(void) {
	TEST_SUITE("connection_mode — 5.1 default is HTTP/1");

	// HTTP/1 is the default; nothing in the server changes that unless
	// the HTTP/2 preface is verified, so existing HTTP/1 connections are
	// untouched.
	ASSERT_EQ("connection_mode defaults to CONNECTION_HTTP1",
	          CONNECTION_HTTP1, connection_mode_value());
}

// ── 5.2 — preface verification ─────────────────────────────────────

static void test_h2_preface_verify(void) {
	TEST_SUITE("h2_verify_preface — 3.4 correct preface");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN + 8];
	int64_t carry;

	// correct preface, single write
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN);
	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("correct preface → CONNECTION_HTTP2", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("connection_mode flipped to HTTP/2", CONNECTION_HTTP2,
	          connection_mode_value());

	// correct preface arriving as partial reads (10 + 14)
	set_connection_mode(CONNECTION_HTTP1);
	write(sv[0], H2_PREFACE, 10);
	write(sv[0], H2_PREFACE + 10, 14);
	ASSERT_EQ("preface across two writes still verifies", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	close(sv[0]);
	close(sv[1]);
}

// The read loop's whole point is that a stream socket may deliver the
// 24 bytes across several read()s. Force exactly that: the first 10
// bytes are waiting before the call, the remaining 14 arrive from a
// child after the parent is blocked inside h2_verify_preface.
static void test_h2_preface_partial_reads(void) {
	TEST_SUITE("h2_verify_preface — read exactly 24 bytes across partial reads");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	write(sv[0], H2_PREFACE, 10);
	int pid = fork();
	if (pid == 0) {
		// child: deliver the rest once the parent is blocked in read()
		usleep(50000); // 50ms
		write(sv[0], H2_PREFACE + 10, 14);
		_exit(0);
	}

	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("10 + 14 byte deliveries verify", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	int status;
	waitpid(pid, &status, 0);
	close(sv[0]);
	close(sv[1]);
}

static void test_h2_preface_rejected(void) {
	TEST_SUITE("h2_verify_preface — 3.4 incorrect preface rejected");

	int sv[2];
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	// 24 bytes that are not the preface
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	for (int i = 0; i < H2_PREFACE_LEN; i++)
		buf[i] = (uint8_t)('A' + i);
	write(sv[0], buf, H2_PREFACE_LEN);
	set_connection_mode(CONNECTION_HTTP1);
	ASSERT_EQ("garbage → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set (connection rejected)", 1, carry);
	ASSERT_EQ("mode stays HTTP/1", CONNECTION_HTTP1, connection_mode_value());
	close(sv[0]);
	close(sv[1]);

	// a near-miss: identical except the final byte — every word compare
	// must hold for the preface to verify
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN - 1);
	uint8_t bad = 0x41; // 'A' instead of '\n'
	write(sv[0], &bad, 1);
	ASSERT_EQ("last byte wrong → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set", 1, carry);
	close(sv[0]);
	close(sv[1]);

	// EOF before the preface completes
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	close(sv[0]); // peer closes without sending anything
	ASSERT_EQ("EOF → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("carry set", 1, carry);
	close(sv[1]);

	// a read() failure (fd already closed → EBADF) rejects too
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	close(sv[1]); // now sv[1] is not an open fd
	set_connection_mode(CONNECTION_HTTP1);
	int64_t rc = h2_verify_preface_wrapper(sv[1], buf, &carry);
	ASSERT_EQ("read error → errno EBADF", 9, rc);
	ASSERT_EQ("carry set (connection rejected)", 1, carry);
	ASSERT_EQ("mode stays HTTP/1", CONNECTION_HTTP1, connection_mode_value());
	close(sv[0]);
}

// ── 5.3 — the opening SETTINGS frame ───────────────────────────────

static void test_h2_send_settings(void) {
	TEST_SUITE("h2_send_settings — 3.5 opening SETTINGS frame");

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	uint8_t buf[H2_PREFACE_LEN];
	int64_t carry;

	// full flow: client preface → verified → server sends SETTINGS
	write(sv[0], H2_PREFACE, H2_PREFACE_LEN);
	ASSERT_EQ("preface verified", CONNECTION_HTTP2,
	          h2_verify_preface_wrapper(sv[1], buf, &carry));
	ASSERT_EQ("settings sent — 15 bytes written", 15,
	          h2_send_settings_wrapper(sv[1], &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// capture the frame from the client side and check every header field
	uint8_t frame[15];
	long n = read(sv[0], frame, 15);
	ASSERT_EQ("15-byte frame captured", 15, n);

	uint32_t length = ((uint32_t)frame[0] << 16) |
	                  ((uint32_t)frame[1] << 8) | frame[2];
	ASSERT_EQ("payload length = 6 (one SETTINGS entry)", 6, length);
	ASSERT_EQ("type = SETTINGS", H2_FRAME_SETTINGS, frame[3]);
	ASSERT_EQ("flags = 0", 0, frame[4]);
	uint32_t stream = ((uint32_t)frame[5] << 24) |
	                  ((uint32_t)frame[6] << 16) |
	                  ((uint32_t)frame[7] << 8) | frame[8];
	ASSERT_EQ("stream id = 0", 0, stream);

	// the single entry: SETTINGS_HEADER_TABLE_SIZE = 0 (dynamic table off)
	uint32_t id = ((uint32_t)frame[9] << 8) | frame[10];
	ASSERT_EQ("entry id = SETTINGS_HEADER_TABLE_SIZE",
	          H2_SETTINGS_HEADER_TABLE_SIZE, id);
	uint32_t value = ((uint32_t)frame[11] << 24) | ((uint32_t)frame[12] << 16) |
	                 ((uint32_t)frame[13] << 8) | frame[14];
	ASSERT_EQ("entry value = 0 (dynamic table disabled)", 0, value);

	// the captured frame matches the asm constant byte-for-byte
	ASSERT_STR_EQ("frame matches h2_settings_frame constant",
	              h2_settings_frame_addr(), frame, 15);

	close(sv[0]);
	close(sv[1]);
}

// The data.S preface constant itself must be exactly the 24 bytes of
// RFC 9113 §3.4 — a typo there would let a wrong preface through.
static void test_h2_preface_constant(void) {
	TEST_SUITE("h2_preface constant — byte-for-byte (3.4)");

	const uint8_t *p = h2_preface_addr();
	ASSERT_STR_EQ("matches the spec string", H2_PREFACE, p, H2_PREFACE_LEN);
}

// ── 6.1 — stream table ─────────────────────────────────────────────

// Create a stream and force it into `state` — the transition tests need
// to start from any state without driving there frame by frame.
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

static void test_h2_stream_table(void) {
	TEST_SUITE("h2_stream table — 6.1 create and find");

	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	int64_t carry;

	// an empty table finds nothing
	ASSERT_EQ("find stream 1 — not found", 0,
	          (int64_t)h2_stream_find_wrapper(1));

	// creating stream 1 fills a fresh entry with the RFC defaults
	h2_stream_t *s1 = h2_stream_create_wrapper(1, &conn, &carry);
	ASSERT_EQ("create 1 succeeds", 0, carry);
	ASSERT_NOT_NULL("create 1 returns an entry", s1);
	ASSERT_EQ("stream_id = 1", 1, s1->stream_id);
	ASSERT_EQ("initial state IDLE", H2_STREAM_IDLE, s1->state);
	ASSERT_EQ("initial flags 0", 0, s1->flags);
	ASSERT_EQ("initial window 65535", H2_DEF_INITIAL_WINDOW_SIZE, s1->window);
	ASSERT_EQ("conn tracks last stream id", 1, conn.last_stream_id);

	// ... and can be found again
	ASSERT_EQ("find 1 returns the same entry", (int64_t)s1,
	          (int64_t)h2_stream_find_wrapper(1));

	// a second stream uses a different entry; the first is untouched
	h2_stream_t *s3 = h2_stream_create_wrapper(3, &conn, &carry);
	ASSERT_EQ("create 3 succeeds", 0, carry);
	ASSERT_NOT_NULL("create 3 returns an entry", s3);
	ASSERT_EQ("entries differ", 1, s1 != s3);
	ASSERT_EQ("find 3 returns its entry", (int64_t)s3,
	          (int64_t)h2_stream_find_wrapper(3));
	ASSERT_EQ("stream 1 still present", (int64_t)s1,
	          (int64_t)h2_stream_find_wrapper(1));
	ASSERT_EQ("conn tracks last stream id", 3, conn.last_stream_id);

	// creating an existing id is find-or-create: same entry, no change
	ASSERT_EQ("create 1 again returns existing entry", (int64_t)s1,
	          (int64_t)h2_stream_create_wrapper(1, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream 1 state unchanged", H2_STREAM_IDLE, s1->state);

	// the table is fixed at H2_MAX_STREAMS — filling it rejects the next
	reset_streams();
	reset_conn(&conn);
	for (int64_t id = 1; id < 2 * H2_MAX_STREAMS; id += 2)
		h2_stream_create_wrapper(id, &conn, &carry);
	// 32 odd ids (1..63) fill the table; the 33rd is rejected
	h2_stream_t *full = h2_stream_create_wrapper(65, &conn, &carry);
	ASSERT_EQ("table full → carry set", 1, carry);
	ASSERT_EQ("table full → REFUSED_STREAM", H2_ERR_REFUSED_STREAM,
	          (int64_t)full);
}

// ── 6.2 — stream id validation ─────────────────────────────────────

static void test_h2_validate_stream_id(void) {
	TEST_SUITE("h2_validate_stream_id — 6.2");

	uint8_t wire[9];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);

	// zero is reserved for connection-level frames (§5.1.1)
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("id 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// client streams are odd — an even id belongs to a server stream
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 4);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id 4 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	// a fresh odd id is fine
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("id 1 accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// ids must increase for new streams (§5.1.1)
	reset_streams();
	reset_conn(&conn);
	conn.last_stream_id = 9; // the connection has already seen up to 9
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 7); // new stream, lower id
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("new id ≤ last → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 11); // new stream, higher id
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("new id > last accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));

	// an existing stream may keep its id — no increase check for it
	reset_streams();
	reset_conn(&conn);
	h2_stream_create_wrapper(5, &conn, &carry); // last becomes 5
	put_wire_header(wire, 0, H2_FRAME_HEADERS, 0, 5);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("existing id accepted", 0,
	          h2_validate_stream_id_wrapper(&hdr, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
}

// 6.2 end-to-end: the HEADERS handler applies the same checks
static void test_h2_headers_stream_creation(void) {
	TEST_SUITE("h2_handle_headers — 6.2 stream creation");

	uint8_t wire[9];
	uint8_t payload[4];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);

	// a HEADERS frame on stream 0 is a PROTOCOL_ERROR
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("no stream created", 0, (int64_t)h2_stream_find_wrapper(1));

	// an even stream id is a PROTOCOL_ERROR
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 2 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("no stream created", 0, (int64_t)h2_stream_find_wrapper(2));

	// a valid HEADERS opens the stream and bumps the high-water mark
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 1 accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_NOT_NULL("stream 1 created", s);
	ASSERT_EQ("state OPEN", H2_STREAM_OPEN, s->state);
	ASSERT_EQ("conn last stream id = 1", 1, conn.last_stream_id);

	// the next stream must use a larger id
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS id 3 accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("conn last stream id = 3", 3, conn.last_stream_id);

	// a HEADERS for an existing stream is fine (trailers, §5.1 open)
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS on existing stream accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream 1 still OPEN", H2_STREAM_OPEN,
	          h2_stream_find_wrapper(1)->state);
}

// ── 6.3 — stream states ────────────────────────────────────────────

static void test_h2_stream_transitions(void) {
	TEST_SUITE("h2_stream_event — 6.3 state machine");

	h2_conn_t conn;
	h2_stream_t *s;
	int64_t carry;

	// ── IDLE ──
	s = stream_in_state(&conn, 1, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+HEADERS → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("IDLE+HEADERS → OPEN", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 3, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+DATA → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	s = stream_in_state(&conn, 5, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+END_STREAM → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	s = stream_in_state(&conn, 7, H2_STREAM_IDLE);
	ASSERT_EQ("IDLE+RST → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_IDLE, s->state);

	// ── OPEN ──
	s = stream_in_state(&conn, 9, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+HEADERS → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("OPEN+HEADERS stays OPEN (trailers)", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 11, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+DATA → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("OPEN+DATA stays OPEN", H2_STREAM_OPEN, s->state);

	s = stream_in_state(&conn, 13, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+END_STREAM → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("OPEN+END_STREAM → HALF_CLOSED_REMOTE",
	          H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	s = stream_in_state(&conn, 15, H2_STREAM_OPEN);
	ASSERT_EQ("OPEN+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("OPEN+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── HALF_CLOSED_REMOTE ──
	s = stream_in_state(&conn, 17, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+HEADERS → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	s = stream_in_state(&conn, 19, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));

	s = stream_in_state(&conn, 21, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+END_STREAM → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));

	s = stream_in_state(&conn, 23, H2_STREAM_HALF_CLOSED_REMOTE);
	ASSERT_EQ("HCR+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("HCR+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── HALF_CLOSED_LOCAL ──
	s = stream_in_state(&conn, 25, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+HEADERS → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry));

	s = stream_in_state(&conn, 27, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));

	s = stream_in_state(&conn, 29, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+END_STREAM → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry));
	ASSERT_EQ("HCL+END_STREAM → CLOSED", H2_STREAM_CLOSED, s->state);

	s = stream_in_state(&conn, 31, H2_STREAM_HALF_CLOSED_LOCAL);
	ASSERT_EQ("HCL+RST → 0", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("HCL+RST → CLOSED", H2_STREAM_CLOSED, s->state);

	// ── CLOSED ──
	s = stream_in_state(&conn, 33, H2_STREAM_CLOSED);
	ASSERT_EQ("CLOSED+DATA → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_DATA, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_CLOSED, s->state);

	// a reset racing our own END_STREAM is tolerated (§5.1 closed)
	s = stream_in_state(&conn, 35, H2_STREAM_CLOSED);
	ASSERT_EQ("CLOSED+RST → 0 (tolerated)", 0,
	          h2_stream_event_wrapper(s, H2_EVENT_RECV_RST_STREAM, &carry));
	ASSERT_EQ("state stays CLOSED", H2_STREAM_CLOSED, s->state);

	// defensive: an out-of-range event is an invalid transition
	s = stream_in_state(&conn, 37, H2_STREAM_OPEN);
	ASSERT_EQ("event out of range → STREAM_CLOSED", H2_ERR_STREAM_CLOSED,
	          h2_stream_event_wrapper(s, 4, &carry));
	ASSERT_EQ("state unchanged", H2_STREAM_OPEN, s->state);
}

// END_STREAM flag handling through the real handlers
static void test_h2_end_stream_flags(void) {
	TEST_SUITE("h2 HEADERS/DATA — 6.3 END_STREAM flag");

	uint8_t wire[9];
	uint8_t payload[4];
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// HEADERS without END_STREAM → OPEN
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state OPEN", H2_STREAM_OPEN, h2_stream_find_wrapper(1)->state);

	// HEADERS with END_STREAM → HALF_CLOSED_REMOTE
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE, s->state);

	// DATA without END_STREAM → stays OPEN
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	put_wire_header(wire, 5, H2_FRAME_DATA, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state still OPEN", H2_STREAM_OPEN, h2_stream_find_wrapper(1)->state);

	// DATA with END_STREAM → HALF_CLOSED_REMOTE
	put_wire_header(wire, 5, H2_FRAME_DATA, H2_FLAG_END_STREAM, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          h2_stream_find_wrapper(1)->state);

	// DATA on an unknown stream → idle violation (PROTOCOL_ERROR)
	put_wire_header(wire, 5, H2_FRAME_DATA, 0, 9);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("DATA on idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);
}

// ── 6.4 — RST_STREAM ───────────────────────────────────────────────

static void test_h2_rst_stream(void) {
	TEST_SUITE("h2_handle_rst_stream — 6.4");

	uint8_t wire[9];
	uint8_t payload[4] = {0, 0, 0, H2_ERR_CANCEL}; // 4-byte error code
	uint8_t block[4];
	memcpy(block, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN); // valid HPACK request
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// the happy path: HEADERS opens a stream, RST_STREAM closes it
	reset_streams();
	reset_conn(&conn);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, block, &conn, &carry));
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_EQ("stream OPEN", H2_STREAM_OPEN, s->state);

	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream CLOSED", H2_STREAM_CLOSED, h2_stream_find_wrapper(1)->state);

	// a wrong payload length is a FRAME_SIZE_ERROR
	put_wire_header(wire, 3, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("length 3 → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// stream 0 is a connection-level id — RST_STREAM there is an error
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 0);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("stream 0 → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// an even id (server-initiated) is an error from the client
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 2);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("even id → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// RST_STREAM on an idle (never opened) stream (§6.4)
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 9);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// RST_STREAM on a half-closed (remote) stream also closes it
	// (stream 1 is closed now; use a fresh stream 3)
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS, H2_FLAG_END_STREAM, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS+END_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, block, &conn, &carry));
	h2_stream_t *s3 = h2_stream_find_wrapper(3);
	ASSERT_EQ("stream 3 HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s3->state);

	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST_STREAM accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream 3 CLOSED", H2_STREAM_CLOSED, h2_stream_find_wrapper(3)->state);

	// RST_STREAM on an already-closed stream is tolerated (§5.1 closed)
	put_wire_header(wire, 4, H2_FRAME_RST_STREAM, 0, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("RST on CLOSED stream tolerated", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream 1 still CLOSED", H2_STREAM_CLOSED,
	          h2_stream_find_wrapper(1)->state);
}

// ── Stage 7 — minimal HPACK (h2_hpack.S) ───────────────────────────

// Assert a decoded name/value pair matches the expected C strings.
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

// Assert a decoded string matches the expected C string and consumption.
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

// Assert an integer decoded to the expected value and consumption.
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

// Assert a decode failed with COMPRESSION_ERROR (rc passed through x0).
static void check_field_error(const char *label, const uint8_t *next,
                              int64_t carry) {
	if (carry != 1 || (int64_t)(uintptr_t)next != H2_ERR_COMPRESSION_ERROR)
		_FAIL("%s — expected COMPRESSION_ERROR (carry=%lld, x0=%p)", label,
		      (long long)carry, (const void *)next);
	else
		_PASS(label);
}

// ── Stage 8 helpers ────────────────────────────────────────────────

// Build one decoded header field the way h2_hpack_decode_block would.
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

// Stage the decoded fields h2_build_request will read.
static void set_fields(const h2_hpack_field_t *fields, int n) {
	memcpy(h2_hpack_fields_addr(), fields,
	       (unsigned long)n * sizeof(h2_hpack_field_t));
}

// ── 7.1 — the RFC 7541 Appendix A static table ─────────────────────

static void test_h2_hpack_static_table(void) {
	TEST_SUITE("h2_hpack_static_lookup — RFC 7541 Appendix A (7.1)");

	ASSERT_EQ("h2_hpack_field_t layout matches H2_HPACK_FIELD_SIZE",
	          H2_HPACK_FIELD_SIZE, (int64_t)sizeof(h2_hpack_field_t));

	const uint8_t *name, *value;
	int64_t name_len, value_len, carry;

	// index 2: :method = GET — the canonical indexed request header
	name = h2_hpack_static_lookup_wrapper(2, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 2 → :method GET", carry, name, name_len, value, value_len,
	            ":method", "GET");

	// index 5: :path = /index.html
	name = h2_hpack_static_lookup_wrapper(5, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 5 → :path /index.html", carry, name, name_len,
	            value, value_len, ":path", "/index.html");

	// index 1: :authority, empty value
	name = h2_hpack_static_lookup_wrapper(1, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 1 → :authority (empty)", carry, name, name_len,
	            value, value_len, ":authority", "");

	// index 16: accept-encoding = gzip, deflate
	name = h2_hpack_static_lookup_wrapper(16, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 16 → accept-encoding gzip, deflate", carry, name,
	            name_len, value, value_len, "accept-encoding", "gzip, deflate");

	// index 31: content-type, empty value
	name = h2_hpack_static_lookup_wrapper(31, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 31 → content-type (empty)", carry, name, name_len,
	            value, value_len, "content-type", "");

	// the last entry of the table
	name = h2_hpack_static_lookup_wrapper(61, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 61 → www-authenticate (empty)", carry, name, name_len,
	            value, value_len, "www-authenticate", "");

	// index 0 and indices past the static table are decoding errors
	const uint8_t *v;
	int64_t rc = (int64_t)(uintptr_t)h2_hpack_static_lookup_wrapper(
	    0, &name_len, &v, &value_len, &carry);
	check_field_error("index 0 rejected", (const uint8_t *)rc, carry);
	rc = (int64_t)(uintptr_t)h2_hpack_static_lookup_wrapper(
	    62, &name_len, &v, &value_len, &carry);
	check_field_error("index 62 rejected (no dynamic table)",
	                  (const uint8_t *)rc, carry);
}

// ── 7.2 — integer decoding (§5.1) ──────────────────────────────────

static void test_h2_hpack_int(void) {
	TEST_SUITE("h2_hpack_decode_int — RFC 7541 §5.1 (7.2)");

	// the Stage 7 required values, all with a 7-bit prefix. The
	// continuation octets carry 7 bits each, least significant group
	// first (§5.1); a prefix of all ones always means "more octets
	// follow", so 2^N - 1 itself needs one more octet.
	check_int("0 decodes",   (const uint8_t *)"\x00", 7, 0, 1);
	check_int("1 decodes",   (const uint8_t *)"\x01", 7, 1, 1);
	check_int("10 decodes",  (const uint8_t *)"\x0a", 7, 10, 1);
	check_int("127 decodes", (const uint8_t *)"\x7f\x00", 7, 127, 2);
	check_int("128 decodes", (const uint8_t *)"\x7f\x01", 7, 128, 2);
	check_int("255 decodes", (const uint8_t *)"\x7f\x80\x01", 7, 255, 3);
	check_int("4096 decodes", (const uint8_t *)"\x7f\x81\x1f", 7, 4096, 3);

	// other prefix widths: the 4-bit literal index (15, 16, 30), the
	// 5-bit size update (31, 32) and the 6-bit incremental index (63, 64)
	check_int("N=4: 15",   (const uint8_t *)"\x0f\x00", 4, 15, 2);
	check_int("N=4: 16",   (const uint8_t *)"\x0f\x01", 4, 16, 2);
	check_int("N=4: 30",   (const uint8_t *)"\x0f\x0f", 4, 30, 2);
	check_int("N=5: 31",   (const uint8_t *)"\x1f\x00", 5, 31, 2);
	check_int("N=5: 32",   (const uint8_t *)"\x1f\x01", 5, 32, 2);
	check_int("N=6: 63",   (const uint8_t *)"\x3f\x00", 6, 63, 2);
	check_int("N=6: 64",   (const uint8_t *)"\x3f\x01", 6, 64, 2);

	// encode → decode round trips across prefix widths, including the
	// 32-bit ceiling, so the encoder and decoder agree on §5.1
	static const uint32_t values[] = {
		0, 1, 10, 62, 63, 64, 126, 127, 128, 255, 256, 1024, 4096,
		65535, 0xffffffffu,
	};
	static const int prefixes[] = { 4, 5, 6, 7 };
	uint8_t enc[8];
	for (unsigned vi = 0; vi < sizeof(values) / sizeof(values[0]); vi++) {
		for (unsigned pi = 0; pi < sizeof(prefixes) / sizeof(prefixes[0]); pi++) {
			int n = put_hpack_int(enc, values[vi], prefixes[pi]);
			int64_t consumed, carry;
			int64_t got = h2_hpack_decode_int_wrapper(enc, prefixes[pi],
			                                          &consumed, &carry);
			if (carry != 0) {
				_FAIL("roundtrip value %u prefix %d — decode failed",
				      (unsigned)values[vi], prefixes[pi]);
			} else if (got != (int64_t)values[vi]) {
				_FAIL("roundtrip value %u prefix %d — got %lld",
				      (unsigned)values[vi], prefixes[pi], (long long)got);
			} else if (consumed != n) {
				_FAIL("roundtrip value %u prefix %d — consumed %lld != %d",
				      (unsigned)values[vi], prefixes[pi],
				      (long long)consumed, n);
			} else {
				_PASS("roundtrip");
			}
		}
	}

	// a value that cannot fit in 32 bits is a decoding error — and the
	// decoder must stop reading, not walk off into memory
	int64_t consumed, carry;
	static const uint8_t overflow[] = { 0x7f, 0xff, 0xff, 0xff, 0xff,
	                                    0xff, 0xff, 0xff, 0xff, 0x01 };
	int64_t rc = h2_hpack_decode_int_wrapper(overflow, 7, &consumed, &carry);
	ASSERT_EQ("32-bit overflow rejected", H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
}

// ── 7.3 — string decoding (§5.2, plain only) ───────────────────────

static void test_h2_hpack_string(void) {
	TEST_SUITE("h2_hpack_decode_string — RFC 7541 §5.2 (7.3)");

	int64_t len, consumed, carry;
	const uint8_t *s;

	// the Stage 7 required strings
	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x03" "GET",
	                                   &len, &consumed, &carry);
	check_string("\"GET\" decodes", carry, s, len, "GET", consumed, 4);

	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x0b" "/index.html",
	                                   &len, &consumed, &carry);
	check_string("\"/index.html\" decodes", carry, s, len, "/index.html",
	             consumed, 12);

	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x09" "text/html",
	                                   &len, &consumed, &carry);
	check_string("\"text/html\" decodes", carry, s, len, "text/html",
	             consumed, 10);

	// empty string
	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x00",
	                                   &len, &consumed, &carry);
	check_string("empty string decodes", carry, s, len, "", consumed, 1);

	// multi-octet lengths: 130 = 127 + 3, 1000 = 127 + 105 + 6*128
	uint8_t s130[133];
	s130[0] = 0x7f; s130[1] = 0x03;
	for (int i = 0; i < 130; i++) s130[2 + i] = (uint8_t)('a' + (i % 26));
	s = h2_hpack_decode_string_wrapper(s130, &len, &consumed, &carry);
	ASSERT_EQ("130-byte length decodes", 130, len);
	ASSERT_EQ("130-byte string consumed", 132, consumed);
	ASSERT_EQ("130-byte string carry clear", 0, carry);
	ASSERT_TRUE("130-byte string data matches",
	            memcmp(s, s130 + 2, 130) == 0);

	uint8_t s1000[1003];
	s1000[0] = 0x7f; s1000[1] = 0xe9; s1000[2] = 0x06;
	for (int i = 0; i < 1000; i++) s1000[3 + i] = (uint8_t)('a' + (i % 26));
	s = h2_hpack_decode_string_wrapper(s1000, &len, &consumed, &carry);
	ASSERT_EQ("1000-byte length decodes", 1000, len);
	ASSERT_EQ("1000-byte string consumed", 1003, consumed);
	ASSERT_EQ("1000-byte string carry clear", 0, carry);
	ASSERT_TRUE("1000-byte string data matches",
	            memcmp(s, s1000 + 3, 1000) == 0);

	// Huffman-coded strings (§5.2) decode through h2_huffman_decode —
	// "www.example.com" is the canonical RFC 7541 Appendix C.4.1 vector
	static const uint8_t h1[] = { 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
	                              0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
	s = h2_hpack_decode_string_wrapper(h1, &len, &consumed, &carry);
	check_string("Huffman \"www.example.com\" decodes", carry, s, len,
	             "www.example.com", consumed, (int64_t)sizeof(h1));
}

// ── 7.3b — Huffman decoding (RFC 7541 Appendix B) ───────────────────
static void test_h2_huffman(void) {
	TEST_SUITE("h2_huffman_decode — RFC 7541 Appendix B Huffman code");

	int64_t len, consumed, carry;
	const uint8_t *s;

	// RFC 7541 Appendix C.4.1 — the canonical Huffman test vector
	static const uint8_t auth[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
	                                0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
	s = h2_huffman_decode_wrapper(auth, (int64_t)sizeof(auth), &len, &consumed,
	                              &carry);
	check_string("www.example.com", carry, s, len, "www.example.com", consumed,
	             (int64_t)sizeof(auth));

	// C.4.2 — no-cache
	static const uint8_t nc[] = { 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
	s = h2_huffman_decode_wrapper(nc, (int64_t)sizeof(nc), &len, &consumed,
	                              &carry);
	check_string("no-cache", carry, s, len, "no-cache", consumed,
	             (int64_t)sizeof(nc));

	// C.6.1 — private, 302
	static const uint8_t priv[] = { 0xae, 0xc3, 0x77, 0x1a, 0x4b };
	s = h2_huffman_decode_wrapper(priv, (int64_t)sizeof(priv), &len, &consumed,
	                              &carry);
	check_string("private", carry, s, len, "private", consumed,
	             (int64_t)sizeof(priv));

	static const uint8_t s302[] = { 0x64, 0x02 };
	s = h2_huffman_decode_wrapper(s302, (int64_t)sizeof(s302), &len, &consumed,
	                              &carry);
	check_string("302", carry, s, len, "302", consumed, (int64_t)sizeof(s302));

	// curl/8.7.1 — the user-agent captured from a real curl request
	static const uint8_t ua[] = { 0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xba, 0xb8, 0x7f };
	s = h2_huffman_decode_wrapper(ua, (int64_t)sizeof(ua), &len, &consumed,
	                              &carry);
	check_string("curl/8.7.1", carry, s, len, "curl/8.7.1", consumed,
	             (int64_t)sizeof(ua));

	// 127.0.0.1:8100 — the :authority captured from a real curl request
	static const uint8_t ah[] = { 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc,
	                              0x78, 0x20, 0x07 };
	s = h2_huffman_decode_wrapper(ah, (int64_t)sizeof(ah), &len, &consumed,
	                              &carry);
	check_string("127.0.0.1:8100", carry, s, len, "127.0.0.1:8100", consumed,
	             (int64_t)sizeof(ah));

	// an empty Huffman string (encoded length 0)
	s = h2_huffman_decode_wrapper((const uint8_t *)"", 0, &len, &consumed,
	                              &carry);
	check_string("empty string", carry, s, len, "", consumed, 0);

	// two Huffman strings back-to-back (the header-block scenario): the
	// second decode appends after the first in h2_hpack_str_buf
	const uint8_t *first = h2_huffman_decode_wrapper(auth, (int64_t)sizeof(auth),
	                                                &len, &consumed, &carry);
	check_string("authority then", carry, s, len, "www.example.com", consumed,
	             (int64_t)sizeof(auth));
	s = h2_huffman_decode_wrapper(ua, (int64_t)sizeof(ua), &len, &consumed,
	                              &carry);
	check_string("then user-agent", carry, s, len, "curl/8.7.1", consumed,
	             (int64_t)sizeof(ua));
	// the first string is still intact at its original position
	ASSERT_TRUE("first string intact",
	            memcmp(first, "www.example.com", 15) == 0);

	// invalid padding — the leftover bits must be all ones (§5.2): after
	// "302" (16 bits, exact) an extra 0x00 byte leaves 000 padding
	static const uint8_t badpad[] = { 0x64, 0x02, 0x00 };
	s = h2_huffman_decode_wrapper(badpad, (int64_t)sizeof(badpad), &len,
	                              &consumed, &carry);
	ASSERT_EQ("bad padding rejected", 1, carry);
	ASSERT_EQ("bad padding error", H2_ERR_COMPRESSION_ERROR,
	          (int64_t)(uintptr_t)s);

	// the EOS symbol inside a string is a decoding error (§5.2)
	static const uint8_t eos[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	s = h2_huffman_decode_wrapper(eos, (int64_t)sizeof(eos), &len, &consumed,
	                              &carry);
	ASSERT_EQ("EOS symbol rejected", 1, carry);
}

// ── 7.4 — indexed header fields (§6.1) ─────────────────────────────

static void test_h2_hpack_indexed(void) {
	TEST_SUITE("h2_hpack_decode_field — indexed (6.1 / 7.4)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	// 0x82 → index 2 → :method: GET — the canonical encoded request header
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x82", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x82 → :method GET", carry, name, name_len, value, value_len,
	            ":method", "GET");
	ASSERT_EQ("next advances one byte", 1, next - (const uint8_t *)"\x82");

	// 0x81 → index 1 → :authority with an empty value
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x81", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x81 → :authority (empty)", carry, name, name_len, value,
	            value_len, ":authority", "");

	// 0x87 → index 7 → :scheme: https
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x87", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x87 → :scheme https", carry, name, name_len, value, value_len,
	            ":scheme", "https");

	// multi-octet index: 0xbf 0x07 → 127 + 7 = 134, beyond the static table
	static const uint8_t big_idx[] = { 0xbf, 0x07 };
	next = h2_hpack_decode_field_wrapper(big_idx, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("index 134 rejected", next, carry);

	// index 0 is never valid (§6.1)
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x80", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field_error("index 0 rejected", next, carry);
}

// ── 7.5 — literal header fields (§6.2.2/§6.2.3) ─────────────────────

static void test_h2_hpack_literal(void) {
	TEST_SUITE("h2_hpack_decode_field — literal (6.2.2/6.2.3 / 7.5)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	// literal without indexing, indexed name: 0x04 + "/index.html" → :path
	static const uint8_t w1[] = { 0x04, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w1, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("0x04 + \"/index.html\" → :path", carry, name, name_len,
	            value, value_len, ":path", "/index.html");
	ASSERT_EQ("next at block end", 13, next - w1);

	// never indexed, indexed name: 0x14 → the same field
	static const uint8_t w2[] = { 0x14, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w2, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("0x14 + \"/index.html\" → :path (never indexed)", carry, name,
	            name_len, value, value_len, ":path", "/index.html");

	// literal without indexing, new name: the name string follows the 0x00
	static const uint8_t w3[] = { 0x00, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w3, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("new name :path, value /index.html", carry, name, name_len,
	            value, value_len, ":path", "/index.html");
	ASSERT_EQ("next at block end", 19, next - w3);

	// never indexed, new name: 0x10 → the same field
	static const uint8_t w4[] = { 0x10, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w4, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("new name :path (never indexed)", carry, name, name_len,
	            value, value_len, ":path", "/index.html");

	// an empty value string
	static const uint8_t w5[] = { 0x04, 0x00 };
	next = h2_hpack_decode_field_wrapper(w5, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field(":path with an empty value", carry, name, name_len, value,
	            value_len, ":path", "");
	ASSERT_EQ("next at block end", 2, next - w5);

	// a multi-octet name index: 0x0f 0x01 → index 16 (accept-encoding),
	// value "gzip, deflate" — exercises the multi-octet prefix path
	static const uint8_t w7[] = { 0x0f, 0x01, 0x0d, 'g', 'z', 'i', 'p', ',', ' ',
	                              'd', 'e', 'f', 'l', 'a', 't', 'e' };
	next = h2_hpack_decode_field_wrapper(w7, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("index 16 (accept-encoding) via 2-octet index", carry, name,
	            name_len, value, value_len, "accept-encoding", "gzip, deflate");
	ASSERT_EQ("next at block end", 16, next - w7);

	// a literal name index beyond the static table (62) → decoding error
	static const uint8_t w6[] = { 0x0f, 0x2f, 0x01, 'x' };
	next = h2_hpack_decode_field_wrapper(w6, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("name index 62 rejected", next, carry);
}

// ── 7.6 — the dynamic table is disabled ─────────────────────────────

static void test_h2_hpack_dynamic_disabled(void) {
	TEST_SUITE("h2_hpack_decode_field — dynamic table disabled (7.6)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	// literal with incremental indexing (§6.2.1) is decoded but never
	// stored: the dynamic table max size is 0, so an entry "added" to it
	// would be evicted immediately (curl encodes user-agent this way)
	static const uint8_t w1[] = { 0x41, 0x05, 'h', 'e', 'l', 'l', 'o' };
	next = h2_hpack_decode_field_wrapper(w1, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("incremental indexing (indexed name) decoded", carry, name,
	            name_len, value, value_len, ":authority", "hello");
	ASSERT_EQ("next at block end", 7, next - w1);

	// incremental indexing with a new name
	static const uint8_t w2[] = { 0x40, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x01, 'x' };
	next = h2_hpack_decode_field_wrapper(w2, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("incremental indexing (new name) decoded", carry, name,
	            name_len, value, value_len, ":path", "x");
	ASSERT_EQ("next at block end", 9, next - w2);

	// a dynamic table size update of 0 is accepted as a no-op
	static const uint8_t w3[] = { 0x20, 0x82 };
	next = h2_hpack_decode_field_wrapper(w3, &name, &name_len, &value,
	                                     &value_len, &carry);
	ASSERT_EQ("size update 0 accepted", 0, carry);
	ASSERT_EQ("not a field — name is 0", 0, (int64_t)(uintptr_t)name);
	ASSERT_EQ("next skips the update", 1, next - w3);

	// a size update above 0 (4096) exceeds our advertised maximum (0)
	static const uint8_t w4[] = { 0x3f, 0xe1, 0x1f }; // 31 + 97 + 31*128
	next = h2_hpack_decode_field_wrapper(w4, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("size update 4096 rejected", next, carry);
}

// ── whole header blocks ─────────────────────────────────────────────

static void test_h2_hpack_block(void) {
	TEST_SUITE("h2_hpack_decode_block — whole header block");

	int64_t carry;
	h2_hpack_field_t *f = h2_hpack_fields_addr();

	// a request-like block: :method GET, :scheme https, :path /index.html,
	// :authority example.com (literal without indexing, indexed name)
	static const uint8_t block[] = {
		0x82, 0x87, 0x85,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	reset_fields();
	ASSERT_EQ("4 fields decoded", 4,
	          h2_hpack_decode_block_wrapper(block, sizeof(block), &carry));
	ASSERT_EQ("carry clear", 0, carry);
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme https", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "https");
	check_field("field 2 :path /index.html", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":path", "/index.html");
	check_field("field 3 :authority example.com", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":authority", "example.com");

	// a size update is skipped and does not count as a field
	static const uint8_t block2[] = { 0x20, 0x82 };
	reset_fields();
	ASSERT_EQ("size update skipped — 1 field", 1,
	          h2_hpack_decode_block_wrapper(block2, sizeof(block2), &carry));
	ASSERT_EQ("carry clear", 0, carry);
	check_field("after size update, :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");

	// an empty block decodes to zero fields
	reset_fields();
	ASSERT_EQ("empty block → 0 fields", 0,
	          h2_hpack_decode_block_wrapper((const uint8_t *)"", 0, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// a truncated block — the value string overruns the block end
	static const uint8_t block3[] = { 0x01, 0x0a, 'e', 'x' }; // claims 10, has 2
	reset_fields();
	int64_t rc = h2_hpack_decode_block_wrapper(block3, sizeof(block3), &carry);
	ASSERT_EQ("truncated block rejected", H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("no field stored for the truncated block", 0, f[0].name_len);

	// a size update followed by an incremental-indexing literal decodes:
	// the entry is never stored (the dynamic table max size is 0), so the
	// block is accepted and the field is added to the output
	static const uint8_t block4[] = { 0x20, 0x41, 0x05, 'h', 'e', 'l', 'l', 'o' };
	reset_fields();
	rc = h2_hpack_decode_block_wrapper(block4, sizeof(block4), &carry);
	ASSERT_EQ("incremental indexing in block accepted — 1 field", 1, rc);
	ASSERT_EQ("carry clear", 0, carry);
	check_field("size update + incremental :authority hello", 0,
	            f[0].name, f[0].name_len, f[0].value, f[0].value_len,
	            ":authority", "hello");

	// more than H2_HPACK_MAX_FIELDS (32) — the fixed output area is full
	uint8_t many[33];
	memset(many, 0x82, sizeof(many)); // :method GET × 33
	reset_fields();
	rc = h2_hpack_decode_block_wrapper(many, sizeof(many), &carry);
	ASSERT_EQ("33-field block rejected (decode area full)",
	          H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
}

// ── whole header block — curl 8.7.1's exact GET / request ───────────
// The block captured on the wire: indexed :method GET and :scheme http,
// an incremental-indexed Huffman :authority, indexed :path /, an
// incremental-indexed Huffman user-agent, and an incremental-indexed
// plain accept — every representation a real client uses together.
static void test_h2_hpack_block_curl(void) {
	TEST_SUITE("h2_hpack_decode_block — curl's real request block");

	static const uint8_t block[] = {
		0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70,
		0xdc, 0x78, 0x20, 0x07, 0x84, 0x7a, 0x88, 0x25, 0xb6, 0x50,
		0xc3, 0xcb, 0xba, 0xb8, 0x7f, 0x53, 0x03, 0x2a, 0x2f, 0x2a,
	};
	reset_fields();
	int64_t carry;
	int64_t count = h2_hpack_decode_block_wrapper(block, (int64_t)sizeof(block),
	                                              &carry);
	ASSERT_EQ("block decodes", 0, carry);
	ASSERT_EQ("6 fields decoded", 6, count);

	h2_hpack_field_t *f = h2_hpack_fields_addr();
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme http", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "http");
	check_field("field 2 :authority (Huffman)", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":authority", "127.0.0.1:8100");
	check_field("field 3 :path /", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":path", "/");
	check_field("field 4 user-agent (Huffman)", 0, f[4].name, f[4].name_len,
	            f[4].value, f[4].value_len, "user-agent", "curl/8.7.1");
	check_field("field 5 accept", 0, f[5].name, f[5].name_len,
	            f[5].value, f[5].value_len, "accept", "*/*");
}

// ── Stage 8 — HEADERS → HPACK → the common request ──────────────────

// 8.1 — a HEADERS frame reaches the HPACK decoder: stream id, the
// header block and the END_STREAM/END_HEADERS flags are extracted, the
// block is decoded, and the request is built end-to-end.
static void test_h2_headers_hpack(void) {
	TEST_SUITE("h2_handle_headers — 8.1 HEADERS reaches the HPACK decoder");

	uint8_t wire[9];
	uint8_t payload[32];
	// :method GET, :scheme https, :path /index.html,
	// :authority example.com (literal without indexing, indexed name)
	static const uint8_t block[] = {
		0x82, 0x87, 0x85,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	memcpy(payload, block, sizeof(block));
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	reset_streams();
	reset_conn(&conn);
	reset_fields();

	put_wire_header(wire, sizeof(block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEADERS accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// stream id + flags extracted onto the stream entry
	h2_stream_t *s = h2_stream_find_wrapper(1);
	ASSERT_NOT_NULL("stream 1 created", s);
	ASSERT_EQ("END_STREAM extracted", H2_FLAG_END_STREAM,
	          s->flags & H2_FLAG_END_STREAM);
	ASSERT_EQ("END_HEADERS extracted", H2_FLAG_END_HEADERS,
	          s->flags & H2_FLAG_END_HEADERS);
	ASSERT_EQ("state HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s->state);

	// the header block reached the HPACK decoder
	h2_hpack_field_t *f = h2_hpack_fields_addr();
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme https", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "https");
	check_field("field 2 :path /index.html", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":path", "/index.html");
	check_field("field 3 :authority example.com", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":authority", "example.com");
	ASSERT_EQ("exactly 4 fields decoded", 0, f[4].name_len);

	// ... and the request was built from them
	ASSERT_EQ("request method GET", GET_ID, REQ->method);
	ASSERT_EQ("request stream id", 1, REQ->stream_id);
	ASSERT_STR_EQ("request path www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
}

// 8.2 — the request pseudo-headers become the common request struct.
static void test_h2_pseudo_request(void) {
	TEST_SUITE("h2_build_request — 8.2 pseudo-headers → common request");

	uint8_t wire[9];
	uint8_t payload[32];
	h2_frame_header_t hdr;
	h2_conn_t conn;
	int64_t carry;

	// :method GET, :path / — the required pair, nothing else
	reset_streams();
	reset_conn(&conn);
	memcpy(payload, H2_REQ_BLOCK, H2_REQ_BLOCK_LEN);
	put_wire_header(wire, H2_REQ_BLOCK_LEN, H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GET / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == GET_ID", GET_ID, REQ->method);
	ASSERT_EQ("stream_id == 1", 1, REQ->stream_id);
	ASSERT_STR_EQ("path = www/index.html (default file)", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));
	ASSERT_EQ("path_length", LITLEN("www/index.html"), REQ->path_length);
	ASSERT_EQ("query == NULL", 0, (int64_t)REQ->query);
	ASSERT_EQ("query_length == 0", 0, REQ->query_length);
	ASSERT_EQ("authority == NULL", 0, (int64_t)REQ->authority);

	// :scheme and :authority are carried along
	reset_streams();
	reset_conn(&conn);
	static const uint8_t full[] = {
		0x82, 0x87, 0x84,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	memcpy(payload, full, sizeof(full));
	put_wire_header(wire, sizeof(full), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 3);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("GET / with scheme+authority accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream_id == 3", 3, REQ->stream_id);
	ASSERT_STR_EQ("authority = example.com", "example.com",
	              REQ->authority, LITLEN("example.com"));

	// HEAD / — the default file applies to HEAD too (HEAD is not in the
	// RFC 7541 static table, so it must be sent as a literal value)
	reset_streams();
	reset_conn(&conn);
	static const uint8_t head_block[] = {
		0x02, 0x04, 'H', 'E', 'A', 'D', 0x84, // :method HEAD, :path /
	};
	memcpy(payload, head_block, sizeof(head_block));
	put_wire_header(wire, sizeof(head_block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 5);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("HEAD / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("method == HEAD_ID", HEAD_ID, REQ->method);
	ASSERT_STR_EQ("path = www/index.html", "www/index.html",
	              REQ->path, LITLEN("www/index.html"));

	// OPTIONS / — no default file, the bare docroot path
	reset_streams();
	reset_conn(&conn);
	static const uint8_t options_block[] = {
		0x02, 0x07, 'O', 'P', 'T', 'I', 'O', 'N', 'S', 0x84,
	};
	memcpy(payload, options_block, sizeof(options_block));
	put_wire_header(wire, sizeof(options_block), H2_FRAME_HEADERS,
	                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 7);
	h2_parse_wrapper(wire, &hdr);
	ASSERT_EQ("OPTIONS / accepted", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("method == OPTIONS_ID", OPTIONS_ID, REQ->method);
	ASSERT_STR_EQ("path = www/", "www/", REQ->path, LITLEN("www/"));
	ASSERT_EQ("path_length = 4", LITLEN("www/"), REQ->path_length);
}

// 8.3 — malformed pseudo-header blocks are rejected with PROTOCOL_ERROR.
static void test_h2_pseudo_validate(void) {
	TEST_SUITE("h2_build_request — 8.3 malformed pseudo-headers rejected");

	h2_hpack_field_t f[4];
	int64_t carry;

	// missing :method
	f[0] = field(":path", "/");
	set_fields(f, 1);
	ASSERT_EQ("missing :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 1, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// an empty block — no pseudo-headers at all
	set_fields(f, 0);
	ASSERT_EQ("empty block → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 0, &carry));

	// empty :method counts as missing
	f[0] = field(":method", "");
	f[1] = field(":path", "/");
	set_fields(f, 2);
	ASSERT_EQ("empty :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 2, &carry));

	// missing :path for a normal (GET) request
	f[0] = field(":method", "GET");
	set_fields(f, 1);
	ASSERT_EQ("missing :path → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 1, &carry));

	// duplicate pseudo-headers
	f[0] = field(":method", "GET");
	f[1] = field(":method", "GET");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("duplicate :method → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// a pseudo-header after a regular header
	f[0] = field(":method", "GET");
	f[1] = field("accept", "text/html");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("pseudo after regular → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// an undefined pseudo-header (:status is response-only)
	f[0] = field(":method", "GET");
	f[1] = field(":status", "200");
	f[2] = field(":path", "/");
	set_fields(f, 3);
	ASSERT_EQ("undefined pseudo-header → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 3, &carry));

	// a path that is not origin-form (no leading '/') is malformed
	f[0] = field(":method", "GET");
	f[1] = field(":path", "index.html");
	set_fields(f, 2);
	ASSERT_EQ("non-origin :path → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_build_request_wrapper(1, 2, &carry));

	// BREW is not a normal request — no :path required, like HTTP/1
	f[0] = field(":method", "BREW");
	set_fields(f, 1);
	ASSERT_EQ("BREW without :path accepted", 0,
	          h2_build_request_wrapper(3, 1, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("method == BREW_ID", BREW_ID, REQ->method);
	ASSERT_EQ("stream_id == 3", 3, REQ->stream_id);
}

// 8.4 — the critical boundary: /index.html over HTTP/2 must produce
// exactly the same internal request representation as HTTP/1. Both sides
// share the parse buffers (filename_buf/query_buf/authority_buf), so the
// HTTP/1 result is snapshotted before the HTTP/2 build overwrites them.
static void test_h2_request_equivalence(void) {
	TEST_SUITE("8.4 HTTP/2 request == HTTP/1 request (same internal form)");

	h2_hpack_field_t f[3];
	int64_t carry;
	char path1[64], auth1[64], q1buf[64];

	// ── /index.html, no query ──
	const char *req1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req1, LITLEN("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")));

	int64_t method1 = REQ->method;
	int64_t plen1 = REQ->path_length;
	int64_t qptr1 = (int64_t)REQ->query;
	int64_t qlen1 = REQ->query_length;
	int64_t alen1 = 0;
	while (REQ->authority[alen1]) alen1++;
	memcpy(path1, REQ->path, (unsigned long)plen1);
	memcpy(auth1, REQ->authority, (unsigned long)alen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field(":authority", "example.com");
	set_fields(f, 3);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 3, &carry));

	ASSERT_EQ("method identical", method1, REQ->method);
	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);
	ASSERT_EQ("query identical (NULL)", qptr1, (int64_t)REQ->query);
	ASSERT_EQ("query_length identical", qlen1, REQ->query_length);
	int64_t alen2 = 0;
	while (REQ->authority[alen2]) alen2++;
	ASSERT_EQ("authority length identical", alen1, alen2);
	ASSERT_TRUE("authority bytes identical",
	            memcmp(auth1, REQ->authority, (unsigned long)alen1) == 0);
	// the one intentional difference: HTTP/2 carries the stream id
	ASSERT_EQ("stream_id = 1 (HTTP/2)", 1, REQ->stream_id);

	// ── /index.html?x=1&y=2 — the query is carried raw on both sides ──
	const char *req2 =
		"GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req2, LITLEN(
		          "GET /index.html?x=1&y=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")));

	plen1 = REQ->path_length;
	qlen1 = REQ->query_length;
	memcpy(path1, REQ->path, (unsigned long)plen1);
	memcpy(q1buf, REQ->query, (unsigned long)qlen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html?x=1&y=2");
	f[2] = field(":authority", "example.com");
	set_fields(f, 3);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 3, &carry));

	ASSERT_EQ("query_length identical", qlen1, REQ->query_length);
	ASSERT_TRUE("query bytes identical",
	            memcmp(q1buf, REQ->query, (unsigned long)qlen1) == 0);
	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);

	// ── percent-encoding — both sides decode %XX the same way ──
	const char *req3 = "GET /a%20b HTTP/1.1\r\nHost: localhost\r\n\r\n";
	ASSERT_EQ("HTTP/1 parse carries clear", 0,
	          parse_request_wrapper(req3, LITLEN("GET /a%20b HTTP/1.1\r\nHost: localhost\r\n\r\n")));

	plen1 = REQ->path_length;
	memcpy(path1, REQ->path, (unsigned long)plen1);

	f[0] = field(":method", "GET");
	f[1] = field(":path", "/a%20b");
	set_fields(f, 2);
	ASSERT_EQ("HTTP/2 build succeeds", 0,
	          h2_build_request_wrapper(1, 2, &carry));

	ASSERT_EQ("path_length identical", plen1, REQ->path_length);
	ASSERT_TRUE("path bytes identical",
	            memcmp(path1, REQ->path, (unsigned long)plen1) == 0);
}

// ── Stage 9 — the first working HTTP/2 GET ──────────────────────────

// 9 — protocol detection: the first bytes decide HTTP/2 vs HTTP/1.
static void test_h2_probe(void) {
	TEST_SUITE("h2_probe — HTTP/2 preface detection (Phase 16 Option B)");

	ASSERT_EQ("full preface", 1, h2_probe_wrapper(H2_PREFACE, H2_PREFACE_LEN));
	ASSERT_EQ("partial preface (10 bytes)", 1, h2_probe_wrapper(H2_PREFACE, 10));
	ASSERT_EQ("preface + extra bytes", 1,
	          h2_probe_wrapper(H2_PREFACE, H2_PREFACE_LEN + 1));
	static const char get[] = "GET / HTTP/1.1\r\n";
	ASSERT_EQ("HTTP/1 GET rejected", 0,
	          h2_probe_wrapper((const uint8_t *)get, LITLEN(get)));
	ASSERT_EQ("empty buffer rejected", 0, h2_probe_wrapper(H2_PREFACE, 0));
}

// ── 9.2 — the HEADERS response encoder, raw wire bytes ──────────────
static void test_h2_write_headers(void) {
	TEST_SUITE("9.2 h2_write_headers — HEADERS frame (200, content-type, content-length)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;        // RES_NONE — no content-encoding
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello</h1>";
	response_t resp = {
		.status = 200,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 1, 0);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x88 | 0x0f 0x10 0x18 ct | 0x0f 0x0d 0x02 "14" → 33 bytes
	// (content-type = static 31, content-length = static 28 — both need
	// the two-octet 4-bit-prefix name index)
	// frame: 9-byte header (len 33, HEADERS, END_HEADERS, stream 1) + block
	uint8_t expect[] = {
		0x00, 0x00, 0x21, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x88,
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '4',
	};
	ASSERT_EQ("42 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

// 9.2 — the same 200 response, but with a gzipped embedded asset: the
// encoder must add content-encoding: gzip (static index 26 → 0x0f 0x0b).
// This exercises the resource_type/embedded_gzip globals path the real
// server uses for gzipped assets like index.html.
static void test_h2_write_headers_gzip(void) {
	TEST_SUITE("9.2 h2_write_headers — content-encoding: gzip for gzipped assets");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 1;        // RES_EMBEDDED
	embedded_gzip = 1;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello</h1>";
	response_t resp = {
		.status = 200,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 1, 0);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x88 | ct | content-length | 0x0f 0x0b 0x04 "gzip" → 40 bytes
	uint8_t expect[] = {
		0x00, 0x00, 0x28, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x88,
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '4',
		0x0f, 0x0b, 0x04, 'g', 'z', 'i', 'p',
	};
	ASSERT_EQ("49 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the gzip HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

// bodyless status response — literal :status, END_STREAM on HEADERS.
static void test_h2_write_headers_404(void) {
	TEST_SUITE("9.2 h2_write_headers — 404 (literal :status, END_STREAM)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	response_t resp = {
		.status = 404,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = 0,
		.body = 0,
		.body_length = 0,
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 3, H2_FLAG_END_STREAM);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[128];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x08 0x03 "404" | 0x0f 0x0d 0x01 "0" → 9 bytes
	// (content-length = static 28, the two-octet 4-bit-prefix name index)
	uint8_t expect[] = {
		0x00, 0x00, 0x09, 0x01, 0x05, 0x00, 0x00, 0x00, 0x03,
		0x08, 0x03, '4', '0', '4',
		0x0f, 0x0d, 0x01, '0',
	};
	ASSERT_EQ("18 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected 404 HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

// ── 9.3 — the DATA encoder, raw wire bytes ──────────────────────────
static void test_h2_write_body(void) {
	TEST_SUITE("9.3 h2_write_body — single DATA frame + END_STREAM");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	static const char body[] = "hello world";
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int64_t carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[128];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	uint8_t expect[] = {
		0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // DATA len=11 END_STREAM
		'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd',
	};
	ASSERT_EQ("20 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the expected DATA frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

// bodies larger than the max frame size split into multiple DATA frames;
// only the final one carries END_STREAM. The response (16502 bytes) is
// bigger than any default socket buffer on macOS, so a forked child
// drains — and verifies — the socket while the parent writes.
static void test_h2_write_body_chunked(void) {
	TEST_SUITE("9.3 h2_write_body — multi-frame DATA (max frame size)");

	static uint8_t big[H2_DEFAULT_MAX_FRAME_SIZE + 100];
	memset(big, 'a', sizeof(big));

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = (int64_t)sizeof(big),
		.body = (const char *)big,
		.body_length = (int64_t)sizeof(big),
		.range_start = -1,
		.range_end = -1,
	};

	int pid = fork();
	if (pid == 0) {
		// ── reader/verifier side ──
		close(sv[1]);
		uint8_t got[H2_DEFAULT_MAX_FRAME_SIZE + 128];
		long n = 0;
		while (n < (long)sizeof(got)) {
			long r = read(sv[0], got + n, (unsigned long)(sizeof(got) - n));
			if (r <= 0) break;
			n += r;
		}
		close(sv[0]);

		long total = (long)(2 * H2_WIRE_HEADER_LEN + sizeof(big));
		if (n != total) _exit(1);

		// frame 1 — the full max frame (16384 = 0x4000), no END_STREAM
		if ((((uint32_t)got[0] << 16) | ((uint32_t)got[1] << 8) | got[2]) != 0x4000)
			_exit(2);
		if (got[3] != H2_FRAME_DATA || got[4] != 0) _exit(3);
		if ((((uint32_t)got[5] << 24) | ((uint32_t)got[6] << 16) |
		     ((uint32_t)got[7] << 8) | got[8]) != 1) _exit(4);
		if (got[9] != 'a' || got[9 + H2_DEFAULT_MAX_FRAME_SIZE - 1] != 'a') _exit(5);

		// frame 2 — the 100-byte remainder, END_STREAM
		long off = H2_WIRE_HEADER_LEN + H2_DEFAULT_MAX_FRAME_SIZE;
		if ((((uint32_t)got[off + 0] << 16) | ((uint32_t)got[off + 1] << 8) |
		     got[off + 2]) != 100) _exit(6);
		if (got[off + 3] != H2_FRAME_DATA ||
		    got[off + 4] != H2_FLAG_END_STREAM) _exit(7);
		if ((((uint32_t)got[off + 5] << 24) | ((uint32_t)got[off + 6] << 16) |
		     ((uint32_t)got[off + 7] << 8) | got[off + 8]) != 1) _exit(8);
		if (got[off + 9] != 'a') _exit(9);
		_exit(0);
	}

	// ── writer side ──
	close(sv[0]);
	int64_t carry = h2_write_body_wrapper(sv[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(sv[1]);
	int status = 0;
	waitpid(pid, &status, 0);

	ASSERT_EQ("reader verified two DATA frames + END_STREAM", 0,
	          (status >> 8) & 0xff);
}

// ── 9.1 — a built request is served through the existing machinery ──
static void test_h2_process_request(void) {
	TEST_SUITE("9.1 h2_process_request — common request → existing resource handler");

	reset_streams();
	reset_fields();
	reset_conn(h2_conn_addr());

	// a request stream: IDLE → OPEN → HALF_CLOSED_REMOTE (HEADERS + END_STREAM)
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_NOT_NULL("stream created", s);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry);
	ASSERT_EQ("headers event ok", 0, carry);
	h2_stream_event_wrapper(s, H2_EVENT_RECV_END_STREAM, &carry);
	ASSERT_EQ("end_stream event ok", 0, carry);
	ASSERT_EQ("stream is HALF_CLOSED_REMOTE", H2_STREAM_HALF_CLOSED_REMOTE,
	          s->state);

	// build the request: GET /index.html
	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	set_fields(f, 2);
	ASSERT_EQ("request built", 0, h2_build_request_wrapper(1, 2, &carry));

	// serve it through a pipe and capture the response frames
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
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("stream moved to CLOSED", H2_STREAM_CLOSED, s->state);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// HEADERS (9) + block (33) = 42, DATA (9 + 17) = 26 → 68 total
	ASSERT_EQ("68 response bytes", 68, n);

	// HEADERS frame: len=0x21 (33), END_HEADERS, stream 1
	ASSERT_EQ("headers length", 0x21,
	          ((uint32_t)got[0] << 16) | ((uint32_t)got[1] << 8) | got[2]);
	ASSERT_EQ("headers type", H2_FRAME_HEADERS, got[3]);
	ASSERT_EQ("headers flags", H2_FLAG_END_HEADERS, got[4]);
	ASSERT_EQ("headers stream", 1,
	          ((uint32_t)got[5] << 24) | ((uint32_t)got[6] << 16) |
	          ((uint32_t)got[7] << 8) | got[8]);
	// HPACK block: :status 200 indexed, content-type (static 31),
	// content-length (static 28) — both two-octet 4-bit-prefix indices
	ASSERT_EQ(":status 200 indexed", 0x88, got[9]);
	ASSERT_EQ("content-type name idx", 0x0f, got[10]);
	ASSERT_EQ("content-type name idx cont", 0x10, got[11]);
	ASSERT_EQ("content-type len", 24, got[12]);
	ASSERT_STR_EQ("content-type value", "text/html; charset=utf-8",
	              got + 13, 24);
	ASSERT_EQ("content-length name idx", 0x0f, got[37]);
	ASSERT_EQ("content-length name idx cont", 0x0d, got[38]);
	ASSERT_EQ("content-length len", 2, got[39]);
	ASSERT_STR_EQ("content-length value", "17", got + 40, 2);

	// DATA frame: len=17, END_STREAM, stream 1, the stub's body
	ASSERT_EQ("data length", 17,
	          ((uint32_t)got[42] << 16) | ((uint32_t)got[43] << 8) | got[44]);
	ASSERT_EQ("data type", H2_FRAME_DATA, got[45]);
	ASSERT_EQ("data flags", H2_FLAG_END_STREAM, got[46]);
	ASSERT_EQ("data stream", 1,
	          ((uint32_t)got[47] << 24) | ((uint32_t)got[48] << 16) |
	          ((uint32_t)got[49] << 8) | got[50]);
	ASSERT_STR_EQ("body", "<h1>hello h2</h1>", got + 51, 17);
}

// ── 9.4 — the full connection loop over a real socketpair ───────────
// Client sends preface + SETTINGS + HEADERS (GET /index.html, END_STREAM);
// the server loop verifies the preface, sends its SETTINGS, serves the
// request and closes when the client closes. The client side verifies
// the exact response bytes and exits 0; the parent asserts that status.
static void test_h2_connection_loop(void) {
	TEST_SUITE("9.4 h2_connection_loop — preface + SETTINGS + HEADERS + DATA");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side ──
		close(sv[0]);
		uint8_t out[128], in[256];
		long out_len = 0;

		// the 24-byte connection preface
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		// client SETTINGS — empty payload, stream 0
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// HEADERS — the exact block curl 8.7.1 sent for GET / (captured
		// on the wire): indexed :method GET / :scheme http, a Huffman-
		// coded :authority, indexed :path /, an incremental-indexed
		// Huffman user-agent, and a plain accept — the full set of
		// representations a real client uses
		static const uint8_t block[] = {
			0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70,
			0xdc, 0x78, 0x20, 0x07, 0x84, 0x7a, 0x88, 0x25, 0xb6, 0x50,
			0xc3, 0xcb, 0xba, 0xb8, 0x7f, 0x53, 0x03, 0x2a, 0x2f, 0x2a,
		};
		put_wire_header(out + out_len, (uint32_t)sizeof(block), H2_FRAME_HEADERS,
		                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		out_len += H2_WIRE_HEADER_LEN;
		memcpy(out + out_len, block, sizeof(block));
		out_len += (long)sizeof(block);

		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(1);
			w += r;
		}
		// read the full response: SETTINGS (15) + HEADERS (42) + DATA (26)
		long n = 0;
		while (n < 83) {
			long r = read(sv[1], in + n, (unsigned long)(83 - n));
			if (r <= 0) break;
			n += r;
		}
		if (n != 83) _exit(2);
		// server SETTINGS: len=6, type=4, stream=0, entry id=1 value=0
		if (in[0] != 0 || in[1] != 0 || in[2] != 6 ||
		    in[3] != H2_FRAME_SETTINGS || in[4] != 0 ||
		    in[5] != 0 || in[6] != 0 || in[7] != 0 || in[8] != 0)
			_exit(3);
		if (in[9] != 0 || in[10] != H2_SETTINGS_HEADER_TABLE_SIZE ||
		    in[11] != 0 || in[12] != 0 || in[13] != 0 || in[14] != 0)
			_exit(4);
		// HEADERS: len=0x21 (33), type=1, flags=END_HEADERS, stream=1
		if (in[15] != 0 || in[16] != 0 || in[17] != 0x21 ||
		    in[18] != H2_FRAME_HEADERS || in[19] != H2_FLAG_END_HEADERS ||
		    in[20] != 0 || in[21] != 0 || in[22] != 0 || in[23] != 1)
			_exit(5);
		// HPACK block: 0x88 | 0x0f 0x10 0x18 ct | 0x0f 0x0d 0x02 "17"
		if (in[24] != 0x88 || in[25] != 0x0f || in[26] != 0x10 ||
		    in[27] != 0x18 ||
		    memcmp(in + 28, "text/html; charset=utf-8", 24) != 0 ||
		    in[52] != 0x0f || in[53] != 0x0d || in[54] != 0x02 ||
		    in[55] != '1' || in[56] != '7')
			_exit(6);
		// DATA: len=17, type=0, flags=END_STREAM, stream=1, body
		if (in[57] != 0 || in[58] != 0 || in[59] != 17 ||
		    in[60] != H2_FRAME_DATA || in[61] != H2_FLAG_END_STREAM ||
		    in[62] != 0 || in[63] != 0 || in[64] != 0 || in[65] != 1)
			_exit(7);
		if (memcmp(in + 66, "<h1>hello h2</h1>", 17) != 0)
			_exit(8);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: run the loop with no pre-buffered bytes ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);

	// the child's exit code doubles as the verification result
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client verified preface + SETTINGS + HEADERS + DATA", 0, exit_code);
}

// ═══════════════════════════════════════════════════════════════════
//  Stage 10 — complete static responses
// ═══════════════════════════════════════════════════════════════════

static int64_t slen(const char *s) {
	int64_t n = 0;
	while (s[n]) n++;
	return n;
}

// get_filetype(filename=x0, len=x1) → (ct=x0, ct_len=x1) — the HTTP/1
// MIME source (file.S), used to prove HTTP/2 serves the same types.
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

// Drive one request through h2_process_request end-to-end and capture
// the response: a fresh stream in HALF_CLOSED_REMOTE, the given HPACK
// fields, a pipe as the client fd. Returns bytes captured (<= cap).
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

// ── 10.1 — HEAD: headers only, no response body ────────────────────
static void test_h2_head_no_body(void) {
	TEST_SUITE("10.1 HEAD — headers only (END_STREAM on HEADERS, no DATA)");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "HEAD");
	f[1] = field(":path", "/index.html");

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	// HEADERS (9 + 33 block) and nothing else: 42 bytes, no DATA frame
	ASSERT_EQ("42 response bytes — no body", 42, n);
	// flags = END_HEADERS | END_STREAM (0x05)
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	// content-length still reflects the full resource (17), like HTTP/1
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 17 (full resource)", "17", cl, vlen);
}

// HEAD ignores the Range header, matching HTTP/1's head (which never
// parses ranges): 200, full content-length, no content-range, no body.
static void test_h2_head_ignores_range(void) {
	TEST_SUITE("10.5 HEAD + Range — range ignored (HTTP/1 parity)");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "HEAD");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=0-9");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	ASSERT_EQ("42 response bytes — no body", 42, n);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 200 (not 206)", "200", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 17", "17", cl, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_TRUE("no content-range", cr == NULL);
}

// ── 10.2 — 404: GET /does-not-exist ─────────────────────────────────
static void test_h2_404(void) {
	TEST_SUITE("10.2 GET /does-not-exist — 404");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/does-not-exist");

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	// literal :status 404 + content-length 0 → 9-byte block → 18 bytes
	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 404", "404", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 0", "0", cl, vlen);
}

// ── 10.3 — 403: a path the server refuses to serve ──────────────────
static void test_h2_403(void) {
	TEST_SUITE("10.3 GET /../etc/passwd — 403 (inaccessible resource)");

	h2_hpack_field_t f[2];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/../etc/passwd");

	// the request decodes cleanly — the path failing the traversal check
	// is REQ_FORBIDDEN, not a protocol error
	reset_fields();
	int64_t carry;
	set_fields(f, 2);
	ASSERT_EQ("request builds (no protocol error)", 0,
	          h2_build_request_wrapper(1, 2, &carry));
	ASSERT_EQ("REQ_FORBIDDEN set", 1, REQ->forbidden);

	uint8_t got[512];
	long n = serve_request(f, 2, got, sizeof(got));

	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 403", "403", st, vlen);
}

// ── 10.4 — MIME types: HTTP/2 == HTTP/1 (get_filetype) ──────────────
static void test_h2_mime(void) {
	TEST_SUITE("10.4 MIME types — .html/.css/.js/.svg/.png match HTTP/1");

	static const char *paths[] = {
		"/index.html", "/assets/style.css", "/assets/app.js",
		"/logo.svg", "/logo.png",
	};
	static const char *cts[] = {
		"text/html; charset=utf-8",
		"text/css; charset=utf-8",
		"text/javascript; charset=utf-8",
		"image/svg+xml",
		"image/png",
	};

	for (int i = 0; i < 5; i++) {
		// the HTTP/1 side derives the type from the extension (file.S)
		const char *h1_ct = NULL;
		int64_t h1_ct_len = 0;
		get_filetype_wrapper(paths[i], slen(paths[i]), &h1_ct, &h1_ct_len);

		h2_hpack_field_t f[2];
		f[0] = field(":method", "GET");
		f[1] = field(":path", paths[i]);
		uint8_t got[512];
		long n = serve_request(f, 2, got, sizeof(got));

		hdr_scan_t h;
		scan_block(got + 9, n - 9, &h);
		long vlen = 0;
		const uint8_t *ct = scan_find(&h, 31, &vlen);
		ASSERT_NOT_NULL("content-type present", ct);
		if (!ct) continue;
		ASSERT_TRUE("content-type == HTTP/1 get_filetype",
		            vlen == h1_ct_len &&
		            memcmp(ct, h1_ct, (unsigned long)vlen) == 0);
		ASSERT_TRUE("content-type == expected",
		            vlen == slen(cts[i]) &&
		            memcmp(ct, cts[i], (unsigned long)vlen) == 0);
	}
}

// ── 10.5 — ranges ───────────────────────────────────────────────────
// The full flow for GET /index.html (17-byte stub body) with a Range:
// the 206 response carries content-length (windowed) and
// content-range (window/total), and the DATA body is exactly the window.
static void test_h2_range(void) {
	TEST_SUITE("10.5 GET + Range: bytes=0-9 — 206 with content-range");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=0-9");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// block: literal :status 206 + content-type + content-length 10 +
	// content-range 0-9/17 → 46 bytes; DATA: 9 + 10 → 74 total
	ASSERT_EQ("74 response bytes", 74, n);
	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	ASSERT_EQ("46-byte HPACK block", 46, blen);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 206", "206", st, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 10", "10", cl, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 0-9/17", "0-9/17", cr, vlen);

	// the DATA frame carries exactly the requested window
	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 10",
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2],
	          10);
	ASSERT_EQ("DATA type", H2_FRAME_DATA, got[data_off + 3]);
	ASSERT_EQ("DATA END_STREAM", H2_FLAG_END_STREAM, got[data_off + 4]);
	ASSERT_STR_EQ("body = first 10 bytes", "<h1>hello ", got + data_off + 9, 10);
}

static void test_h2_range_open(void) {
	TEST_SUITE("10.5 GET + Range: bytes=10- — open-ended 206");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=10-");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 10-16/17", "10-16/17", cr, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 7", "7", cl, vlen);

	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 7", 7,
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2]);
	ASSERT_STR_EQ("body = h2</h1>", "h2</h1>", got + data_off + 9, 7);
}

static void test_h2_range_suffix(void) {
	TEST_SUITE("10.5 GET + Range: bytes=-5 — suffix 206");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=-5");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	hdr_scan_t h;
	long blen = scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_NOT_NULL("content-range present", cr);
	if (cr) ASSERT_STR_EQ("content-range = 12-16/17", "12-16/17", cr, vlen);
	const uint8_t *cl = scan_find(&h, 28, &vlen);
	ASSERT_NOT_NULL("content-length present", cl);
	if (cl) ASSERT_STR_EQ("content-length = 5", "5", cl, vlen);

	long data_off = 9 + blen;
	ASSERT_EQ("DATA length 5", 5,
	          ((uint32_t)got[data_off] << 16) | ((uint32_t)got[data_off + 1] << 8) |
	              got[data_off + 2]);
	ASSERT_STR_EQ("body = </h1>", "</h1>", got + data_off + 9, 5);
}

static void test_h2_range_unsatisfiable(void) {
	TEST_SUITE("10.5 GET + Range: bytes=100- — 416");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "bytes=100-");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// literal :status 416 + content-length 0 → 9-byte block → 18 bytes
	ASSERT_EQ("18 response bytes", 18, n);
	ASSERT_EQ("END_STREAM on the HEADERS frame",
	          H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, got[4]);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 416", "416", st, vlen);
}

static void test_h2_range_invalid(void) {
	TEST_SUITE("10.5 GET + unparsable Range — ignored, full 200");

	h2_hpack_field_t f[3];
	f[0] = field(":method", "GET");
	f[1] = field(":path", "/index.html");
	f[2] = field("range", "garbage");

	uint8_t got[512];
	long n = serve_request(f, 3, got, sizeof(got));

	// the full 200 response: HEADERS (42) + DATA (26)
	ASSERT_EQ("68 response bytes", 68, n);
	hdr_scan_t h;
	scan_block(got + 9, n - 9, &h);
	long vlen = 0;
	const uint8_t *st = scan_find(&h, 8, &vlen);
	ASSERT_NOT_NULL(":status present", st);
	if (st) ASSERT_STR_EQ(":status = 200", "200", st, vlen);
	const uint8_t *cr = scan_find(&h, 30, &vlen);
	ASSERT_TRUE("no content-range", cr == NULL);
}

// ── 10.5 — the range parser and resolver, standalone ────────────────
static void test_h2_parse_range(void) {
	TEST_SUITE("10.5 h2_parse_range — Range header value parsing");

	int64_t end, carry;

	// concrete range
	ASSERT_EQ("bytes=0-99 → start 0", 0,
	          h2_parse_range_wrapper("bytes=0-99", 10, &end, &carry));
	ASSERT_EQ("bytes=0-99 → end 99", 99, end);
	ASSERT_EQ("carry clear", 0, carry);

	// open-ended
	ASSERT_EQ("bytes=100- → start 100", 100,
	          h2_parse_range_wrapper("bytes=100-", 10, &end, &carry));
	ASSERT_EQ("bytes=100- → end -1", -1, end);
	ASSERT_EQ("carry clear", 0, carry);

	// suffix
	ASSERT_EQ("bytes=-50 → start -1", -1,
	          h2_parse_range_wrapper("bytes=-50", 9, &end, &carry));
	ASSERT_EQ("bytes=-50 → end 50", 50, end);
	ASSERT_EQ("carry clear", 0, carry);

	// case-insensitive unit, single-byte range
	ASSERT_EQ("Bytes=0-0 → start 0", 0,
	          h2_parse_range_wrapper("Bytes=0-0", 9, &end, &carry));
	ASSERT_EQ("Bytes=0-0 → end 0", 0, end);
	ASSERT_EQ("carry clear", 0, carry);

	// invalid values — carry set, treated as "no range" (like HTTP/1)
	h2_parse_range_wrapper("garbage", 7, &end, &carry);
	ASSERT_EQ("non-bytes unit rejected", 1, carry);
	h2_parse_range_wrapper("bytes=", 6, &end, &carry);
	ASSERT_EQ("empty value rejected", 1, carry);
	h2_parse_range_wrapper("bytes=abc", 9, &end, &carry);
	ASSERT_EQ("non-digit start rejected", 1, carry);
	h2_parse_range_wrapper("bytes=10-5", 10, &end, &carry);
	ASSERT_EQ("end < start rejected", 1, carry);
	h2_parse_range_wrapper("bytes=0-99,200-299", 19, &end, &carry);
	ASSERT_EQ("multi-range rejected (single range only)", 1, carry);
	h2_parse_range_wrapper("bytes=0", 7, &end, &carry);
	ASSERT_EQ("no dash rejected", 1, carry);
}

static void test_h2_resolve_range(void) {
	TEST_SUITE("10.5 h2_resolve_range — range → 200/206/416");

	int64_t end, status;

	// 17-byte resource (the stub index.html)
	ASSERT_EQ("0-9/17 → start 0", 0, h2_resolve_range_wrapper(0, 9, 17, &end, &status));
	ASSERT_EQ("0-9/17 → end 9", 9, end);
	ASSERT_EQ("0-9/17 → 206", 206, status);

	// end clamped to size-1
	ASSERT_EQ("10-99/17 → start 10", 10,
	          h2_resolve_range_wrapper(10, 99, 17, &end, &status));
	ASSERT_EQ("10-99/17 → end 16", 16, end);
	ASSERT_EQ("10-99/17 → 206", 206, status);

	// open-ended
	ASSERT_EQ("12-/17 → start 12", 12,
	          h2_resolve_range_wrapper(12, -1, 17, &end, &status));
	ASSERT_EQ("12-/17 → end 16", 16, end);
	ASSERT_EQ("12-/17 → 206", 206, status);

	// suffix
	ASSERT_EQ("-5/17 → start 12", 12,
	          h2_resolve_range_wrapper(-1, 5, 17, &end, &status));
	ASSERT_EQ("-5/17 → end 16", 16, end);
	ASSERT_EQ("-5/17 → 206", 206, status);

	// suffix >= size → the whole file, still a 206 (mirrors get.S: the
	// range is clamped to the file, so it's satisfiable — no 200 path)
	ASSERT_EQ("-99/17 → start 0", 0,
	          h2_resolve_range_wrapper(-1, 99, 17, &end, &status));
	ASSERT_EQ("-99/17 → end 16", 16, end);
	ASSERT_EQ("-99/17 → 206", 206, status);

	// start >= size → 416
	ASSERT_EQ("17-/17 → 416", -1,
	          h2_resolve_range_wrapper(17, -1, 17, &end, &status));
	ASSERT_EQ("17-/17 status 416", 416, status);
	ASSERT_EQ("99-100/17 → 416", -1,
	          h2_resolve_range_wrapper(99, 100, 17, &end, &status));
	ASSERT_EQ("99-100/17 status 416", 416, status);

	// bytes=-0 → 416; empty-file edge cases
	ASSERT_EQ("-0/17 → 416", -1, h2_resolve_range_wrapper(-1, 0, 17, &end, &status));
	ASSERT_EQ("-0/17 status 416", 416, status);
	ASSERT_EQ("0-9/0 → 416 (empty file)", -1,
	          h2_resolve_range_wrapper(0, 9, 0, &end, &status));
	ASSERT_EQ("0-9/0 status 416", 416, status);
	ASSERT_EQ("-5/0 → 200 (empty file)", -1,
	          h2_resolve_range_wrapper(-1, 5, 0, &end, &status));
	ASSERT_EQ("-5/0 status 200", 200, status);
}

// ── 10.5 — the 206 response encoder, raw wire bytes ────────────────
static void test_h2_write_headers_206(void) {
	TEST_SUITE("10.5 h2_write_headers — 206 (content-length + content-range)");

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	resource_type = 0;
	embedded_gzip = 0;
	embedded_etag = 0;
	embedded_etag_len = 0;

	static const char ct[] = "text/html; charset=utf-8";
	static const char body[] = "<h1>hello h2</h1>";
	response_t resp = {
		.status = 206,
		.content_type = ct,
		.content_type_len = LITLEN(ct),
		.content_length = LITLEN(body),  // total resource size
		.body = body,
		.body_length = 10,               // the 0-9 window
		.range_start = 0,
		.range_end = 9,
	};

	int64_t carry = h2_write_headers_wrapper(fds[1], &resp, 1, 0);
	ASSERT_EQ("carry clear", 0, carry);

	close(fds[1]);
	uint8_t got[512];
	long n = 0;
	while (n < (long)sizeof(got)) {
		long r = read(fds[0], got + n, (unsigned long)(sizeof(got) - n));
		if (r <= 0) break;
		n += r;
	}
	close(fds[0]);

	// block: 0x08 0x03 "206" | ct (static 31) | content-length 10
	// (static 28) | content-range 0-9/17 (static 30 → 0x0f 0x0f)
	// = 5 + 27 + 5 + 9 = 46 bytes; frame = 9 + 46 = 55
	uint8_t expect[] = {
		0x00, 0x00, 0x2e, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x03, '2', '0', '6',
		0x0f, 0x10, 0x18,
		't', 'e', 'x', 't', '/', 'h', 't', 'm', 'l', ';', ' ',
		'c', 'h', 'a', 'r', 's', 'e', 't', '=', 'u', 't', 'f', '-', '8',
		0x0f, 0x0d, 0x02, '1', '0',
		0x0f, 0x0f, 0x06, '0', '-', '9', '/', '1', '7',
	};
	ASSERT_EQ("55 wire bytes", (long)sizeof(expect), n);
	ASSERT_TRUE("bytes match the 206 HEADERS frame",
	            memcmp(got, expect, sizeof(expect)) == 0);
}

// ═══════════════════════════════════════════════════════════════════
//  Stage 11 — DATA flow control (RFC 9113 §5.2, §6.9)
// ═══════════════════════════════════════════════════════════════════
// The server's send-side credit: the connection window (h2_conn,
// shared by all streams) and each stream's window (h2_streams entry)
// start at 65535 (H2_DEF_INITIAL_WINDOW_SIZE) and are drained by every
// DATA frame the server sends. WINDOW_UPDATE replenishes them.

// ── 11.1 — the connection window ───────────────────────────────────
// Sending DATA drains the connection window. With no stream entry
// (h2_write_body's stream-id lookup misses), only the connection-level
// credit applies: the chunk is bounded by the connection window alone.
static void test_h2_flow_conn_window(void) {
	TEST_SUITE("11.1 connection window — DATA send drains it");

	reset_conn(h2_conn_addr());
	reset_streams();

	static const char body[] = "flow control body";
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	int64_t carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(fds[1]);
	uint8_t drain[128];
	while (read(fds[0], drain, sizeof(drain)) > 0) ;
	close(fds[0]);

	ASSERT_EQ("connection window drained by the body",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), h2_conn_addr()->window);
}

// ── 11.2 — the stream window ───────────────────────────────────────
// With a stream in play, a DATA send drains BOTH the connection window
// and the stream's window; each starts at the peer's
// SETTINGS_INITIAL_WINDOW_SIZE (65535 default).
static void test_h2_flow_stream_window(void) {
	TEST_SUITE("11.2 stream window — DATA send drains both windows");

	reset_conn(h2_conn_addr());
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_EQ("stream created", 0, carry);
	ASSERT_EQ("stream window starts at 65535", H2_DEF_INITIAL_WINDOW_SIZE,
	          s->window);

	static const char body[] = "flow control body";
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	int fds[2];
	if (pipe(fds) != 0) {
		printf("  ✗ pipe() failed\n");
		exit(2);
	}
	carry = h2_write_body_wrapper(fds[1], &resp, 1);
	ASSERT_EQ("carry clear", 0, carry);
	close(fds[1]);
	uint8_t drain[128];
	while (read(fds[0], drain, sizeof(drain)) > 0) ;
	close(fds[0]);

	ASSERT_EQ("connection window drained",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), h2_conn_addr()->window);
	ASSERT_EQ("stream window drained",
	          H2_DEF_INITIAL_WINDOW_SIZE - LITLEN(body), s->window);
}

// ── 11.3 — WINDOW_UPDATE (§6.9) ────────────────────────────────────
// The handler: the 31-bit increment replenishes the connection window
// (stream 0) or the stream window (nonzero id). Zero increments, wrong
// lengths, idle streams and over-2^31 windows are rejected; updates on
// CLOSED streams are ignored (§5.1 — a peer may update after END_STREAM).
static void test_h2_flow_window_update(void) {
	TEST_SUITE("11.3 h2_handle_window_update — §6.9 credit replenishment");

	h2_conn_t conn;
	reset_conn(&conn);
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, &conn, &carry);
	ASSERT_EQ("stream created", 0, carry);

	uint8_t payload[4];
	h2_frame_header_t hdr;
	hdr.type = H2_FRAME_WINDOW_UPDATE;
	hdr.flags = 0;

	// stream 0 → the connection window
	hdr.length = 4;
	hdr.stream_id = 0;
	payload[0] = 0x00; payload[1] = 0x00; payload[2] = 0x03; payload[3] = 0xe8; // +1000
	ASSERT_EQ("conn window update ok", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry clear", 0, carry);
	ASSERT_EQ("connection window +1000", H2_DEF_INITIAL_WINDOW_SIZE + 1000,
	          conn.window);

	// stream 1 → the stream window
	hdr.stream_id = 1;
	payload[2] = 0x01; payload[3] = 0xf4; // +500
	ASSERT_EQ("stream window update ok", 0,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("stream window +500", H2_DEF_INITIAL_WINDOW_SIZE + 500, s->window);

	// an increment of 0 → PROTOCOL_ERROR
	hdr.stream_id = 0;
	payload[2] = 0x00; payload[3] = 0x00;
	ASSERT_EQ("zero increment → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// a length other than 4 → FRAME_SIZE_ERROR
	hdr.length = 2;
	ASSERT_EQ("bad length → FRAME_SIZE_ERROR", H2_ERR_FRAME_SIZE_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// an update that would push a window past 2^31-1 → FLOW_CONTROL_ERROR.
	// conn.window is 66535; 0x7fffffff more overshoots the ceiling.
	hdr.length = 4;
	hdr.stream_id = 0;
	payload[0] = 0x7f; payload[1] = 0xff; payload[2] = 0xff; payload[3] = 0xff;
	ASSERT_EQ("window overflow → FLOW_CONTROL_ERROR", H2_ERR_FLOW_CONTROL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));
	ASSERT_EQ("carry set", 1, carry);

	// an idle stream (never created) → PROTOCOL_ERROR
	hdr.stream_id = 5;
	payload[0] = 0x00; payload[1] = 0x00; payload[2] = 0x00; payload[3] = 0x64;
	ASSERT_EQ("idle stream → PROTOCOL_ERROR", H2_ERR_PROTOCOL_ERROR,
	          h2_dispatch_wrapper(&hdr, payload, &conn, &carry));

	// RST_STREAM closes stream 1 (after moving it to OPEN — a reset on an
	// idle stream is itself a PROTOCOL_ERROR, §5.1); a WINDOW_UPDATE on it
	// is then ignored, not an error, and the window is untouched
	h2_stream_event_wrapper(s, H2_EVENT_RECV_HEADERS, &carry);
	ASSERT_EQ("stream opened", H2_STREAM_OPEN, s->state);
	hdr.type = H2_FRAME_RST_STREAM;
	hdr.length = 4;
	hdr.stream_id = 1;
	uint8_t rst[4] = { 0, 0, 0, H2_ERR_CANCEL };
	ASSERT_EQ("RST_STREAM ok", 0, h2_dispatch_wrapper(&hdr, rst, &conn, &carry));
	ASSERT_EQ("stream closed", H2_STREAM_CLOSED, s->state);

	hdr.type = H2_FRAME_WINDOW_UPDATE;
	hdr.stream_id = 1;
	uint8_t wu[4] = { 0, 0, 0x00, 0x64 };
	ASSERT_EQ("closed stream update ignored", 0,
	          h2_dispatch_wrapper(&hdr, wu, &conn, &carry));
	ASSERT_EQ("stream window unchanged", H2_DEF_INITIAL_WINDOW_SIZE + 500,
	          s->window);
}

// ── 11.3 — transmission resumes after WINDOW_UPDATE ────────────────
// End-to-end over a socketpair: both windows start at 0, so h2_write_body
// blocks reading frames; the client's two WINDOW_UPDATEs (stream, then
// connection) open the windows and the blocked writer completes the body.
static void test_h2_flow_resume(void) {
	TEST_SUITE("11.3 transmission resumes after WINDOW_UPDATE");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side: grant credit, then read the body ──
		close(sv[0]);
		uint8_t out[64];
		long out_len = 0;
		// stream 1 WINDOW_UPDATE +2000
		put_wire_header(out + out_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 1);
		out_len += H2_WIRE_HEADER_LEN;
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x07; out[out_len++] = 0xd0;
		// connection WINDOW_UPDATE +2000
		put_wire_header(out + out_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		out[out_len++] = 0x00; out[out_len++] = 0x00;
		out[out_len++] = 0x07; out[out_len++] = 0xd0;
		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(1);
			w += r;
		}
		// the resumed body — one DATA frame, END_STREAM, stream 1
		uint8_t in[64];
		long n = 0;
		while (n < H2_WIRE_HEADER_LEN) {
			long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
			if (r <= 0) _exit(2);
			n += r;
		}
		long len = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
		if (len != 20) _exit(3);
		if (in[3] != H2_FRAME_DATA) _exit(4);
		if ((in[4] & H2_FLAG_END_STREAM) == 0) _exit(5);
		if ((((uint32_t)in[5] << 24) | ((uint32_t)in[6] << 16) |
		     ((uint32_t)in[7] << 8) | in[8]) != 1) _exit(6);
		n = 0;
		while (n < len) {
			long r = read(sv[1], in + n, (unsigned long)(len - n));
			if (r <= 0) _exit(7);
			n += r;
		}
		if (memcmp(in, "flow control resumes", 20) != 0) _exit(8);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: both windows at 0, then write the body ──
	close(sv[1]);
	reset_conn(h2_conn_addr());
	reset_streams();
	int64_t carry;
	h2_stream_t *s = h2_stream_create_wrapper(1, h2_conn_addr(), &carry);
	ASSERT_EQ("stream created", 0, carry);
	h2_conn_addr()->window = 0;
	s->window = 0;

	static const char body[] = "flow control resumes";
	response_t resp = {
		.status = 200,
		.content_type = 0,
		.content_type_len = 0,
		.content_length = LITLEN(body),
		.body = body,
		.body_length = LITLEN(body),
		.range_start = -1,
		.range_end = -1,
	};

	carry = h2_write_body_wrapper(sv[0], &resp, 1);
	ASSERT_EQ("writer resumed and completed", 0, carry);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client received the resumed body", 0, exit_code);
	// 2000 granted − 20 sent on each window
	ASSERT_EQ("connection window after send", 2000 - LITLEN(body),
	          h2_conn_addr()->window);
	ASSERT_EQ("stream window after send", 2000 - LITLEN(body), s->window);
}

// ── 11.4 — a file larger than the initial flow-control window ──────
// GET /big.bin (70000 bytes, stub embedded in stubs_response.S) through
// the full connection loop. The client drains the response and tops up
// both windows with WINDOW_UPDATEs as its credit runs low; the assertion
// is that the whole file arrives — no deadlock, no truncated body.
static void test_h2_flow_large_file(void) {
	TEST_SUITE("11.4 large file (> initial window) — complete, no deadlock");

	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  ✗ socketpair() failed\n");
		exit(2);
	}

	int pid = fork();
	if (pid == 0) {
		// ── client side ──
		close(sv[0]);
		uint8_t out[256], in[70000 + 32];
		long out_len = 0;
		// preface + client SETTINGS + HEADERS (GET /big.bin)
		memcpy(out + out_len, H2_PREFACE, H2_PREFACE_LEN);
		out_len += H2_PREFACE_LEN;
		put_wire_header(out + out_len, 0, H2_FRAME_SETTINGS, 0, 0);
		out_len += H2_WIRE_HEADER_LEN;
		// HPACK block: :method GET (0x82) + literal :path /big.bin
		static const uint8_t block[] = {
			0x82, 0x04, 0x08, '/', 'b', 'i', 'g', '.', 'b', 'i', 'n',
		};
		put_wire_header(out + out_len, (uint32_t)sizeof(block), H2_FRAME_HEADERS,
		                H2_FLAG_END_STREAM | H2_FLAG_END_HEADERS, 1);
		out_len += H2_WIRE_HEADER_LEN;
		memcpy(out + out_len, block, sizeof(block));
		out_len += (long)sizeof(block);
		long w = 0;
		while (w < out_len) {
			long r = write(sv[1], out + w, (unsigned long)(out_len - w));
			if (r <= 0) _exit(1);
			w += r;
		}

		// the server's opening SETTINGS (15 bytes) — read, then skip
		long n = 0;
		while (n < 15) {
			long r = read(sv[1], in + n, (unsigned long)(15 - n));
			if (r <= 0) _exit(2);
			n += r;
		}
		// the HEADERS frame header, then skip its HPACK payload
		n = 0;
		while (n < H2_WIRE_HEADER_LEN) {
			long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
			if (r <= 0) _exit(3);
			n += r;
		}
		if (in[3] != H2_FRAME_HEADERS) _exit(4);
		long hlen = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
		n = 0;
		while (n < hlen) {
			long r = read(sv[1], in, (unsigned long)hlen);
			if (r <= 0) _exit(5);
			n += r;
		}

		// DATA loop: top the windows up before they run dry, then read
		long stream_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long conn_credit = H2_DEF_INITIAL_WINDOW_SIZE;
		long total = 0, len = 0;
		int done = 0, nframes = 0;
		while (!done) {
			while (stream_credit < H2_DEFAULT_MAX_FRAME_SIZE ||
			       conn_credit < H2_DEFAULT_MAX_FRAME_SIZE) {
				// replenish both windows by the initial amount
				uint8_t wu[26];
				long wu_len = 0;
				put_wire_header(wu + wu_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 1);
				wu_len += H2_WIRE_HEADER_LEN;
				wu[wu_len++] = 0x00; wu[wu_len++] = 0x00;
				wu[wu_len++] = 0xff; wu[wu_len++] = 0xff;
				put_wire_header(wu + wu_len, 4, H2_FRAME_WINDOW_UPDATE, 0, 0);
				wu_len += H2_WIRE_HEADER_LEN;
				wu[wu_len++] = 0x00; wu[wu_len++] = 0x00;
				wu[wu_len++] = 0xff; wu[wu_len++] = 0xff;
				long w2 = 0;
				while (w2 < wu_len) {
					long r = write(sv[1], wu + w2, (unsigned long)(wu_len - w2));
					if (r <= 0) _exit(6);
					w2 += r;
				}
				stream_credit += H2_DEF_INITIAL_WINDOW_SIZE;
				conn_credit += H2_DEF_INITIAL_WINDOW_SIZE;
			}
			n = 0;
			while (n < H2_WIRE_HEADER_LEN) {
				long r = read(sv[1], in + n, (unsigned long)(H2_WIRE_HEADER_LEN - n));
				if (r <= 0) _exit(7);
				n += r;
			}
			len = ((long)in[0] << 16) | ((long)in[1] << 8) | in[2];
			if (in[3] != H2_FRAME_DATA) _exit(8);
			// save the flags byte — the payload read below overwrites in[0..]
			int end_stream = in[4] & H2_FLAG_END_STREAM;
			nframes++;
			stream_credit -= len;
			conn_credit -= len;
			n = 0;
			while (n < len) {
				long r = read(sv[1], in + n, (unsigned long)(len - n));
				if (r <= 0) _exit(9);
				n += r;
			}
			total += len;
			if (end_stream) done = 1;
		}
		if (total != 70000) _exit(10);
		// spot-check the body content ('a' everywhere)
		if (in[0] != 'a' || in[len - 1] != 'a') _exit(11);
		close(sv[1]);
		_exit(0);
	}

	// ── server side: the full connection loop over the socketpair ──
	close(sv[1]);
	uint8_t in[512];
	h2_connection_loop_wrapper(sv[0], in, 0);
	close(sv[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	int exit_code = (status >> 8) & 0xff;
	ASSERT_EQ("client received all 70000 bytes (no deadlock)", 0, exit_code);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_connection_mode_default();
	test_h2_preface_constant();
	test_h2_preface_verify();
	test_h2_preface_partial_reads();
	test_h2_preface_rejected();
	test_h2_send_settings();
	test_h2_conn_defaults();
	test_h2_parse_frame_header();
	test_h2_validate_frame();
	test_h2_dispatch_frame();
	test_h2_settings_store();
	test_h2_settings_validation();
	test_h2_settings_ack();
	test_h2_malformed_rejected();
	// Stage 6 — stream management
	test_h2_stream_table();
	test_h2_validate_stream_id();
	test_h2_headers_stream_creation();
	test_h2_stream_transitions();
	test_h2_end_stream_flags();
	test_h2_rst_stream();
	// Stage 7 — minimal HPACK
	test_h2_hpack_static_table();
	test_h2_hpack_int();
	test_h2_hpack_string();
	test_h2_huffman();
	test_h2_hpack_indexed();
	test_h2_hpack_literal();
	test_h2_hpack_dynamic_disabled();
	test_h2_hpack_block();
	test_h2_hpack_block_curl();
	// Stage 8 — HEADERS → HPACK → the common request
	test_h2_headers_hpack();
	test_h2_pseudo_request();
	test_h2_pseudo_validate();
	test_h2_request_equivalence();
	// Stage 9 — the first working HTTP/2 GET
	test_h2_probe();
	test_h2_write_headers();
	test_h2_write_headers_gzip();
	test_h2_write_headers_404();
	test_h2_write_body();
	test_h2_write_body_chunked();
	test_h2_process_request();
	test_h2_connection_loop();
	// Stage 10 — complete static responses
	test_h2_head_no_body();
	test_h2_head_ignores_range();
	test_h2_404();
	test_h2_403();
	test_h2_mime();
	test_h2_range();
	test_h2_range_open();
	test_h2_range_suffix();
	test_h2_range_unsatisfiable();
	test_h2_range_invalid();
	test_h2_parse_range();
	test_h2_resolve_range();
	test_h2_write_headers_206();
	// Stage 11 — DATA flow control
	test_h2_flow_conn_window();
	test_h2_flow_stream_window();
	test_h2_flow_window_update();
	test_h2_flow_resume();
	test_h2_flow_large_file();
	test_summary();
	return 0;
}
