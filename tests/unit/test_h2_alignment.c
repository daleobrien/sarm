// test_h2_alignment.c — verify data symbols are 16-byte aligned.
//
// Every string, buffer and table in the source is aligned to a 16-byte
// boundary (`.align 4` in the .data/.bss declarations, buffer sizes
// rounded up to a 16-byte multiple). 16-byte alignment guarantees that
// the 8-byte word loads used by streqn/h2_verify_preface never straddle
// a 16-byte boundary, keeps 16-byte memcpy chunks cache-line friendly,
// and leaves room for 128-bit NEON loads later.
//
// This suite checks the data symbols that are exported from the modules
// the test binaries link. Internal (non-global) strings are aligned by
// the same convention but are not addressable from C, so they can't be
// asserted here.
//
// The assembly defines symbols WITHOUT the C leading underscore (this
// is a pure-assembly codebase), so a C `extern` declaration can never
// resolve them. Addresses are taken via inline asm instead, exactly like
// the *_addr helpers in test_h2_common.h.
//
// Built by the same rule as the other test_h2_* suites (links H2_LIBS).

#include "test_harness.h"

// Take the address of an assembly symbol by name (see note above).
#define ASM_SYM_ADDR(sym) ({ \
	uintptr_t _addr; \
	asm volatile( \
		"adrp x0, " #sym "@PAGE\n\t" \
		"add  x0, x0, " #sym "@PAGEOFF\n\t" \
		"mov  %0, x0\n\t" \
		: "=r"(_addr) \
		: \
		: "x0"); \
	_addr; \
})

// assert an assembly symbol is aligned to `align` bytes
#define ASSERT_ASM_ALIGNED(label, sym, align) \
	ASSERT_EQ(label, 0, (int64_t)ASM_SYM_ADDR(sym) % (align))

static void test_data_alignment(void) {
	TEST_SUITE("16-byte alignment — shared state (data.S)");

	ASSERT_ASM_ALIGNED("file_des", file_des, 16);
	ASSERT_ASM_ALIGNED("connection_mode", connection_mode, 16);
	ASSERT_ASM_ALIGNED("h2_preface", h2_preface, 16);
	ASSERT_ASM_ALIGNED("buf", buf, 16);
	ASSERT_ASM_ALIGNED("request", request, 16);
	ASSERT_ASM_ALIGNED("response", response, 16);
	ASSERT_ASM_ALIGNED("request_ctx", request_ctx, 16);
	ASSERT_ASM_ALIGNED("header_len", header_len, 16);
	ASSERT_ASM_ALIGNED("clientfd", clientfd, 16);
	ASSERT_ASM_ALIGNED("request_id", request_id, 16);
	ASSERT_ASM_ALIGNED("resource_type", resource_type, 16);
	ASSERT_ASM_ALIGNED("embedded_content", embedded_content, 16);
	ASSERT_ASM_ALIGNED("embedded_ct", embedded_ct, 16);
	ASSERT_ASM_ALIGNED("embedded_ct_len", embedded_ct_len, 16);
	ASSERT_ASM_ALIGNED("embedded_gzip", embedded_gzip, 16);
	ASSERT_ASM_ALIGNED("embedded_etag", embedded_etag, 16);
	ASSERT_ASM_ALIGNED("embedded_etag_len", embedded_etag_len, 16);
	ASSERT_ASM_ALIGNED("req_start", req_start, 16);
	ASSERT_ASM_ALIGNED("req_end", req_end, 16);
	ASSERT_ASM_ALIGNED("response_code", response_code, 16);
}

static void test_parse_alignment(void) {
	TEST_SUITE("16-byte alignment — parse module (parse/data.S)");

	ASSERT_ASM_ALIGNED("www_prefix", www_prefix, 16);
	ASSERT_ASM_ALIGNED("default_file", default_file, 16);
	ASSERT_ASM_ALIGNED("filename_buf", filename_buf, 16);
	ASSERT_ASM_ALIGNED("query_buf", query_buf, 16);
	ASSERT_ASM_ALIGNED("authority_buf", authority_buf, 16);
}

static void test_http1_alignment(void) {
	TEST_SUITE("16-byte alignment — http1 module");

	ASSERT_ASM_ALIGNED("header_buf", header_buf, 16);
	ASSERT_ASM_ALIGNED("header_500", header_500, 16);
}

static void test_h2_alignment(void) {
	TEST_SUITE("16-byte alignment — h2/hpack modules");

	ASSERT_ASM_ALIGNED("h2_conn", h2_conn, 16);
	ASSERT_ASM_ALIGNED("h2_frame_header", h2_frame_header, 16);
	ASSERT_ASM_ALIGNED("h2_streams", h2_streams, 16);
	ASSERT_ASM_ALIGNED("h2_frame_buf", h2_frame_buf, 16);
	ASSERT_ASM_ALIGNED("h2_settings_frame", h2_settings_frame, 16);
	ASSERT_ASM_ALIGNED("h2_hpack_fields", h2_hpack_fields, 16);
	ASSERT_ASM_ALIGNED("h2_hpack_str_buf", h2_hpack_str_buf, 16);
	ASSERT_ASM_ALIGNED("h2_hpack_str_off", h2_hpack_str_off, 16);
	ASSERT_ASM_ALIGNED("h2_huffman_table", h2_huffman_table, 16);
	ASSERT_ASM_ALIGNED("h2_huffman_len_start", h2_huffman_len_start, 16);
}

int main(void) {
	test_data_alignment();
	test_parse_alignment();
	test_http1_alignment();
	test_h2_alignment();
	test_summary();
	return 0;
}
