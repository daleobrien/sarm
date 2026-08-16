// Unit tests for tls_read_record from src/tls/record/read_record.S
// (RFC 8446 §5.1, PLAN.MD Phase 20)
//
// tls_read_record is the network-level counterpart to tls_record_parse:
// it reads a record's 5-byte header off a real fd, then its fragment,
// then delegates to tls_record_parse. Exercised over a real
// socketpair() so the "read exactly N bytes, looping over short reads"
// behaviour (inherited from transport_read) is actually tested, not
// just assumed.

#include "test_harness.h"

extern long tls_read_record(long fd, void *buf, unsigned long buf_cap)
    __asm__("tls_read_record");
extern unsigned long transport_mode __asm__("transport_mode");

#define TLS_RECORD_HANDSHAKE 22
#define TLS_RECORD_APPLICATION_DATA 23
#define TLS_RECORD_ERR_SHORT  1
#define TLS_RECORD_ERR_LENGTH 4

extern int socketpair(int domain, int type, int protocol, int sv[2]);
extern long write(int fd, const void *buf, unsigned long len);
extern int close(int fd);

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

// tls_read_record(fd=x0, buf=x1, buf_cap=x2) -> x0=type,x1=frag,x2=fraglen,
// x3=total on success (carry clear); x0=error code on failure (carry set).
struct rr_result {
	unsigned long type, fraglen, total;
	const unsigned char *frag;
};
static long read_record_c(long fd, void *buf, unsigned long buf_cap,
                          struct rr_result *r, long *carry) {
	long err, v0, v1, v2, v3, c;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %6\n"
		"mov x1, %7\n"
		"mov x2, %8\n"
		"bl tls_read_record\n"
		"cset %0, cs\n"
		"mov %1, x0\n"
		"mov %2, x1\n"
		"mov %3, x2\n"
		"mov %4, x3\n"
		: "=r"(c), "=r"(v0), "=r"(v1), "=r"(v2), "=r"(v3), "=r"(err)
		: "r"(fd), "r"(buf), "r"(buf_cap)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x19", "x20", "x21", "x22", "x30", "cc", "memory");
	*carry = c;
	if (r) {
		r->type = (unsigned long)v0;
		r->frag = (const unsigned char *)v1;
		r->fraglen = (unsigned long)v2;
		r->total = (unsigned long)v3;
	}
	return c ? v0 : 0;
}

static void test_read_record_basic(void) {
	TEST_SUITE("tls_read_record — full record over a real socket");
	transport_mode = 0;

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

	// a 5-byte header (type=handshake, version 0x0303, len=10) + 10-byte
	// fragment, written in two separate write() calls to force
	// tls_read_record's underlying transport_read to actually loop
	// across short reads rather than getting everything in one shot.
	unsigned char header[5] = {22, 0x03, 0x03, 0x00, 0x0a};
	unsigned char fragment[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	write(sv[1], header, 5);
	write(sv[1], fragment, 10);

	unsigned char buf[64];
	struct rr_result r;
	long carry = 0;
	read_record_c(sv[0], buf, sizeof(buf), &r, &carry);
	ASSERT_EQ("carry clear", 0, (int)carry);
	ASSERT_EQ("type == handshake", TLS_RECORD_HANDSHAKE, (int)r.type);
	ASSERT_EQ("fraglen == 10", 10, (int)r.fraglen);
	ASSERT_EQ("total == 15", 15, (int)r.total);
	ASSERT_TRUE("fragment bytes match", memcmp(r.frag, fragment, 10) == 0);

	close(sv[0]);
	close(sv[1]);
}

static void test_read_record_eof(void) {
	TEST_SUITE("tls_read_record — closed connection before a full header");
	transport_mode = 0;

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	unsigned char partial[3] = {23, 0x03, 0x03};
	write(sv[1], partial, 3);
	close(sv[1]);                      // EOF before the header completes

	unsigned char buf[64];
	struct rr_result r;
	long carry = 0;
	long err = read_record_c(sv[0], buf, sizeof(buf), &r, &carry);
	ASSERT_EQ("carry set", 1, (int)carry);
	ASSERT_EQ("TLS_RECORD_ERR_SHORT", TLS_RECORD_ERR_SHORT, (int)err);

	close(sv[0]);
}

static void test_read_record_too_large_for_buffer(void) {
	TEST_SUITE("tls_read_record — record larger than the destination buffer");
	transport_mode = 0;

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	// header claims a 100-byte fragment; destination buffer only has
	// room for 5 + 10.
	unsigned char header[5] = {23, 0x03, 0x03, 0x00, 100};
	write(sv[1], header, 5);

	unsigned char buf[15];
	struct rr_result r;
	long carry = 0;
	long err = read_record_c(sv[0], buf, sizeof(buf), &r, &carry);
	ASSERT_EQ("carry set", 1, (int)carry);
	ASSERT_EQ("TLS_RECORD_ERR_LENGTH", TLS_RECORD_ERR_LENGTH, (int)err);

	close(sv[0]);
	close(sv[1]);
}

static void test_read_record_application_data(void) {
	TEST_SUITE("tls_read_record — application_data type roundtrip");
	transport_mode = 0;

	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	unsigned char msg[6] = {23, 0x03, 0x03, 0x00, 0x01, 0xaa};
	write(sv[1], msg, sizeof(msg));

	unsigned char buf[64];
	struct rr_result r;
	long carry = 0;
	read_record_c(sv[0], buf, sizeof(buf), &r, &carry);
	ASSERT_EQ("carry clear", 0, (int)carry);
	ASSERT_EQ("type == application_data", TLS_RECORD_APPLICATION_DATA,
	          (int)r.type);
	ASSERT_EQ("fraglen == 1", 1, (int)r.fraglen);
	ASSERT_EQ("fragment byte matches", 0xaa, r.frag[0]);

	close(sv[0]);
	close(sv[1]);
}

int main(void) {
	test_read_record_basic();
	test_read_record_eof();
	test_read_record_too_large_for_buffer();
	test_read_record_application_data();
	test_summary();
	return 0;
}
