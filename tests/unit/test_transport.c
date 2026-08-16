// Unit tests for src/transport/ — the transport mode seam (PLAN.MD §1.3)
//
// transport_read(fd=x0, buf=x1, len=x2) and transport_write(fd=x0,
// buf=x1, len=x2) dispatch on the runtime `transport_mode` global
// (src/transport/data.S), which is initialised from config.S's
// TRANSPORT_MODE compile-time default:
//
//   TRANSPORT_PLAIN (0) — the raw socket path (existing behaviour)
//   TRANSPORT_TLS   (1) — seals/opens application_data records via
//                         tls_app_data_write/tls_app_data_read
//                         (PLAN.MD Phase 20), chunking/staging so
//                         every call still gets exactly the bytes it
//                         asked for regardless of record boundaries
//
// Both functions keep the h2 seam contract: carry clear + x0 = 0 on
// success (transport_write returns the byte count), carry set + errno on
// failure.

#include "test_harness.h"

// ── asm symbols ─────────────────────────────────────────────────────
// Apple ARM64 prefixes C names with '_' but the asm symbols don't have
// one, so pin the asm names explicitly (same pattern as test_atoi_n.c).
extern long transport_read(long fd, void *buf, unsigned long len)
    __asm__("transport_read");
extern long transport_write(long fd, const void *buf, unsigned long len)
    __asm__("transport_write");
extern unsigned long transport_mode __asm__("transport_mode");

// ── TLS-mode plumbing: app keys/seq/staging state it reads/writes ───
extern unsigned char tls_client_app_key[16] __asm__("tls_client_app_key");
extern unsigned char tls_client_app_iv[12] __asm__("tls_client_app_iv");
extern unsigned char tls_server_app_key[16] __asm__("tls_server_app_key");
extern unsigned char tls_server_app_iv[12] __asm__("tls_server_app_iv");
extern unsigned long tls_client_seq __asm__("tls_client_seq");
extern unsigned long tls_server_seq __asm__("tls_server_seq");
extern unsigned long tls_read_stage_len __asm__("tls_read_stage_len");
extern unsigned long tls_read_stage_pos __asm__("tls_read_stage_pos");

// ── constants mirrored from config.S / defs.S ───────────────────────
#define TRANSPORT_PLAIN 0
#define TRANSPORT_TLS   1
#ifdef __linux__
#define ENOTSUP 95
#else
#define ENOTSUP 45
#endif

// ── libc functions, declared manually (harness style) ───────────────
extern int socketpair(int domain, int type, int protocol, int sv[2]);
extern int close(int fd);

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif

// ── inline asm wrappers ─────────────────────────────────────────────
// Call the asm transport function and capture the carry flag (1 = error,
// 0 = ok), mirroring how the h2 frame loop uses it: `bl transport_read;
// b.cs fail`. Clobbers cover the union of both dispatch paths' own
// documented clobber lists (transport_read.S/transport_write.S,
// PLAN.MD Phase 20): the PLAIN path only touches a handful of
// caller-saved registers, but the TLS path calls into the record layer
// and AEAD, which reach much further (x0-x12, x19-x24, the vector
// registers used by AES-GCM/SHA-256).

static inline long transport_read_c(long fd, void *buf, unsigned long len,
                                    long *carry) {
	long result, c;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"mov x2, %4\n"
		"bl transport_read\n"
		"cset %1, cs\n"
		"mov %0, x0\n"
		: "=r"(result), "=r"(c)
		: "r"(fd), "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24",
		  "x30", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		  "v16", "v17", "v18", "v19", "v20", "v21", "cc", "memory"
	);
	*carry = c;
	return result;
}

static inline long transport_write_c(long fd, const void *buf,
                                     unsigned long len, long *carry) {
	long result, c;
	asm volatile(
		"cmp xzr, xzr\n"
		"mov x0, %2\n"
		"mov x1, %3\n"
		"mov x2, %4\n"
		"bl transport_write\n"
		"cset %1, cs\n"
		"mov %0, x0\n"
		: "=r"(result), "=r"(c)
		: "r"(fd), "r"(buf), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
		  "x10", "x11", "x12", "x19", "x20", "x21", "x22", "x23", "x24",
		  "x30", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
		  "v16", "v17", "v18", "v19", "v20", "v21", "cc", "memory"
	);
	*carry = c;
	return result;
}

// ── tests: default mode ─────────────────────────────────────────────
// transport_mode starts as config.S's TRANSPORT_MODE, which is
// TRANSPORT_PLAIN — plain TCP → HTTP/2 stays the default (PLAN.MD §1.3).

static void test_default_mode(void) {
	TEST_SUITE("transport default mode");
	ASSERT_EQ("transport_mode starts as TRANSPORT_PLAIN",
	          TRANSPORT_PLAIN, transport_mode);
}

// ── tests: PLAIN roundtrip through a real socket ────────────────────
// With the default mode the transport functions must behave exactly as
// before §1.3: write-all and read-exactly over a real fd, carry clear,
// byte-for-byte payloads, and len-0 as an immediate no-op.

static void test_plain_roundtrip(void) {
	TEST_SUITE("transport PLAIN roundtrip");
	int sv[2];
	long carry;
	static char data[4096];
	char buf[4096];
	int size;

	for (int i = 0; i < 4096; i++)
		data[i] = (char)(i * 31 + 7);

	ASSERT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

	// len 0 is an immediate success on both sides (no syscall loop).
	ASSERT_EQ("write 0 bytes → 0", 0, transport_write_c(sv[0], data, 0, &carry));
	ASSERT_EQ("write 0 bytes carry clear", 0, carry);
	ASSERT_EQ("read 0 bytes → 0", 0, transport_read_c(sv[1], buf, 0, &carry));
	ASSERT_EQ("read 0 bytes carry clear", 0, carry);

	// 1, 5, 21, 85, 341, 1365, 4096 — small to large roundtrips.
	for (size = 1; size <= 4096; size = size * 4 + 1) {
		ASSERT_EQ("write full payload", size,
		          transport_write_c(sv[0], data, size, &carry));
		ASSERT_EQ("write carry clear", 0, carry);
		ASSERT_EQ("read success → 0", 0,
		          transport_read_c(sv[1], buf, size, &carry));
		ASSERT_EQ("read carry clear", 0, carry);
		ASSERT_STR_EQ("payload byte-for-byte", data, buf, size);
	}

	close(sv[0]);
	close(sv[1]);
}

// ── tests: TLS mode round-trips through real application-data records ──
// transport_write's TLS branch always seals under the *server*
// application key (tls_server_app_key/iv), and transport_read's always
// opens under the *client* one (tls_app_data_write/read, PLAN.MD Phase
// 19, have fixed directions) — so this same-process test points both
// at the same key/IV, which makes what transport_write seals exactly
// what transport_read can open. That's a legitimate shortcut here: the
// AEAD itself is already proven correct per-direction by
// tests/unit/test_tls_application/; this test's only job is the NEW
// plumbing transport_read/write add on top — chunking, and staging a
// decrypted record's leftover plaintext across as many transport_read
// calls as it takes to drain, over a real socketpair().
static void tls_mode_reset_keys(void) {
	static const unsigned char key[16] = {
	    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	static const unsigned char iv[12] = {
	    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
	};
	memcpy(tls_client_app_key, key, 16);
	memcpy(tls_server_app_key, key, 16);
	memcpy(tls_client_app_iv, iv, 12);
	memcpy(tls_server_app_iv, iv, 12);
	tls_client_seq = 0;
	tls_server_seq = 0;
	tls_read_stage_len = 0;
	tls_read_stage_pos = 0;
}

static void test_tls_mode_roundtrip(void) {
	TEST_SUITE("transport TLS mode — seal/open over a real socket");
	tls_mode_reset_keys();

	int sv[2];
	long carry;
	static const char msg[] = "hello, TLS transport";  // 20 bytes, no NUL

	ASSERT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	transport_mode = TRANSPORT_TLS;

	ASSERT_EQ("write all 20 bytes", 20,
	          transport_write_c(sv[0], msg, 20, &carry));
	ASSERT_EQ("write carry clear", 0, carry);

	// drain the one resulting record across two reads of different
	// sizes, exercising the stage buffer's partial-drain path
	char buf[32];
	ASSERT_EQ("read first 12 bytes", 0,
	          transport_read_c(sv[1], buf, 12, &carry));
	ASSERT_EQ("read 12 carry clear", 0, carry);
	ASSERT_STR_EQ("first 12 bytes match", "hello, TLS t", buf, 12);

	ASSERT_EQ("read remaining 8 bytes", 0,
	          transport_read_c(sv[1], buf, 8, &carry));
	ASSERT_EQ("read 8 carry clear", 0, carry);
	ASSERT_STR_EQ("remaining 8 bytes match", "ransport", buf, 8);

	close(sv[0]);
	close(sv[1]);
}

static void test_tls_mode_multiple_records(void) {
	TEST_SUITE("transport TLS mode — a read spanning two records");
	tls_mode_reset_keys();

	int sv[2];
	long carry;

	ASSERT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	transport_mode = TRANSPORT_TLS;

	ASSERT_EQ("write first chunk", 5, transport_write_c(sv[0], "abcde", 5, &carry));
	ASSERT_EQ("write first carry clear", 0, carry);
	ASSERT_EQ("write second chunk", 5, transport_write_c(sv[0], "fghij", 5, &carry));
	ASSERT_EQ("write second carry clear", 0, carry);

	// two separate records now sit on the wire; one 10-byte read must
	// pull and decrypt both to satisfy the request
	char buf[16];
	ASSERT_EQ("read across both records", 0,
	          transport_read_c(sv[1], buf, 10, &carry));
	ASSERT_EQ("read carry clear", 0, carry);
	ASSERT_STR_EQ("bytes match across the record boundary", "abcdefghij", buf, 10);

	close(sv[0]);
	close(sv[1]);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_default_mode();
	test_plain_roundtrip();
	test_tls_mode_roundtrip();
	test_tls_mode_multiple_records();
	test_summary();
	return 0;
}
