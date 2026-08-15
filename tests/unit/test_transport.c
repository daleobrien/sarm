// Unit tests for src/transport/ — the transport mode seam (PLAN.MD §1.3)
//
// transport_read(fd=x0, buf=x1, len=x2) and transport_write(fd=x0,
// buf=x1, len=x2) dispatch on the runtime `transport_mode` global
// (src/transport/data.S), which is initialised from config.S's
// TRANSPORT_MODE compile-time default:
//
//   TRANSPORT_PLAIN (0) — the raw socket path (existing behaviour)
//   TRANSPORT_TLS   (1) — not implemented yet; fails closed with
//                         ENOTSUP (carry set) so a TLS-mode connection
//                         can never read or write plaintext
//
// Both functions keep the h2 seam contract: carry clear + x0 = 0 on
// success (transport_write returns the byte count), carry set + errno on
// failure. ENOTSUP is 95 on Linux, 45 on macOS (defs.S).

#include "test_harness.h"

// ── asm symbols ─────────────────────────────────────────────────────
// Apple ARM64 prefixes C names with '_' but the asm symbols don't have
// one, so pin the asm names explicitly (same pattern as test_atoi_n.c).
extern long transport_read(long fd, void *buf, unsigned long len)
    __asm__("transport_read");
extern long transport_write(long fd, const void *buf, unsigned long len)
    __asm__("transport_write");
extern unsigned long transport_mode __asm__("transport_mode");

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
// b.cs fail`. Clobbers match the transport_read/write doc headers
// (caller-saved registers only; x19-x21/x25-x26 are callee-saved and
// restored by the callee).

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
		: "x0", "x1", "x2", "x3", "x4", "x9", "memory"
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
		: "x0", "x1", "x2", "x9", "memory"
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

// ── tests: TLS mode fails closed ────────────────────────────────────
// TRANSPORT_TLS has no implementation yet, so both sides must fail with
// ENOTSUP + carry set WITHOUT touching the socket: no plaintext is ever
// read or written on a TLS-mode connection. The probe sequence below is
// arranged so every failure mode fails cleanly (no blocking read):
//   1. PLAIN write "hello"           → 5 bytes pending on sv[1]
//   2. TLS read  sv[1] 5 → ENOTSUP   → must consume nothing
//   3. TLS write sv[0] "world" → ENOTSUP → must write nothing
//   4. PLAIN write sv[0] "!"         → 6 bytes pending in the good case
//   5. PLAIN read sv[1] 5 → "hello", then 1 → "!"
// If step 2 consumed bytes the first read gets "ello..." (or blocks), if
// step 3 wrote bytes the second read gets "w" instead of "!".

static void test_tls_fail_closed(void) {
	TEST_SUITE("transport TLS mode fails closed");
	int sv[2];
	long carry;
	char buf[8];
	static const char hello[] = "hello";

	ASSERT_EQ("socketpair", 0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	ASSERT_EQ("write hello (PLAIN)", 5,
	          transport_write_c(sv[0], hello, 5, &carry));
	ASSERT_EQ("write hello carry clear", 0, carry);

	transport_mode = TRANSPORT_TLS;

	ASSERT_EQ("TLS read → ENOTSUP", ENOTSUP,
	          transport_read_c(sv[1], buf, 5, &carry));
	ASSERT_EQ("TLS read carry set", 1, carry);
	ASSERT_EQ("TLS write → ENOTSUP", ENOTSUP,
	          transport_write_c(sv[0], hello, 5, &carry));
	ASSERT_EQ("TLS write carry set", 1, carry);

	// Back to PLAIN — the dispatch is per-call, not latched.
	transport_mode = TRANSPORT_PLAIN;
	ASSERT_EQ("PLAIN write marker", 1,
	          transport_write_c(sv[0], "!", 1, &carry));
	ASSERT_EQ("marker carry clear", 0, carry);

	ASSERT_EQ("read 5 → success", 0,
	          transport_read_c(sv[1], buf, 5, &carry));
	ASSERT_EQ("read 5 carry clear", 0, carry);
	ASSERT_STR_EQ("pending data untouched (TLS read consumed nothing)",
	              hello, buf, 5);
	ASSERT_EQ("read 1 → success", 0,
	          transport_read_c(sv[1], buf, 1, &carry));
	ASSERT_EQ("read 1 carry clear", 0, carry);
	ASSERT_STR_EQ("marker follows hello (TLS write wrote nothing)", "!", buf, 1);

	close(sv[0]);
	close(sv[1]);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_default_mode();
	test_plain_roundtrip();
	test_tls_fail_closed();
	test_summary();
	return 0;
}
