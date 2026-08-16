// Differential-test driver protocol for buffer-copy assembly functions.
//
// The function under test is `copy_bytes(dst, src, len)`; each concrete
// driver (.c file) supplies it -- either libc (reference) or the asm
// function (candidate) via an inline-asm wrapper. This header provides
// main() and the stdin/stdout protocol:
//
//   Input, one case per line:
//     LEN SRCOFF DSTOFF HEX          normal case
//     GS LEN SRCOFF DSTOFF HEX       source ends at a guard page
//     GD LEN SRCOFF DSTOFF HEX       destination ends at a guard page
//
//   LEN     bytes to copy (0..65535; guard cases limited to 4080)
//   SRCOFF  offset added to the source pointer (0..15)
//   DSTOFF  offset added to the destination pointer (0..15)
//   HEX     hex-encoded LEN payload bytes
//
//   Output, one line per case:
//     OK LEN HEX
//
//   OK is always 1 if the process survives; HEX is the LEN bytes read
//   back from dst+DSTOFF. Guard cases place the buffer so the copy ends
//   exactly at a PROT_NONE page: a read/write overrun of even one byte
//   segfaults, and the harness sees a missing line.
//
// The candidate driver is rebuilt by `make` after every candidate
// install, so it always tests the exact source under evaluation.

#ifndef sarm_DIFF_DRIVER_H
#define sarm_DIFF_DRIVER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Provided by the concrete driver (memcpy_ref.c / memcpy_asm.c).
void copy_bytes(void *dst, const void *src, int64_t len);

#define MAX_CASE_LEN 65535
#define MAX_GUARD_LEN 4080

static int hex_val(int c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t hex_decode(const char *s, uint8_t *out) {
	size_t n = 0;
	while (s[0] && s[1]) {
		int hi = hex_val(s[0]), lo = hex_val(s[1]);
		if (hi < 0 || lo < 0)
			break;
		out[n++] = (uint8_t)((hi << 4) | lo);
		s += 2;
	}
	return n;
}

static void print_hex(const uint8_t *p, size_t n) {
	static const char *digits = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		putchar(digits[p[i] >> 4]);
		putchar(digits[p[i] & 15]);
	}
	putchar('\n');
}

int main(void) {
	long page = sysconf(_SC_PAGESIZE);
	if (page < 4096)
		page = 4096;

	// Guard region: two accessible pages, then a PROT_NONE page.
	uint8_t *guard = mmap(NULL, (size_t)3 * page, PROT_READ | PROT_WRITE,
	                      MAP_PRIVATE | MAP_ANON, -1, 0);
	if (guard == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		return 2;
	}
	mprotect(guard + 2 * page, page, PROT_NONE);
	uint8_t *guard_start = guard + 2 * page; // first byte of the guard page

	size_t arena = 1u << 20;
	uint8_t *src_arena = malloc(arena);
	uint8_t *dst_arena = malloc(arena);
	if (!src_arena || !dst_arena) {
		fprintf(stderr, "malloc failed\n");
		return 2;
	}

	char line[16384]; // room for 4080-byte payload hex + overhead
	while (fgets(line, sizeof line, stdin)) {
		char *tokens[8];
		int nt = 0;
		char *save = NULL;
		for (char *t = strtok_r(line, " \t\r\n", &save);
		     t && nt < 8; t = strtok_r(NULL, " \t\r\n", &save)) {
			tokens[nt++] = t;
		}
		if (nt < 4)
			continue;

		int guarded = 0; // 0 none, 1 source, 2 destination
		int len, soff, doff;
		const char *hex;
		if (strcmp(tokens[0], "GS") == 0) {
			guarded = 1;
			len = atoi(tokens[1]);
			soff = atoi(tokens[2]);
			doff = atoi(tokens[3]);
			hex = tokens[4];
		} else if (strcmp(tokens[0], "GD") == 0) {
			guarded = 2;
			len = atoi(tokens[1]);
			soff = atoi(tokens[2]);
			doff = atoi(tokens[3]);
			hex = tokens[4];
		} else {
			len = atoi(tokens[0]);
			soff = atoi(tokens[1]);
			doff = atoi(tokens[2]);
			hex = tokens[3];
		}
		if (len < 0 || len > (guarded ? MAX_GUARD_LEN : MAX_CASE_LEN))
			continue;

		static uint8_t *payload;
		static size_t payload_cap;
		if ((size_t)len > payload_cap) {
			payload_cap = (size_t)len + 16;
			uint8_t *np = realloc(payload, payload_cap);
			if (!np)
				return 2;
			payload = np;
		}
		size_t got = hex_decode(hex, payload);
		if (got != (size_t)len)
			continue;

		uint8_t *src, *dst;
		if (guarded == 1) {
			src = guard_start - soff - len;   // reads end at the guard
			dst = dst_arena + doff;
		} else if (guarded == 2) {
			src = src_arena + soff;
			dst = guard_start - doff - len;   // writes end at the guard
		} else {
			src = src_arena + soff;
			dst = dst_arena + doff;
		}
		memcpy(src, payload, (size_t)len);
		if (guarded != 1)
			memset(dst, 0xA5, (size_t)len);

		copy_bytes(dst, src, len);

		printf("1 %d ", len);
		print_hex(dst, (size_t)len);
	}

	free(src_arena);
	free(dst_arena);
	munmap(guard, (size_t)3 * page);
	return 0;
}

#endif
