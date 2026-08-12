// ymawky unit test harness — minimal C assertion macros
// This file is part of ymawky.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only
//
// NOTE: Does NOT include <stdlib.h> or <string.h> to avoid name
// collisions with assembly functions (atoi, strlen, memcpy).

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <stdint.h>

// ── libc functions we need, declared manually ──────────────────────
// Avoid <stdlib.h> (declares atoi) and <string.h> (declares strlen, memcpy).

void exit(int status);
int memcmp(const void *s1, const void *s2, unsigned long n);
void *memcpy(void *dst, const void *src, unsigned long n);
void *memmove(void *dst, const void *src, unsigned long n);
void *memset(void *s, int c, unsigned long n);

// ── test runner state ──────────────────────────────────────────────

static int _tests_passed = 0;
static int _tests_failed = 0;
static const char *_current_suite = "";

#define TEST_SUITE(name) \
	do { _current_suite = name; printf("\n── %s ──\n", name); } while(0)

// ── assertion macros ───────────────────────────────────────────────

#define _FAIL(fmt, ...) do { \
	printf("  ✗ %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	_tests_failed++; \
} while(0)

#define _PASS(msg) do { \
	printf("  ✓ %s\n", msg); \
	_tests_passed++; \
} while(0)

// assert two 64-bit integers are equal
#define ASSERT_EQ(label, expected, actual) do { \
	int64_t _e = (int64_t)(expected); \
	int64_t _a = (int64_t)(actual); \
	if (_e == _a) \
		_PASS(label); \
	else \
		_FAIL("%s — expected %lld, got %lld", label, (long long)_e, (long long)_a); \
} while(0)

// assert two unsigned 64-bit integers are equal (hex display)
#define ASSERT_EQ_HEX(label, expected, actual) do { \
	uint64_t _e = (uint64_t)(expected); \
	uint64_t _a = (uint64_t)(actual); \
	if (_e == _a) \
		_PASS(label); \
	else \
		_FAIL("%s — expected 0x%llx, got 0x%llx", label, \
		      (unsigned long long)_e, (unsigned long long)_a); \
} while(0)

// assert that a string matches expected
#define ASSERT_STR_EQ(label, expected_str, actual_str, len) do { \
	const char *_x = (const char *)(expected_str); \
	const char *_y = (const char *)(actual_str); \
	if ((len) == 0 || memcmp(_x, _y, (unsigned long)(len)) == 0) \
		_PASS(label); \
	else \
		_FAIL("%s", label); \
} while(0)

// assert condition is true
#define ASSERT_TRUE(label, cond) do { \
	if (cond) \
		_PASS(label); \
	else \
		_FAIL("%s — expected true", label); \
} while(0)

// assert condition is false
#define ASSERT_FALSE(label, cond) do { \
	if (!(cond)) \
		_PASS(label); \
	else \
		_FAIL("%s — expected false", label); \
} while(0)

// assert pointer is non-null
#define ASSERT_NOT_NULL(label, ptr) do { \
	if ((ptr) != NULL) \
		_PASS(label); \
	else \
		_FAIL("%s — expected non-NULL pointer", label); \
} while(0)

// ── test summary ───────────────────────────────────────────────────

static void test_summary(void) {
	printf("\n═══════════════════════════════════════════\n");
	printf("  Passed:  %d\n", _tests_passed);
	printf("  Failed:  %d\n", _tests_failed);
	printf("═══════════════════════════════════════════\n");
	if (_tests_failed > 0) {
		printf("\nSome tests failed!\n");
		exit(1);
	} else {
		printf("\nAll tests passed.\n");
		exit(0);
	}
}

#endif // TEST_HARNESS_H
