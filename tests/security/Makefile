# Security test Makefile for sarm (docs/SECURITY.md)
#
# Run from the project root:
#   make -C tests/security          — build and run all security tests
#   make -C tests/security test     — same
#   make -C tests/security build    — compile only, don't run
#   make -C tests/security clean    — remove build artifacts
#
# These tests do not link the server. They test the *test infrastructure*
# the later steps depend on (Step 2, this file's guard-page helper), and
# — from Step 3 onward — individual assembly routines against guarded
# buffers. Each suite is its own executable with its own main(), the
# same shape as tests/unit, and reports a machine-readable
# "TOTAL_TESTS passed failed" line that the loop below aggregates.
#
# Unlike the production binary, test code may use libc freely: the
# standalone, no-libc constraint is a property of `sarm`, not of the
# things that measure it (docs/SECURITY.md §2).

.PHONY: all test build clean

CC      := cc
CFLAGS  := -g -O1 -arch arm64 -Wall -Wextra
LDFLAGS := -arch arm64

# -O1, not -O2: these tests deliberately dereference out-of-bounds
# pointers, which is undefined behaviour by the letter of the standard
# even though it is exactly what the guard page is there to catch. The
# probes are all `volatile`, but a lower optimisation level keeps the
# generated code close to what was written, so a passing test means the
# access really happened.

OBJ_DIR := _obj

HELPERS := guard_pages.h
COMMON_OBJS := $(OBJ_DIR)/guard_pages.o

TEST_GUARD_PAGES := $(OBJ_DIR)/test_guard_pages

TESTS := $(TEST_GUARD_PAGES)

all: test

test: $(TESTS)
	@failures=0; \
	logs=""; \
	total_passed=0; \
	total_failed=0; \
	for t in $(TESTS); do \
		out=$$(./$$t 2>&1); rc=$$?; \
		name=$$(basename $$t); \
		suite=$${name#test_}; \
		t_passed=$$(printf '%s\n' "$$out" | sed -n 's/.*TOTAL_TESTS \([0-9][0-9]*\) \([0-9][0-9]*\).*/\1/p'); \
		t_failed=$$(printf '%s\n' "$$out" | sed -n 's/.*TOTAL_TESTS \([0-9][0-9]*\) \([0-9][0-9]*\).*/\2/p'); \
		[ -n "$$t_passed" ] || t_passed=0; \
		[ -n "$$t_failed" ] || t_failed=0; \
		total_passed=$$((total_passed + t_passed)); \
		total_failed=$$((total_failed + t_failed)); \
		if [ $$rc -eq 0 ]; then \
			printf "── %-37s ... (%3d tests) \033[0;32m✓\033[0m\n" "$${suite}" "$$((t_passed + t_failed))"; \
		else \
			failures=$$((failures + 1)); \
			printf "── security (%-33s ... (%3d tests) \033[0;31m✗\033[0m\n" "$${suite})" "$$((t_passed + t_failed))"; \
			logs="$${logs}$$(printf "\n━━━ %s ━━━\n%s\n" "$$name" "$$out")"; \
		fi; \
	done; \
	if [ $$failures -eq 0 ]; then \
		echo ""; \
		echo "✅ All security tests passed ($$total_passed tests)."; \
		exit 0; \
	else \
		printf '%s\n' "$$logs"; \
		echo ""; \
		echo "❌ $$failures security suite(s) failed ($$total_passed passed, $$total_failed failed)."; \
		exit 1; \
	fi

build: $(TESTS)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/guard_pages.o: guard_pages.c $(HELPERS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Every suite includes tests/unit/test_harness.h, so a change there must
# rebuild them, exactly as in tests/unit/Makefile.
HARNESS := ../unit/test_harness.h

$(OBJ_DIR)/test_%: test_%.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(COMMON_OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf $(OBJ_DIR)
