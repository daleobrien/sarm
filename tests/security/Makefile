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
CFLAGS  := -g -O1 -arch arm64 -Wall -Wextra -Wno-unused-function
LDFLAGS := -arch arm64

# -O1, not -O2: these tests deliberately dereference out-of-bounds
# pointers, which is undefined behaviour by the letter of the standard
# even though it is exactly what the guard page is there to catch. The
# probes are all `volatile`, but a lower optimisation level keeps the
# generated code close to what was written, so a passing test means the
# access really happened.
#
# -Wno-unused-function because crypto_ref.h and bounds_common.h are
# header libraries of static functions: each suite uses the subset it
# needs, and every suite would otherwise warn about the rest.

OBJ_DIR := _obj

HELPERS := guard_pages.h crypto_ref.h ref_selfcheck.h refbn.h bounds_common.h diff_common.h overflow_common.h fuzz_common.h
COMMON_OBJS := $(OBJ_DIR)/guard_pages.o

# ── assembly under test ─────────────────────────────────────────────
# The bounds suites (Step 3) call the real .S files, assembled here
# rather than reused from tests/unit/_obj so the two suites cannot get
# out of step with each other. Same pattern rule shape as
# tests/unit/Makefile.
ASFLAGS := -g -O2 -arch arm64 -I ../../src

rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

crypto_srcs := $(call rwildcard,../../src/crypto,*.S)
crypto_objs := $(patsubst ../../src/crypto/%.S,$(OBJ_DIR)/crypto_%.o,$(crypto_srcs))

# The HPACK overflow suite (Step 5) drives the real decoders, which
# reach the dynamic table and memcpy — the hpack module plus the one
# util routine it calls, and nothing else. Deliberately not the whole
# h2 stack: the point of a standalone harness is that a failure names
# HPACK rather than "the server".
hpack_srcs := $(call rwildcard,../../src/hpack,*.S)
hpack_objs := $(patsubst ../../src/hpack/%.S,$(OBJ_DIR)/hpack_%.o,$(hpack_srcs))
util_memcpy_obj := $(OBJ_DIR)/util_memcpy.o

# The TLS record fuzzer (Step 6) drives the record layer against
# generated input. Named file by file rather than by wildcard: the
# application_read/application_write specializations reach into
# tls_state and the sequence counters, which would drag the whole TLS
# module into a harness whose whole point is that a failure names
# `tls_record_parse` and not "the server".
tls_record_srcs := parse.S decrypt.S encrypt.S nonce.S write.S read_record.S
tls_record_objs := $(patsubst %.S,$(OBJ_DIR)/tls_record_%.o,$(tls_record_srcs))
transport_raw_obj := $(OBJ_DIR)/transport_raw_read.o

# The handshake fuzzer (Step 7) drives tls_server_handshake, whose
# whole job is to sequence every other TLS module against a live
# socket — so unlike the record fuzzer above it links src/tls,
# src/crypto and src/transport whole. Naming files individually would
# only be a way of pretending the driver has fewer dependencies than
# it has. src/data.S (the HTTP buffers) is still not linked: the TLS
# module deliberately keeps its own scratch buffers.
tls_all_srcs   := $(call rwildcard,../../src/tls,*.S)
tls_all_objs   := $(patsubst ../../src/tls/%.S,$(OBJ_DIR)/tlsmod_%.o,$(tls_all_srcs))
transport_srcs := $(call rwildcard,../../src/transport,*.S)
transport_objs := $(patsubst ../../src/transport/%.S,$(OBJ_DIR)/transport_%.o,$(transport_srcs))

TEST_GUARD_PAGES  := $(OBJ_DIR)/test_guard_pages
BOUNDS_TESTS      := $(patsubst test_bounds_%.c,$(OBJ_DIR)/test_bounds_%,$(wildcard test_bounds_*.c))
DIFF_TESTS        := $(patsubst test_diff_%.c,$(OBJ_DIR)/test_diff_%,$(wildcard test_diff_*.c))
OVERFLOW_TESTS    := $(patsubst test_overflow_%.c,$(OBJ_DIR)/test_overflow_%,$(wildcard test_overflow_*.c))
FUZZ_TESTS        := $(patsubst test_fuzz_%.c,$(OBJ_DIR)/test_fuzz_%,$(wildcard test_fuzz_*.c))

TESTS := $(TEST_GUARD_PAGES) $(BOUNDS_TESTS) $(DIFF_TESTS) $(OVERFLOW_TESTS) $(FUZZ_TESTS)

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

$(OBJ_DIR)/guard_pages.o: guard_pages.c guard_pages.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

.SECONDARY: $(crypto_objs)

$(OBJ_DIR)/crypto_%.o: ../../src/crypto/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

.SECONDARY: $(hpack_objs) $(util_memcpy_obj)

$(OBJ_DIR)/hpack_%.o: ../../src/hpack/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/util_%.o: ../../src/util/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

.SECONDARY: $(tls_record_objs) $(transport_raw_obj)

$(OBJ_DIR)/tls_record_%.o: ../../src/tls/record/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/transport_%.o: ../../src/transport/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

.SECONDARY: $(tls_all_objs)

$(OBJ_DIR)/tlsmod_%.o: ../../src/tls/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

# Every suite includes tests/unit/test_harness.h, so a change there must
# rebuild them, exactly as in tests/unit/Makefile.
HARNESS := ../unit/test_harness.h

$(OBJ_DIR)/test_guard_pages: test_guard_pages.c guard_pages.h $(HARNESS) $(COMMON_OBJS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(COMMON_OBJS) $(LDFLAGS) -o $@

# The bounds suites link the crypto module in full: one .S file per
# function means every suite drags in its module's neighbours anyway
# (hkdf calls hmac calls sha256), and linking the lot keeps the rule
# to one line.
$(OBJ_DIR)/test_bounds_%: test_bounds_%.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(COMMON_OBJS) $(crypto_objs) $(LDFLAGS) -o $@

# The differential suites (Step 4) run millions of vectors through the
# same objects, so they are built at -O2: the reference is the slow
# side, and nothing here deliberately reads out of bounds the way the
# bounds suites do, so the reason for -O1 does not apply.
$(OBJ_DIR)/test_diff_%: test_diff_%.c $(HELPERS) $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -O2 $< $(crypto_objs) $(LDFLAGS) -o $@

# The overflow suites (Step 5) feed a hostile corpus to the real
# parsers with a guard page immediately after the input, so a read that
# leaves the block faults instead of returning plausible bytes. Built
# at the default -O1 for the same reason the bounds suites are.
$(OBJ_DIR)/test_overflow_hpack: test_overflow_hpack.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) $(hpack_objs) $(util_memcpy_obj) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(COMMON_OBJS) $(hpack_objs) $(util_memcpy_obj) $(LDFLAGS) -o $@

$(OBJ_DIR)/test_overflow_crypto: test_overflow_crypto.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(COMMON_OBJS) $(crypto_objs) $(LDFLAGS) -o $@

# The fuzz suites (Step 6) run millions of generated cases through the
# real routines. Built at -O2: the harness itself is the hot loop, and
# unlike the bounds suites nothing here dereferences a pointer the
# compiler could reasonably decide is undefined — the out-of-bounds
# accesses under test happen inside the assembly, where no optimiser
# is involved.
$(OBJ_DIR)/test_fuzz_tls_record: test_fuzz_tls_record.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) $(tls_record_objs) $(crypto_objs) $(util_memcpy_obj) $(transport_raw_obj) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -O2 $< $(COMMON_OBJS) $(tls_record_objs) $(crypto_objs) $(util_memcpy_obj) $(transport_raw_obj) $(LDFLAGS) -o $@

# The handshake fuzzer additionally plays a real client against the
# server, so it links the same objects from both sides — there is only
# one implementation of X25519 and of the key schedule in this tree,
# and the ServerHello parse on the client side is written by hand
# precisely so the two are not the same code.
$(OBJ_DIR)/test_fuzz_tls_handshake: test_fuzz_tls_handshake.c $(HELPERS) $(HARNESS) $(COMMON_OBJS) $(tls_all_objs) $(crypto_objs) $(transport_objs) $(util_memcpy_obj) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -O2 $< $(COMMON_OBJS) $(tls_all_objs) $(crypto_objs) $(transport_objs) $(util_memcpy_obj) $(LDFLAGS) -o $@

clean:
	rm -rf $(OBJ_DIR)
