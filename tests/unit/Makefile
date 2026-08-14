# Unit test Makefile for ymawky assembly functions
# Builds and runs unit tests for individual .S functions without
# needing the full server binary.
#
# Run from the project root:
#   make -C tests/unit          — build and run all tests
#   make -C tests/unit test     — same
#   make -C tests/unit build    — compile only, don't run
#   make -C tests/unit clean    — remove build artifacts
#
# Each test executable links only the modules it actually needs. Source
# files live in per-module folders under src/ (one function per file);
# the object lists below expand each folder with a wildcard.
# NOTE: the util module defines a "strlen" with non-standard ABI (x1 arg).
# Test C code must avoid libc strlen() when util is linked.

.PHONY: all test build clean

# ── toolchain ───────────────────────────────────────────────────────
AS      := cc
CC      := cc
ASFLAGS := -g -O2 -arch arm64 -I ../../src
CFLAGS  := -g -O2 -arch arm64 -I .
LDFLAGS := -arch arm64

# ── build directory ─────────────────────────────────────────────────
OBJ_DIR := _obj

# ── assembly object files ──────────────────────────────────────────
# One object per source file; each module's objects are gathered with a
# wildcard so adding a new function file needs no Makefile edit.
util_objs    := $(patsubst ../../src/util/%.S,$(OBJ_DIR)/util_%.o,$(wildcard ../../src/util/*.S))
parse_objs   := $(patsubst ../../src/parse/%.S,$(OBJ_DIR)/parse_%.o,$(wildcard ../../src/parse/*.S))
file_objs    := $(patsubst ../../src/file/%.S,$(OBJ_DIR)/file_%.o,$(wildcard ../../src/file/*.S))
http1_objs   := $(patsubst ../../src/http1/%.S,$(OBJ_DIR)/http1_%.o,$(wildcard ../../src/http1/*.S))
h2_objs      := $(patsubst ../../src/h2/%.S,$(OBJ_DIR)/h2_%.o,$(wildcard ../../src/h2/*.S))
hpack_objs   := $(patsubst ../../src/hpack/%.S,$(OBJ_DIR)/hpack_%.o,$(wildcard ../../src/hpack/*.S))
crypto_objs  := $(patsubst ../../src/crypto/%.S,$(OBJ_DIR)/crypto_%.o,$(wildcard ../../src/crypto/*.S))
data_objs    := $(OBJ_DIR)/data.o
stubs_objs   := $(OBJ_DIR)/stubs.o
stubs_resp_objs := $(OBJ_DIR)/stubs_response.o

# ── test executables ────────────────────────────────────────────────
TEST_PARSE := $(OBJ_DIR)/test_parse
TEST_FILE  := $(OBJ_DIR)/test_file
TEST_REQUEST := $(OBJ_DIR)/test_request
TEST_RESPONSE := $(OBJ_DIR)/test_response
TEST_STR_LEN := $(OBJ_DIR)/test_strlen
TEST_STREQN := $(OBJ_DIR)/test_streqn
TEST_STREQN_I := $(OBJ_DIR)/test_streqn_i
TEST_MEMCPY := $(OBJ_DIR)/test_memcpy
TEST_ITOA := $(OBJ_DIR)/test_itoa
TEST_FNV1A_64 := $(OBJ_DIR)/test_fnv1a_64
TEST_ATOI := $(OBJ_DIR)/test_atoi
TEST_ATOI_N := $(OBJ_DIR)/test_atoi_n
TEST_SHA256 := $(OBJ_DIR)/test_sha256
TEST_AES128 := $(OBJ_DIR)/test_aes128
# HTTP/2 suites — one per stage group; all share test_h2_common.h.
TEST_H2_FRAMES    := $(OBJ_DIR)/test_h2_frames
TEST_H2_PREFACE   := $(OBJ_DIR)/test_h2_preface
TEST_H2_STREAMS   := $(OBJ_DIR)/test_h2_streams
TEST_H2_HPACK     := $(OBJ_DIR)/test_h2_hpack
TEST_H2_REQUEST   := $(OBJ_DIR)/test_h2_request
TEST_H2_RESPONSE  := $(OBJ_DIR)/test_h2_response
TEST_H2_STATIC    := $(OBJ_DIR)/test_h2_static
TEST_H2_FLOW      := $(OBJ_DIR)/test_h2_flow
TEST_H2_MUX       := $(OBJ_DIR)/test_h2_mux
TEST_H2_CONN_MGMT := $(OBJ_DIR)/test_h2_conn_mgmt
TEST_H2_ALIGNMENT := $(OBJ_DIR)/test_h2_alignment

TESTS := $(TEST_PARSE) $(TEST_FILE) $(TEST_REQUEST) $(TEST_RESPONSE) \
	$(TEST_STR_LEN) $(TEST_STREQN) $(TEST_STREQN_I) $(TEST_MEMCPY) $(TEST_ITOA) $(TEST_FNV1A_64) \
	$(TEST_ATOI) $(TEST_ATOI_N) $(TEST_SHA256) $(TEST_AES128) \
	$(TEST_H2_FRAMES) $(TEST_H2_PREFACE) $(TEST_H2_STREAMS) $(TEST_H2_HPACK) \
	$(TEST_H2_REQUEST) $(TEST_H2_RESPONSE) $(TEST_H2_STATIC) $(TEST_H2_FLOW) \
	$(TEST_H2_MUX) $(TEST_H2_CONN_MGMT) $(TEST_H2_ALIGNMENT)

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
			printf "── test (%-19s ... (%3d tests) \033[0;32m✓\033[0m\n" "$${suite})" "$$((t_passed + t_failed))"; \
		else \
			failures=$$((failures + 1)); \
			printf "── test (%-19s ... (%3d tests) \033[0;31m✗\033[0m\n" "$${suite})" "$$((t_passed + t_failed))"; \
			logs="$${logs}$$(printf "\n━━━ %s ━━━\n%s\n" "$$name" "$$out")"; \
		fi; \
	done; \
	if [ $$failures -eq 0 ]; then \
		exit 0; \
	else \
		printf '%s\n' "$$logs"; \
		echo ""; \
		echo "❌ $$failures test suite(s) failed ($$total_passed passed, $$total_failed failed)."; \
		exit 1; \
	fi

build: $(TESTS)

# ── assembly compilation rules ─────────────────────────────────────

# The per-module objects are only ever prerequisites of the test binaries,
# so GNU make treats them as intermediates and deletes them after each
# link — forcing a full recompile on every `make test`. Keep them.
.SECONDARY: $(util_objs) $(parse_objs) $(file_objs) $(http1_objs) $(h2_objs) $(hpack_objs) $(crypto_objs)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# one pattern rule per module folder — src/<module>/<file>.S compiles to
# _obj/<module>_<file>.o
$(OBJ_DIR)/util_%.o: ../../src/util/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/parse_%.o: ../../src/parse/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/file_%.o: ../../src/file/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/http1_%.o: ../../src/http1/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/h2_%.o: ../../src/h2/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/hpack_%.o: ../../src/hpack/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto_%.o: ../../src/crypto/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(data_objs): ../../src/data.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(stubs_objs): stubs.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(stubs_resp_objs): stubs_response.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

# ── test executable link rules ─────────────────────────────────────

# Every suite includes test_harness.h, so it must be a prerequisite of
# each link rule to force a rebuild when the harness changes.
HARNESS := test_harness.h

# test_atoi: only needs util (pure functions).
# atoi uses the standard ABI, so the C test code calls it directly.
$(TEST_ATOI): test_atoi.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_strlen: only needs util (pure functions).
# The C test code calls asm strlen via an inline asm wrapper.
$(TEST_STR_LEN): test_strlen.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_streqn: only needs util (pure functions).
# streqn uses the standard ABI, so the C test code calls it directly.
$(TEST_STREQN): test_streqn.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_streqn_i: only needs util (pure functions).
# streqn_i uses the standard ABI, so the C test code calls it directly.
$(TEST_STREQN_I): test_streqn_i.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_memcpy: only needs util (pure functions).
# memcpy uses the standard ABI, so the C test code calls it via an
# inline asm wrapper (mirrors test_strlen.c).
$(TEST_MEMCPY): test_memcpy.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_itoa: only needs util (pure functions).
# itoa returns two values (ptr=x0, len=x1), so the C test code calls it
# via an inline asm wrapper.
$(TEST_ITOA): test_itoa.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_fnv1a_64: only needs util (pure functions).
# fnv1a_64 uses the standard ABI, so the C test code calls it directly.
$(TEST_FNV1A_64): test_fnv1a_64.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_atoi_n: only needs util (pure functions).
# atoi_n returns its value in x0 but signals errors through the carry
# flag, so the C test code calls it via an inline asm wrapper.
$(TEST_ATOI_N): test_atoi_n.c $(HARNESS) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(LDFLAGS) -o $@

# test_sha256: only needs crypto (pure function, standard ABI).
# sha256(state=x0, data=x1, nblocks=x2) is called directly.
$(TEST_SHA256): test_sha256.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_aes128: only needs crypto (pure function, standard ABI).
# aes128_encrypt(pt=x0, rk=x1, ct=x2) is called directly.
$(TEST_AES128): test_aes128.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_parse: needs util + parse + data + file + stubs.
# parse_header_end uses parse data. get_header_field calls streqn_i.
# parse_range calls get_header_field + atoi_n. Error paths go to
# reply_status (stubs.o). Cross-references to decode_url etc in
# parse_request require file.o.
$(TEST_PARSE): test_parse.c $(HARNESS) $(util_objs) $(parse_objs) $(data_objs) $(file_objs) $(stubs_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(parse_objs) $(data_objs) $(file_objs) $(stubs_objs) $(LDFLAGS) -o $@

# test_file: needs file + util + stubs.
# check_path_traversal/check_path_safety are self-contained.
# get_filetype calls streqn_i and strlen from util.
# lookup_embedded references embedded_files/embedded_count from stubs.o.
$(TEST_FILE): test_file.c $(HARNESS) $(util_objs) $(file_objs) $(stubs_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(file_objs) $(stubs_objs) $(LDFLAGS) -o $@

# test_request: needs parse + data + file + util + stubs.
# parse_request parses into the `request` struct (data.o), calls
# parse_path/get_header_field (parse) and decode_url/check_path_*
# (file), with error paths going to reply_status (stubs.o).
$(TEST_REQUEST): test_request.c $(HARNESS) $(util_objs) $(parse_objs) $(data_objs) $(file_objs) $(stubs_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(parse_objs) $(data_objs) $(file_objs) $(stubs_objs) $(LDFLAGS) -o $@

# test_response: Stage 2 response abstraction. Links the REAL http1
# module (find_http_code, http1_write_response, reply_status,
# create_response, get_setup, get, head) so the response struct is
# exercised through the real encoder, plus parse/file for
# parse_range/get_filetype. stubs_response.o replaces stubs.o (no
# duplicate reply_status/build_header stubs) and adds a child_end stub.
$(TEST_RESPONSE): test_response.c $(HARNESS) $(util_objs) $(data_objs) $(parse_objs) $(file_objs) $(http1_objs) $(stubs_resp_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_objs) $(data_objs) $(parse_objs) $(file_objs) $(http1_objs) $(stubs_resp_objs) $(LDFLAGS) -o $@

# HTTP/2 suites: one .c file per stage group, all linking the same
# object set — the full Stage 4-14 stack (h2 + hpack + the shared
# request/file/response helpers) plus stubs_response.o (the embedded
# table, child_end). Every test_h2_*.c includes test_h2_common.h, which
# must trigger a rebuild when it changes.
H2_LIBS := $(h2_objs) $(hpack_objs) $(data_objs) $(util_objs) $(parse_objs) $(file_objs) $(http1_objs) $(stubs_resp_objs)

$(OBJ_DIR)/test_h2_%: test_h2_%.c $(HARNESS) test_h2_common.h $(H2_LIBS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(H2_LIBS) $(LDFLAGS) -o $@

# ── clean ───────────────────────────────────────────────────────────

clean:
	rm -rf $(OBJ_DIR)
