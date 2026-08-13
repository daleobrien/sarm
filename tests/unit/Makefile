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
# Each test executable links only the .S files it actually needs.
# NOTE: util.S defines a "strlen" with non-standard ABI (x1 arg).
# Test C code must avoid libc strlen() when util.o is linked.

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
# Compiled once, reused across test executables.
util_o     := $(OBJ_DIR)/util.o
data_o     := $(OBJ_DIR)/data.o
parse_o    := $(OBJ_DIR)/parse.o
file_o     := $(OBJ_DIR)/file.o
header_o   := $(OBJ_DIR)/header.o
get_o      := $(OBJ_DIR)/get.o
stubs_o    := $(OBJ_DIR)/stubs.o
stubs_resp_o := $(OBJ_DIR)/stubs_response.o
http2_o    := $(OBJ_DIR)/http2.o
hpack_o    := $(OBJ_DIR)/h2_hpack.o

# ── test executables ────────────────────────────────────────────────
TEST_UTIL  := $(OBJ_DIR)/test_util
TEST_PARSE := $(OBJ_DIR)/test_parse
TEST_FILE  := $(OBJ_DIR)/test_file
TEST_REQUEST := $(OBJ_DIR)/test_request
TEST_RESPONSE := $(OBJ_DIR)/test_response
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

TESTS := $(TEST_UTIL) $(TEST_PARSE) $(TEST_FILE) $(TEST_REQUEST) $(TEST_RESPONSE) \
	$(TEST_H2_FRAMES) $(TEST_H2_PREFACE) $(TEST_H2_STREAMS) $(TEST_H2_HPACK) \
	$(TEST_H2_REQUEST) $(TEST_H2_RESPONSE) $(TEST_H2_STATIC) $(TEST_H2_FLOW) \
	$(TEST_H2_MUX) $(TEST_H2_CONN_MGMT)

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

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(util_o): ../../src/util.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(data_o): ../../src/data.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(parse_o): ../../src/parse.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(file_o): ../../src/file.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

# header.o and get.o are only linked by test_response; the other suites
# use the function stubs in stubs.o instead.
$(header_o): ../../src/header.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(get_o): ../../src/get.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(stubs_o): stubs.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(stubs_resp_o): stubs_response.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(http2_o): ../../src/http2.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(hpack_o): ../../src/h2_hpack.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

# ── test executable link rules ─────────────────────────────────────

# Every suite includes test_harness.h, so it must be a prerequisite of
# each link rule to force a rebuild when the harness changes.
HARNESS := test_harness.h

# test_util: only needs util.o (pure functions).
# The C test code uses inline asm wrappers to call asm functions.
$(TEST_UTIL): test_util.c $(HARNESS) $(util_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(LDFLAGS) -o $@

# test_parse: needs util.o + parse.o + data.o + file.o + stubs.o.
# parse_header_end uses parse.S data. get_header_field calls streqn_i.
# parse_range calls get_header_field + atoi_n. Error paths go to
# reply_status (stubs.o). Cross-references to decode_url etc in
# parse_request require file.o.
$(TEST_PARSE): test_parse.c $(HARNESS) $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_file: needs file.o + util.o + stubs.o.
# check_path_traversal/check_path_safety are self-contained.
# get_filetype calls streqn_i and strlen from util.S.
# lookup_embedded references embedded_files/embedded_count from stubs.o.
$(TEST_FILE): test_file.c $(HARNESS) $(util_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_request: needs parse.o + data.o + file.o + util.o + stubs.o.
# parse_request parses into the `request` struct (data.o), calls
# parse_path/get_header_field (parse.o) and decode_url/check_path_*
# (file.o), with error paths going to reply_status (stubs.o).
$(TEST_REQUEST): test_request.c $(HARNESS) $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_response: Stage 2 response abstraction. Links the REAL header.o
# (http1_write_response, reply_status) and get.o (create_response) so
# the response struct is exercised through the real encoder, plus
# parse.o/file.o for parse_range/get_filetype. stubs_response.o replaces
# stubs.o (no duplicate reply_status/build_header stubs) and adds a
# child_end stub.
$(TEST_RESPONSE): test_response.c $(HARNESS) $(util_o) $(data_o) $(parse_o) $(file_o) $(header_o) $(get_o) $(stubs_resp_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(data_o) $(parse_o) $(file_o) $(header_o) $(get_o) $(stubs_resp_o) $(LDFLAGS) -o $@

# HTTP/2 suites: one .c file per stage group, all linking the same
# object set — the full Stage 4-14 stack (http2.o + h2_hpack.o + the
# shared request/file/response helpers) plus stubs_response.o (the
# embedded table, child_end). Every test_h2_*.c includes
# test_h2_common.h, which must trigger a rebuild when it changes.
H2_LIBS := $(http2_o) $(hpack_o) $(data_o) $(util_o) $(parse_o) $(file_o) $(header_o) $(get_o) $(stubs_resp_o)

$(OBJ_DIR)/test_h2_%: test_h2_%.c $(HARNESS) test_h2_common.h $(H2_LIBS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(H2_LIBS) $(LDFLAGS) -o $@

# ── clean ───────────────────────────────────────────────────────────

clean:
	rm -rf $(OBJ_DIR)
