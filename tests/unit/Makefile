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

# ── test executables ────────────────────────────────────────────────
TEST_UTIL  := $(OBJ_DIR)/test_util
TEST_PARSE := $(OBJ_DIR)/test_parse
TEST_FILE  := $(OBJ_DIR)/test_file
TEST_REQUEST := $(OBJ_DIR)/test_request
TEST_RESPONSE := $(OBJ_DIR)/test_response
TEST_HTTP2 := $(OBJ_DIR)/test_http2

TESTS := $(TEST_UTIL) $(TEST_PARSE) $(TEST_FILE) $(TEST_REQUEST) $(TEST_RESPONSE) $(TEST_HTTP2)

all: test

test: $(TESTS)
	@failures=0; \
	logs=""; \
	passed=0; \
	for t in $(TESTS); do \
		out=$$(./$$t 2>&1); rc=$$?; \
		if [ $$rc -eq 0 ]; then \
			passed=$$((passed + 1)); \
		else \
			failures=$$((failures + 1)); \
			logs="$${logs}$$(printf "\n━━━ %s ━━━\n%s\n" "$$(basename $$t)" "$$out")"; \
		fi; \
	done; \
	if [ $$failures -eq 0 ]; then \
		printf "  \033[0;32m✓\033[0m all unit tests passed (%d suites)\n" "$$passed"; \
	else \
		printf '%s\n' "$$logs"; \
		echo ""; \
		echo "❌ $$failures test suite(s) failed."; \
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

# ── test executable link rules ─────────────────────────────────────

# test_util: only needs util.o (pure functions).
# The C test code uses inline asm wrappers to call asm functions.
$(TEST_UTIL): test_util.c $(util_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(LDFLAGS) -o $@

# test_parse: needs util.o + parse.o + data.o + file.o + stubs.o.
# parse_header_end uses parse.S data. get_header_field calls streqn_i.
# parse_range calls get_header_field + atoi_n. Error paths go to
# reply_status (stubs.o). Cross-references to decode_url etc in
# parse_request require file.o.
$(TEST_PARSE): test_parse.c $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_file: needs file.o + util.o + stubs.o.
# check_path_traversal/check_path_safety are self-contained.
# get_filetype calls streqn_i and strlen from util.S.
# lookup_embedded references embedded_files/embedded_count from stubs.o.
$(TEST_FILE): test_file.c $(util_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_request: needs parse.o + data.o + file.o + util.o + stubs.o.
# parse_request parses into the `request` struct (data.o), calls
# parse_path/get_header_field (parse.o) and decode_url/check_path_*
# (file.o), with error paths going to reply_status (stubs.o).
$(TEST_REQUEST): test_request.c $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(parse_o) $(data_o) $(file_o) $(stubs_o) $(LDFLAGS) -o $@

# test_response: Stage 2 response abstraction. Links the REAL header.o
# (http1_write_response, reply_status) and get.o (create_response) so
# the response struct is exercised through the real encoder, plus
# parse.o/file.o for parse_range/get_filetype. stubs_response.o replaces
# stubs.o (no duplicate reply_status/build_header stubs) and adds a
# child_end stub.
$(TEST_RESPONSE): test_response.c $(util_o) $(data_o) $(parse_o) $(file_o) $(header_o) $(get_o) $(stubs_resp_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(util_o) $(data_o) $(parse_o) $(file_o) $(header_o) $(get_o) $(stubs_resp_o) $(LDFLAGS) -o $@

# test_http2: Stages 4-6 frame engine + connection preface + stream
# management (http2.S). h2_verify_preface reads the client preface and
# stores connection_mode (data.S), h2_send_settings tail-calls write_all
# (util.S) to emit the opening SETTINGS frame, and the stream functions
# operate on the global h2_streams table.
$(TEST_HTTP2): test_http2.c $(http2_o) $(data_o) $(util_o) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(http2_o) $(data_o) $(util_o) $(LDFLAGS) -o $@

# ── clean ───────────────────────────────────────────────────────────

clean:
	rm -rf $(OBJ_DIR)
