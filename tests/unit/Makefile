# Unit test Makefile for sarm assembly functions
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

# ── recursive wildcard ───────────────────────────────────────────
# Same as the main Makefile: find .S files in subdirectories
rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

# ── assembly object files ──────────────────────────────────────────
# One object per source file; each module's objects are gathered with a
# wildcard so adding a new function file needs no Makefile edit.
util_objs    := $(patsubst ../../src/util/%.S,$(OBJ_DIR)/util_%.o,$(wildcard ../../src/util/*.S))
parse_objs   := $(patsubst ../../src/parse/%.S,$(OBJ_DIR)/parse_%.o,$(wildcard ../../src/parse/*.S))
file_objs    := $(patsubst ../../src/file/%.S,$(OBJ_DIR)/file_%.o,$(wildcard ../../src/file/*.S))
http1_srcs   := $(call rwildcard,../../src/http1,*.S)
http1_objs   := $(patsubst ../../src/http1/%.S,$(OBJ_DIR)/http1_%.o,$(http1_srcs))
h2_srcs      := $(call rwildcard,../../src/h2,*.S)
h2_objs      := $(patsubst ../../src/h2/%.S,$(OBJ_DIR)/h2_%.o,$(h2_srcs))
hpack_objs   := $(patsubst ../../src/hpack/%.S,$(OBJ_DIR)/hpack_%.o,$(wildcard ../../src/hpack/*.S))
crypto_srcs  := $(call rwildcard,../../src/crypto,*.S)
crypto_objs  := $(patsubst ../../src/crypto/%.S,$(OBJ_DIR)/crypto_%.o,$(crypto_srcs))
transport_objs := $(patsubst ../../src/transport/%.S,$(OBJ_DIR)/transport_%.o,$(wildcard ../../src/transport/*.S))
# TLS module objects, including submodules in record/, transcript/, etc.
tls_srcs     := $(call rwildcard,../../src/tls,*.S)
tls_objs     := $(patsubst ../../src/tls/%.S,$(OBJ_DIR)/tls_%.o,$(tls_srcs))
data_objs    := $(OBJ_DIR)/data.o

# util/write_all.S now tail-calls transport_write, so any test binary that
# links the util objects must also link the transport module.
util_objs += $(transport_objs)
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
# Split test suites — one per .c file under the test directory
SHA256_TESTS := $(patsubst test_sha256/%.c,$(OBJ_DIR)/test_sha256_%,$(wildcard test_sha256/*.c))
HMAC_TESTS := $(OBJ_DIR)/test_hmac
HKDF_TESTS := $(patsubst test_hkdf/%.c,$(OBJ_DIR)/test_hkdf_%,$(wildcard test_hkdf/*.c))
AES128_TESTS := $(patsubst test_aes128/%.c,$(OBJ_DIR)/test_aes128_%,$(wildcard test_aes128/*.c))
GCM_TESTS := $(patsubst test_gcm/%.c,$(OBJ_DIR)/test_gcm_%,$(wildcard test_gcm/*.c))
X25519_TESTS := $(OBJ_DIR)/test_x25519
P256_TESTS := $(patsubst test_p256/%.c,$(OBJ_DIR)/test_p256_%,$(wildcard test_p256/*.c))
P256_SCALAR_TESTS := $(patsubst test_p256_scalar/%.c,$(OBJ_DIR)/test_p256_scalar_%,$(wildcard test_p256_scalar/*.c))
P256_POINT_TESTS := $(patsubst test_p256_point/%.c,$(OBJ_DIR)/test_p256_point_%,$(wildcard test_p256_point/*.c))
P256_ECDSA_TESTS := $(patsubst test_p256_ecdsa/%.c,$(OBJ_DIR)/test_p256_ecdsa_%,$(wildcard test_p256_ecdsa/*.c))
TEST_CRYPTO_RANDOM := $(OBJ_DIR)/test_crypto_random
TEST_TRANSPORT := $(OBJ_DIR)/test_transport
TEST_TLS := $(OBJ_DIR)/test_tls
TEST_TLS_CLIENT_HELLO := $(OBJ_DIR)/test_tls_client_hello
TEST_TLS_SERVER_HELLO := $(OBJ_DIR)/test_tls_server_hello
TEST_TLS_KEY_SCHEDULE := $(OBJ_DIR)/test_tls_key_schedule
TEST_TLS_ENCRYPTED_EXTENSIONS := $(OBJ_DIR)/test_tls_encrypted_extensions
TEST_TLS_CERTIFICATE := $(OBJ_DIR)/test_tls_certificate
# certificate_verify suites — one per src/tls/handshake/certificate_verify/*.S
# module; all share the server's real pubkey and DER
# helpers, but need no common.h (each vector table is self-contained).
TLS_CERTIFICATE_VERIFY_TESTS := $(patsubst test_tls_certificate_verify/%.c,$(OBJ_DIR)/test_tls_certificate_verify_%,$(wildcard test_tls_certificate_verify/*.c))
# finished suites — one per src/tls/handshake/finished/*.S module;
# vectors are self-contained, no common.h needed.
TLS_FINISHED_TESTS := $(patsubst test_tls_finished/%.c,$(OBJ_DIR)/test_tls_finished_%,$(wildcard test_tls_finished/*.c))
# application suites — one per Phase 19 module (src/tls/handshake/
# application_secrets.S, src/tls/record/application_write.S,
# src/tls/record/application_read.S); vectors are self-contained, no
# common.h needed.
TLS_APPLICATION_TESTS := $(patsubst test_tls_application/%.c,$(OBJ_DIR)/test_tls_application_%,$(wildcard test_tls_application/*.c))
# transcript suites — one per src/tls/transcript/*.S module; all share
# test_tls_transcript/common.h (KAT vectors, C reference SHA-256, asm wrappers).
TEST_TLS_TRANSCRIPT_INIT := $(OBJ_DIR)/test_tls_transcript_init
TEST_TLS_TRANSCRIPT_ADD  := $(OBJ_DIR)/test_tls_transcript_add
TEST_TLS_TRANSCRIPT_HASH := $(OBJ_DIR)/test_tls_transcript_hash
# record layer suites — one per src/tls/record/*.S module; all share
# test_tls_record/common.h (constants, RFC 8448 vectors, asm wrappers).
TEST_TLS_RECORD_PARSE   := $(OBJ_DIR)/test_tls_record_parse
TEST_TLS_RECORD_WRITE   := $(OBJ_DIR)/test_tls_record_write
TEST_TLS_RECORD_NONCE   := $(OBJ_DIR)/test_tls_record_nonce
TEST_TLS_RECORD_ENCRYPT := $(OBJ_DIR)/test_tls_record_encrypt
TEST_TLS_RECORD_DECRYPT := $(OBJ_DIR)/test_tls_record_decrypt
TEST_TLS_RECORD_SEQ     := $(OBJ_DIR)/test_tls_record_seq
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
	$(TEST_ATOI) $(TEST_ATOI_N) $(SHA256_TESTS) $(HMAC_TESTS) $(HKDF_TESTS) $(AES128_TESTS) $(GCM_TESTS) $(X25519_TESTS) $(P256_TESTS) $(P256_SCALAR_TESTS) $(P256_POINT_TESTS) $(P256_ECDSA_TESTS) $(TEST_CRYPTO_RANDOM) $(TEST_TRANSPORT) $(TEST_TLS) $(TEST_TLS_CLIENT_HELLO) $(TEST_TLS_SERVER_HELLO) $(TEST_TLS_KEY_SCHEDULE) $(TEST_TLS_ENCRYPTED_EXTENSIONS) $(TEST_TLS_CERTIFICATE) $(TLS_CERTIFICATE_VERIFY_TESTS) $(TLS_FINISHED_TESTS) $(TLS_APPLICATION_TESTS) \
	$(TEST_TLS_TRANSCRIPT_INIT) $(TEST_TLS_TRANSCRIPT_ADD) $(TEST_TLS_TRANSCRIPT_HASH) \
	$(TEST_TLS_RECORD_PARSE) $(TEST_TLS_RECORD_WRITE) $(TEST_TLS_RECORD_NONCE) $(TEST_TLS_RECORD_ENCRYPT) $(TEST_TLS_RECORD_DECRYPT) $(TEST_TLS_RECORD_SEQ) \
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
			printf "── test (%-25s ... (%3d tests) \033[0;32m✓\033[0m\n" "$${suite})" "$$((t_passed + t_failed))"; \
		else \
			failures=$$((failures + 1)); \
			printf "── test (%-25s ... (%3d tests) \033[0;31m✗\033[0m\n" "$${suite})" "$$((t_passed + t_failed))"; \
			logs="$${logs}$$(printf "\n━━━ %s ━━━\n%s\n" "$$name" "$$out")"; \
		fi; \
	done; \
	if [ $$failures -eq 0 ]; then \
		echo ""; \
		echo "✅ All tests passed ($$total_passed tests)."; \
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
.SECONDARY: $(util_objs) $(parse_objs) $(file_objs) $(http1_objs) $(h2_objs) $(hpack_objs) $(crypto_objs) $(transport_objs) $(tls_objs)

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
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/h2_%.o: ../../src/h2/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/hpack_%.o: ../../src/hpack/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto_%.o: ../../src/crypto/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/transport_%.o: ../../src/transport/%.S | $(OBJ_DIR)
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/tls_%.o: ../../src/tls/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/tls_record_%.o: ../../src/tls/record/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/tls_transcript_%.o: ../../src/tls/transcript/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@
	$(AS) $(ASFLAGS) -c $< -o $@

$(OBJ_DIR)/tls_handshake_%.o: ../../src/tls/handshake/%.S | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@
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

# Split test suites: one .c file per src/crypto/* function module.
# Each test suite is split into separate binaries (one per test_sha256/*.c, etc.)

# test_sha256: only needs crypto (pure function, standard ABI).
# sha256(state=x0, data=x1, nblocks=x2) is called directly.
$(OBJ_DIR)/test_sha256_%: test_sha256/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_hmac: only needs crypto (pure function, standard ABI).
# hmac_sha256(key=x0, keylen=x1, data=x2, datalen=x3, digest=x4) is
# called directly; it links sha256.o for the streaming sha256_* calls.
$(HMAC_TESTS): test_hmac.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_hkdf: only needs crypto (pure functions, standard ABI).
# hkdf_extract(salt=x0, saltlen=x1, ikm=x2, ikmlen=x3, prk=x4),
# hkdf_expand(prk=x0, prklen=x1, info=x2, infolen=x3, okm=x4, okmlen=x5)
# and hkdf_expand_label(secret=x0, label=x1, label_len=x2, context=x3,
# context_len=x4, out=x5, outlen=x6) are called directly; the module
# links sha256.o + hmac.o for the HMAC calls.
$(OBJ_DIR)/test_hkdf_%: test_hkdf/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_aes128: only needs crypto (pure functions, standard ABI).
# aes128_encrypt(pt=x0, rk=x1, ct=x2) and aes128_key_expand(key=x0,
# rk=x1) are called directly.
$(OBJ_DIR)/test_aes128_%: test_aes128/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_gcm: only needs crypto (pure functions, standard ABI); gcm.o
# references aes128_key_expand/aes128_encrypt from aes128.o.
# gf_mult_128(x=x0, y=x1, z=x2), ghash(h=x0, aad=x1, aad_len=x2, ct=x3,
# ct_len=x4, out=x5), aes_gcm_encrypt(key=x0, iv=x1, aad=x2, aad_len=x3,
# pt=x4, pt_len=x5, ct=x6, tag=x7) and aes_gcm_decrypt(key=x0, iv=x1,
# aad=x2, aad_len=x3, ct=x4, ct_len=x5, tag=x6, pt=x7, returns x0=1/0)
# are called directly.
$(OBJ_DIR)/test_gcm_%: test_gcm/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_x25519: only needs crypto (pure functions, standard ABI).
# x25519_fe_frombytes(out=x0,s=x1), x25519_fe_tobytes(out=x0,in=x1),
# x25519_fe_add(out=x0,a=x1,b=x2), x25519_fe_sub, x25519_fe_mul,
# x25519_fe_sqr(out=x0,a=x1), x25519_fe_sqr_times(out=x0,a=x1,count=x2),
# x25519_fe_scalar_product(out=x0,a=x1,scalar=x2), x25519_fe_recip(out=x0,a=x1),
# x25519_swap_conditional(x=x0,qpx=x1,iswap=x2) and
# x25519(out=x0,scalar=x1,point=x2) are called directly.
$(X25519_TESTS): test_x25519.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_p256.c drives p256_fe_* against Python-computed
# reference vectors for the real NIST P-256 prime.
$(OBJ_DIR)/test_p256_%: test_p256/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_p256_scalar.c drives p256_scalar_* (arithmetic mod n) against
# Python-computed reference vectors for the real P-256 group order.
$(OBJ_DIR)/test_p256_scalar_%: test_p256_scalar/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_p256_point.c drives p256_point_*
# against a Python transliteration of the exact same Jacobian formulas
# (dbl/add) and against cryptography-library-derived public keys
# (point_mul).
$(OBJ_DIR)/test_p256_point_%: test_p256_point/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_p256_ecdsa.c drives p256_ecdsa_sign_with_k/verify (PLAN.MD
# Phase 16.5/16.6) against vectors cross-checked with (and, for verify,
# produced directly by) the `cryptography` library.
$(OBJ_DIR)/test_p256_ecdsa_%: test_p256_ecdsa/%.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_crypto_random: only needs crypto (crypto_random_bytes is a
# pure syscall wrapper, standard ABI).
$(TEST_CRYPTO_RANDOM): test_crypto_random.c $(HARNESS) $(crypto_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(crypto_objs) $(LDFLAGS) -o $@

# test_transport: only needs transport — transport_read/transport_write
# dispatch on `transport_mode`, which lives in src/transport/data.S (part
# of the transport_objs wildcard), so no data.o or stubs are needed.
$(TEST_TRANSPORT): test_transport.c $(HARNESS) $(transport_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(transport_objs) $(LDFLAGS) -o $@

# test_tls: the tls module (PLAN.MD §2) — the wire constants in
# defs.S are compile-time, so this links src/tls/data.S: the tls_state
# block and the tls_* field labels the offset tests check against the
# TLS_* offsets. crypto is linked too: the tls_objs wildcard now also
# picks up transcript/*.S (sha256_* streaming API) and record/*.S
# (aes_gcm from crypto + memcpy from util), so util_objs is linked as
# well (util_objs drags in the transport module per the comment at the top).
$(TEST_TLS): test_tls.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_client_hello: the ClientHello parser.
# Links the same object set as test_tls — tls_parse_client_hello writes
# into tls_state (tls_objs/data.S) and the tls_objs wildcard also pulls
# in record/*.S and transcript/*.S, hence crypto_objs + util_objs.
$(TEST_TLS_CLIENT_HELLO): test_tls_client_hello.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_server_hello: the ServerHello generator.
# Same object set as test_tls_client_hello — tls_build_server_hello
# calls crypto_random_bytes and x25519 from crypto_objs.
$(TEST_TLS_SERVER_HELLO): test_tls_server_hello.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_key_schedule.c drives tls_derive_handshake_secrets (PLAN.MD
# Phase 10) directly against tls_state, and cross-checks it with
# hkdf_expand_label from crypto_objs.
$(TEST_TLS_KEY_SCHEDULE): test_tls_key_schedule.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_encrypted_extensions.c drives tls_encrypted_extensions_write
# plus a seal/open round trip through
# tls_record_encrypt/tls_record_decrypt (tls_objs' record/*.S), which
# calls aes_gcm_encrypt/decrypt from crypto_objs.
$(TEST_TLS_ENCRYPTED_EXTENSIONS): test_tls_encrypted_extensions.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_certificate.c drives tls_certificate_write against the embedded
# certs/cert.der (tls_objs' cert_data.S).
$(TEST_TLS_CERTIFICATE): test_tls_certificate.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_certificate_verify_*: one suite per
# src/tls/handshake/certificate_verify/*.S module —
# content_hash (pure), sign_with_k (deterministic, cross-checked
# against a real ECDSA verify), and write (draws its own nonce, checked
# structurally + by verifying against the server's real pubkey). Same
# object set as test_tls_certificate — the private key and DER helper
# both live in crypto_objs/tls_objs already.
$(OBJ_DIR)/test_tls_certificate_verify_%: test_tls_certificate_verify/%.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_finished_*: one suite per src/tls/handshake/finished/*.S
# module — finished_key and verify_data (both thin,
# cross-checked wrappers over already-verified primitives) and write
# (end-to-end, reads tls_server_hs_traffic_secret from tls_state).
$(OBJ_DIR)/test_tls_finished_%: test_tls_finished/%.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_application_*: one suite per Phase 19 module — secrets
# (key-schedule tail, HKDF-Expand-Label wrappers) and write/read (thin
# record-layer specializations over tls_record_encrypt/decrypt).
$(OBJ_DIR)/test_tls_application_%: test_tls_application/%.c $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_transcript_*: tls + crypto + util.
# One suite per src/tls/transcript/*.S module (init, add, hash) — each a
# self-contained binary with its own main(), like the test_tls_record_*
# suites above. All share test_tls_transcript/common.h (KAT vectors +
# the independent C reference SHA-256 + asm wrappers). util_objs is
# linked because the tls_objs wildcard also picks up record/*.S, which
# calls memcpy from util.
TLS_TRANSCRIPT_COMMON := test_tls_transcript/common.h

$(OBJ_DIR)/test_tls_transcript_%: test_tls_transcript/%.c $(TLS_TRANSCRIPT_COMMON) $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

# test_tls_record_*: tls + crypto + util.
# One suite per src/tls/record/*.S module (parse, write, nonce, encrypt,
# decrypt, seq) — each a self-contained binary with its own main(), like
# the test_h2_* suites below. All share test_tls_record/common.h (RFC 8448
# vectors + asm wrappers) and call memcpy (util) / aes_gcm_* (crypto).
TLS_RECORD_COMMON := test_tls_record/common.h

$(OBJ_DIR)/test_tls_record_%: test_tls_record/%.c $(TLS_RECORD_COMMON) $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@

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
