# Benchmarks for individual sarm assembly functions.
#
# Each bench_<function> target compiles the function's own .S file (so a
# candidate installed by the optimizer is picked up automatically) plus a
# small C driver that times it and prints machine-readable JSON:
#
#   {"function": "memcpy", "runtime_ns": 12.34, "sizes": {...}}
#
# Built binaries land in _bench_bin/ (gitignored, like the _bench_obj/
# intermediates) rather than this source directory, so `git status` stays
# clean and nothing here needs a one-off .gitignore line per benchmark.
#
# Usage:
#   make bench_memcpy && ./_bench_bin/bench_memcpy
#   make clean

# Parallel by default, same as the top-level Makefile: each bench_<function>
# target is an independent compile.
#
#   make -C scripts/benchmarks JOBS=1     # serial build
#
# JOBS rather than -j because GNU make 3.81 (macOS) hides MAKEFLAGS from
# the makefile at parse time and cannot see a -j on the command line.
NPROC := $(shell (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 4)
JOBS ?= $(NPROC)
ifeq (,$(findstring -j,$(MAKEFLAGS)))
ifneq ($(JOBS),1)
MAKEFLAGS += -j$(JOBS)
endif
endif

AS      := cc
CC      := cc
ASFLAGS := -g -O2 -arch arm64
CFLAGS  := -g -O2 -arch arm64 -I ../../include
LDFLAGS := -arch arm64

_bench_obj:
	mkdir -p _bench_obj

_bench_bin:
	mkdir -p _bench_bin

_bench_obj/memcpy.o: ../../src/util/memcpy.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_memcpy: _bench_bin/bench_memcpy
_bench_bin/bench_memcpy: bench_memcpy.c _bench_obj/memcpy.o | _bench_bin
	$(CC) $(CFLAGS) bench_memcpy.c _bench_obj/memcpy.o $(LDFLAGS) -o $@

# bench_primitives spans most of src/, so instead of naming each .S it
# builds every one into an archive and lets the linker pull in what the
# driver actually reaches. src/sarm/main.S is excluded (it defines _main),
# as are the shared headers and the two generated tables, which are
# either not standalone or not needed here.
rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))
SRC       := ../../src
PRIM_SRCS := $(filter-out $(SRC)/config.S $(SRC)/defs.S $(SRC)/embedded.S \
                          $(SRC)/h2_huffman_table.S $(SRC)/tls/cert_data.S \
                          $(SRC)/sarm/main.S,$(call rwildcard,$(SRC),*.S))
PRIM_OBJS := $(patsubst $(SRC)/%.S,_bench_obj/sarm/%.o,$(PRIM_SRCS))

_bench_obj/sarm/%.o: $(SRC)/%.S
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/libsarm.a: $(PRIM_OBJS)
	ar rcs $@ $(PRIM_OBJS)

bench_primitives: _bench_bin/bench_primitives
_bench_bin/bench_primitives: bench_primitives.c _bench_obj/libsarm.a | _bench_bin
	$(CC) $(CFLAGS) bench_primitives.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

# ── AES-GCM / GHASH benchmark trio (docs/SCRIPTS.md) ──
# Distinguishes AES-only, GHASH-only (through the real .Lgcm_ghash_run call
# path) and complete AES-GCM cost as three separate numbers.

_bench_obj/aes128_key_expand.o: ../../src/crypto/aes128/key_expand.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/aes128_encrypt.o: ../../src/crypto/aes128/encrypt.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/gcm_encrypt.o: ../../src/crypto/gcm/encrypt.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/gcm_decrypt.o: ../../src/crypto/gcm/decrypt.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/gcm_ctx_init.o: ../../src/crypto/gcm/ctx_init.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/gcm_ghash.o: ../../src/crypto/gcm/ghash.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/gcm_ghash_run_probe.o: gcm_ghash_run_probe.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_aes128_encrypt: _bench_bin/bench_aes128_encrypt
_bench_bin/bench_aes128_encrypt: bench_aes128_encrypt.c _bench_obj/aes128_key_expand.o _bench_obj/aes128_encrypt.o | _bench_bin
	$(CC) $(CFLAGS) bench_aes128_encrypt.c _bench_obj/aes128_key_expand.o \
	    _bench_obj/aes128_encrypt.o $(LDFLAGS) -o $@

bench_aes_gcm_encrypt: _bench_bin/bench_aes_gcm_encrypt
_bench_bin/bench_aes_gcm_encrypt: bench_aes_gcm_encrypt.c _bench_obj/gcm_encrypt.o _bench_obj/gcm_decrypt.o _bench_obj/gcm_ctx_init.o _bench_obj/aes128_key_expand.o _bench_obj/aes128_encrypt.o | _bench_bin
	$(CC) $(CFLAGS) bench_aes_gcm_encrypt.c _bench_obj/gcm_encrypt.o \
	    _bench_obj/gcm_decrypt.o _bench_obj/gcm_ctx_init.o \
	    _bench_obj/aes128_key_expand.o \
	    _bench_obj/aes128_encrypt.o $(LDFLAGS) -o $@

bench_gcm_ghash_run: _bench_bin/bench_gcm_ghash_run
_bench_bin/bench_gcm_ghash_run: bench_gcm_ghash_run.c _bench_obj/gcm_ghash_run_probe.o _bench_obj/gcm_ghash.o | _bench_bin
	$(CC) $(CFLAGS) bench_gcm_ghash_run.c _bench_obj/gcm_ghash_run_probe.o \
	    _bench_obj/gcm_ghash.o $(LDFLAGS) -o $@

# ── P-256 benchmark suite (docs/SCRIPTS.md) ──
# Isolates p256_reduce (the prompt 04 target) from p256_bn_mul, so
# reduction cost can be separated from multiplication cost inside
# p256_fe_mul, plus point_mul/ECDSA/ECDH so the reduction change's
# end-to-end effect is measurable, not just the microbenchmark effect.

_bench_obj/p256_bn_mul.o: ../../src/crypto/p256/bn_mul.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/p256_sqr_mul.o: ../../src/crypto/p256/sqr_mul.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/p256_data.o: ../../src/crypto/p256/data.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/p256_reduce_probe.o: p256_reduce_probe.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_p256_reduce: _bench_bin/bench_p256_reduce
_bench_bin/bench_p256_reduce: bench_p256_reduce.c _bench_obj/p256_reduce_probe.o _bench_obj/p256_bn_mul.o _bench_obj/p256_sqr_mul.o _bench_obj/p256_data.o | _bench_bin
	$(CC) $(CFLAGS) bench_p256_reduce.c _bench_obj/p256_reduce_probe.o \
	    _bench_obj/p256_bn_mul.o _bench_obj/p256_sqr_mul.o \
	    _bench_obj/p256_data.o $(LDFLAGS) -o $@

bench_p256_fe_mul: _bench_bin/bench_p256_fe_mul
_bench_bin/bench_p256_fe_mul: bench_p256_fe_mul.c _bench_obj/p256_reduce_probe.o _bench_obj/p256_bn_mul.o _bench_obj/p256_sqr_mul.o _bench_obj/p256_data.o | _bench_bin
	$(CC) $(CFLAGS) bench_p256_fe_mul.c _bench_obj/p256_reduce_probe.o \
	    _bench_obj/p256_bn_mul.o _bench_obj/p256_sqr_mul.o \
	    _bench_obj/p256_data.o $(LDFLAGS) -o $@

bench_p256_bn_mul: _bench_bin/bench_p256_bn_mul
_bench_bin/bench_p256_bn_mul: bench_p256_bn_mul.c _bench_obj/p256_bn_mul.o | _bench_bin
	$(CC) $(CFLAGS) bench_p256_bn_mul.c _bench_obj/p256_bn_mul.o $(LDFLAGS) -o $@

# point_mul/ECDSA reach the full P-256 field/point/scalar chain, so these
# link the whole-src archive rather than naming each object.
bench_p256_point_mul: _bench_bin/bench_p256_point_mul
_bench_bin/bench_p256_point_mul: bench_p256_point_mul.c _bench_obj/libsarm.a | _bench_bin
	$(CC) $(CFLAGS) bench_p256_point_mul.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

bench_p256_point_mul_base: _bench_bin/bench_p256_point_mul_base
_bench_bin/bench_p256_point_mul_base: bench_p256_point_mul_base.c _bench_obj/libsarm.a | _bench_bin
	$(CC) $(CFLAGS) bench_p256_point_mul_base.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

bench_p256_scalar_inv: _bench_bin/bench_p256_scalar_inv
_bench_bin/bench_p256_scalar_inv: bench_p256_scalar_inv.c _bench_obj/libsarm.a | _bench_bin
	$(CC) $(CFLAGS) bench_p256_scalar_inv.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

bench_p256_ecdsa_sign_with_k: _bench_bin/bench_p256_ecdsa_sign_with_k
_bench_bin/bench_p256_ecdsa_sign_with_k: bench_p256_ecdsa_sign_with_k.c _bench_obj/libsarm.a | _bench_bin
	$(CC) $(CFLAGS) bench_p256_ecdsa_sign_with_k.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

# ── crypto_random_bytes (docs/SCRIPTS.md) ──
# The fresh re-profile found this hot enough post-03/04 to be worth its
# own isolated number: a real open+read+close of /dev/urandom per call,
# not arithmetic, so it belongs with the primitives it's compared against.

_bench_obj/random.o: ../../src/crypto/random.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_crypto_random_bytes: _bench_bin/bench_crypto_random_bytes
_bench_bin/bench_crypto_random_bytes: bench_crypto_random_bytes.c _bench_obj/random.o | _bench_bin
	$(CC) $(CFLAGS) bench_crypto_random_bytes.c _bench_obj/random.o $(LDFLAGS) -o $@

# ── lookup_embedded (docs/SCRIPTS.md) ──
# Links the real generated table (src/embedded.S -- run embed_www.sh
# first) so the measurement reflects the actual six-entry asset set, not
# a synthetic one.

_bench_obj/file_lookup_embedded.o: ../../src/file/lookup_embedded.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/util_streqn.o: ../../src/util/streqn.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/embedded.o: ../../src/embedded.S | _bench_obj
	@mkdir -p $(abspath _bench_obj)
	cd ../.. && $(AS) $(ASFLAGS) -c src/embedded.S -o scripts/benchmarks/$@

bench_lookup_embedded: _bench_bin/bench_lookup_embedded
_bench_bin/bench_lookup_embedded: bench_lookup_embedded.c _bench_obj/file_lookup_embedded.o _bench_obj/util_streqn.o _bench_obj/embedded.o | _bench_bin
	$(CC) $(CFLAGS) bench_lookup_embedded.c _bench_obj/file_lookup_embedded.o \
	    _bench_obj/util_streqn.o _bench_obj/embedded.o $(LDFLAGS) -o $@

# ── h2_stream_find (docs/SCRIPTS.md) ──
# Links h2/data.S for the real stream table and its packed id index, so
# the scan measured is the one the server runs, over the real layout.

_bench_obj/h2_h2_stream_find.o: ../../src/h2/h2_stream_find.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/h2_h2_stream_create.o: ../../src/h2/h2_stream_create.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/h2_data.o: ../../src/h2/data.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_h2_stream_find: _bench_bin/bench_h2_stream_find
_bench_bin/bench_h2_stream_find: bench_h2_stream_find.c _bench_obj/h2_h2_stream_find.o _bench_obj/h2_data.o | _bench_bin
	$(CC) $(CFLAGS) bench_h2_stream_find.c _bench_obj/h2_h2_stream_find.o \
	    _bench_obj/h2_data.o $(LDFLAGS) -o $@

# ── h2_stream_create (docs/SCRIPTS.md) ──
# Links only the function and the data it walks: h2_stream_create touches
# h2_streams, h2_stream_ids and the two slot bitmaps, all of which live in
# h2/data.S, and calls nothing.
bench_h2_stream_create: _bench_bin/bench_h2_stream_create
_bench_bin/bench_h2_stream_create: bench_h2_stream_create.c _bench_obj/h2_h2_stream_create.o _bench_obj/h2_data.o | _bench_bin
	$(CC) $(CFLAGS) bench_h2_stream_create.c _bench_obj/h2_h2_stream_create.o \
	    _bench_obj/h2_data.o $(LDFLAGS) -o $@

# ── http1_reset_request (docs/SCRIPTS.md) ──
# Clears a dozen globals spread across parse/, http1/ and src/data.S, and
# range_buf's own file drags in the range parser behind it, so this links
# the whole-src archive rather than chasing each object.

_bench_obj/http1_reset_request.o: ../../src/http1/reset_request.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/parse_data.o: ../../src/parse/data.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/http1_data.o: ../../src/http1/data.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/sarm_data.o: ../../src/data.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

_bench_obj/http1_reset_stub.o: http1_reset_stub.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_http1_reset_request: _bench_bin/bench_http1_reset_request
_bench_bin/bench_http1_reset_request: bench_http1_reset_request.c _bench_obj/http1_reset_request.o _bench_obj/parse_data.o _bench_obj/http1_data.o _bench_obj/sarm_data.o _bench_obj/http1_reset_stub.o | _bench_bin
	$(CC) $(CFLAGS) bench_http1_reset_request.c _bench_obj/http1_reset_request.o \
	    _bench_obj/parse_data.o _bench_obj/http1_data.o _bench_obj/sarm_data.o \
	    _bench_obj/http1_reset_stub.o $(LDFLAGS) -o $@

.PHONY: clean bench_http1_reset_request bench_memcpy bench_primitives bench_aes128_encrypt \
    bench_aes_gcm_encrypt bench_gcm_ghash_run bench_p256_reduce \
    bench_p256_fe_mul bench_p256_bn_mul bench_p256_point_mul \
    bench_p256_point_mul_base bench_p256_scalar_inv \
    bench_p256_ecdsa_sign_with_k bench_crypto_random_bytes \
    bench_lookup_embedded bench_h2_stream_find bench_h2_stream_create
clean:
	rm -rf _bench_obj _bench_bin
