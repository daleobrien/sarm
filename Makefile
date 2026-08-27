rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))
DETECTED_OS := $(shell uname -s)

# Sources: every .S under src/ (recursively, so the per-function folders
# are picked up), except the shared headers (config.S, defs.S), the
# generated embedded table (built separately), and the generated HPACK
# Huffman table (included by src/hpack/data.S, never compiled standalone).
SRCS := $(filter-out src/config.S src/defs.S src/embedded.S src/tls/cert_data.S src/h2_huffman_table.S,$(call rwildcard,src,*.S))
# ── hot-path link order (experiment, docs/HISTORY.md) ────────────────
# The link is a plain `ld $(OBJS)`, so OBJS order IS the .text layout.
# Left alone, that order is whatever rwildcard's directory walk hands
# back — alphabetical by folder, which is to say arbitrary. HOT_SRCS
# moves the profiled hot set to the front in request-flow order so the
# functions that run together are laid out together.
#
# This is a null test, and the prediction registered before the first
# run is that it buys nothing measurable. The whole of .text is 48.6 KB
# against a 64 KB L1I on Neoverse-N1, and the h2c hot set is 7.8 KB
# over 136 of the cache's 1024 line slots at 91% line density — sarm
# cannot capacity-miss its own code, so there is no miss for reordering
# to remove. Reordering does collapse the hot set's address span from
# 27 KB to ~8 KB, and the point of running it is to have that measured
# rather than argued. Ceiling if the mechanism were real: 136 -> ~125
# lines, ~9%. Expected on h2c cycles/request: under 0.3%, i.e. below
# this rig's resolution.
#
# The order below is request flow for h2c (the protocol under study),
# then the utilities all three protocols share, then the TLS record
# path, then HTTP/1.1. Every entry is a function the sampled profile
# in perf-results/ec2-20260826-222952 actually attributed cycles to;
# nothing here is guessed from reading the call graph.
HOT_SRCS := \
	src/h2/h2_connection_loop.S \
	src/transport/transport_read.S \
	src/h2/h2_handle_headers.S \
	src/hpack/h2_hpack_decode_block.S \
	src/hpack/h2_hpack_decode_field.S \
	src/hpack/h2_hpack_decode_int.S \
	src/hpack/h2_hpack_static_lookup.S \
	src/hpack/dynamic_table/lookup.S \
	src/h2/h2_name_eq.S \
	src/h2/h2_stream_find.S \
	src/h2/h2_stream_create.S \
	src/h2/h2_stream_event.S \
	src/h2/h2_build_request.S \
	src/parse/parse_h2_path.S \
	src/file/decode_url.S \
	src/file/check_path_safety.S \
	src/file/check_path_traversal.S \
	src/h2/h2_process_request.S \
	src/h2/h2_write_headers.S \
	src/h2/h2_write_body.S \
	src/transport/raw_writev.S \
	src/util/memcpy.S \
	src/util/streqn.S \
	src/util/itoa.S \
	src/crypto/gcm/encrypt.S \
	src/transport/raw_write.S \
	src/transport/raw_read.S \
	src/parse/get_header_field.S \
	src/util/streqn_i.S \
	src/sarm/child.S \
	src/http1/http1_write_response.S \
	src/http1/reset_request.S \
	src/parse/parse_header_end.S \
	src/parse/parse_request.S \
	src/parse/parse_path.S \
	src/file/lookup_embedded.S

# A renamed or moved hot-path file must not silently fall back to the
# arbitrary order — that would turn a measured null into an unmeasured
# one and nobody would notice.
HOT_MISSING := $(filter-out $(SRCS),$(HOT_SRCS))
ifneq ($(HOT_MISSING),)
$(error HOT_SRCS lists files that are not in SRCS: $(HOT_MISSING))
endif

SRCS := $(HOT_SRCS) $(filter-out $(HOT_SRCS),$(SRCS))

OBJS := $(SRCS:src/%.S=build/%.o)
CFLAGS += -O3
# Link-time hardening (docs/SECURITY.md §13).
# tests/test_hardening.sh asserts every property these flags buy, by
# inspecting the linked binary rather than trusting the flags.
#
#   -pie              position-independent executable, so the loader can
#                     place the image at a random base. The tree carries
#                     no absolute addresses in static data — every table
#                     holds link-time-resolved offsets — so this needs no
#                     load-time relocation on either platform.
#   -z noexecstack    emit PT_GNU_STACK RW. Without it aarch64 Linux
#                     turns on READ_IMPLIES_EXEC for the whole process,
#                     which makes every readable mapping executable.
#   -z separate-code  give .rodata its own r-- LOAD segment instead of
#                     sharing the r-x one with .text.
ifeq ($(DETECTED_OS),Darwin)
	LDFLAGS := -e _main -arch arm64 -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -pie
else
	LDFLAGS := -pie --no-dynamic-linker -z noexecstack -z separate-code
	CFLAGS += "-march=armv8-a+crypto"
	CXXFLAGS += "-march=armv8-a+crypto"
endif

# sarm depends on 'assets', changing any file under:
#  www triggers regeneration of src/embedded.S -> build/embedded.o
#  certs triggers regeneration of src/tls/cert_data.S -> build/tls/cert_data.o
# then a relinking
sarm: assets $(OBJS) build/embedded.o build/tls/cert_data.o
	@ld $(OBJS) build/embedded.o build/tls/cert_data.o -o sarm $(LDFLAGS)
	@rm -rf build

build/%.o: src/%.S
	@mkdir -p $(dir $@)
	@cc -g $(CFLAGS) -c $< -o $@

# ── variant: an out-of-tree build with extra -D flags ────────────────
# Same sources, same link, different compile-time configuration, and a
# binary somewhere other than ./sarm — so a test can exercise a knob
# without disturbing the binary the rest of the suite is running
# against. tests/test_limits.sh (docs/SECURITY.md Step 12) uses it to
# assert the connection deadline and the receive timeout in seconds
# rather than minutes:
#
#   make variant BIN=/tmp/sarm-short \
#        VARIANT_CFLAGS='-DCONN_DEADLINE_SECONDS=6 -DRECV_TIMEOUT_SECONDS=2'
#
# The object tree is separate ($(VBUILD)) and removed on the way out, so
# a variant build never leaves stale objects for the default target.
BIN ?= sarm-variant
VBUILD := build-variant
VOBJS := $(SRCS:src/%.S=$(VBUILD)/%.o)

$(VBUILD)/%.o: src/%.S
	@mkdir -p $(dir $@)
	@cc -g $(CFLAGS) $(VARIANT_CFLAGS) -c $< -o $@

.PHONY: variant
variant: assets $(VOBJS) $(VBUILD)/embedded.o $(VBUILD)/tls/cert_data.o
	@mkdir -p $(dir $(BIN))
	@ld $(VOBJS) $(VBUILD)/embedded.o $(VBUILD)/tls/cert_data.o -o $(BIN) $(LDFLAGS)
	@rm -rf $(VBUILD)

# Production build: same pipeline as the default target, but the final
# binary is stripped of local symbols with `strip -x`.
.PHONY: production
production: sarm
	@strip -x sarm

.PHONY: assets
assets: src/embedded.S src/tls/cert_data.S

# Web assets:
# embed_www.sh generates both www_gz/* and src/embedded.S.
# The stamp gives Make a real file to track rather than tracking
# the www_gz directory itself.
www_gz/.stamp: embed_www.sh $(call rwildcard,www,*)
	@rm -rf www_gz
	@mkdir -p www_gz
	@sh embed_www.sh
	@touch $@

src/embedded.S: www_gz/.stamp
	@test -f $@

# TLS assets.
src/tls/cert_data.S: certs/embed_cert.sh \
                     certs/cert.der \
                     certs/cert.pem
	@sh certs/embed_cert.sh

.PHONY: clean
clean:
	@$(MAKE) -s -C tests/security clean
	rm -f sarm src/embedded.S
	rm -f sarm src/tls/cert_data.S
	rm -rf build build-variant www_gz www/err
	rm -f sarm-variant

.PHONY: test-security
# The security test suite (docs/SECURITY.md). Links no part of the
# server and needs no built binary — it tests the security test
# infrastructure itself (guard pages, Step 2) and, from Step 3 on,
# individual assembly routines against guarded buffers. Kept as its own
# target so it can be run alone, and folded into `make test` below.
test-security:
	@$(MAKE) -s -C tests/security

.PHONY: fuzz-soak
# Step 14 (continuous fuzzing). `make test` runs every fuzz campaign on a
# fixed seed, because a suite whose corpus moves cannot tell a regression
# from a coincidence. This one runs the same campaigns on seeds nobody has
# run before, and preserves the input of anything it finds under
# tests/security/findings/. Not part of `make test`: it is meant for the
# machines and hours nobody is waiting on. SOAK_ARGS passes options
# through (--minutes, --forever, --mult, --suite, --minimize).
#   docs/SECURITY.md §12
fuzz-soak:
	@./scripts/fuzz_soak.py $(SOAK_ARGS)

.PHONY: test
test: sarm
	@./tests/test_files.sh --no-build --quiet
	@./tests/test_security.sh --no-build --quiet
	@./tests/test_protocols.sh --no-build --quiet
	@./tests/test_keepalive.sh --no-build --quiet
	@./tests/test_h2_flow.sh --no-build --quiet
	@./tests/test_workers.sh --no-build --quiet
	@./tests/test_leak.sh --no-build --quiet
	@./tests/test_syscalls.sh --no-build --quiet
	@./tests/test_limits.sh --no-build --quiet
	@./tests/test_hardening.sh --no-build --quiet
	@./tests/test_width_guard.sh --no-build --quiet
	@./tests/test_rng_fail.sh --no-build --quiet
	@./tests/test_multicore.sh --no-build --quiet --workers 1 --iterations 2 --stress-seconds 5
	@./tests/test_multicore.sh --no-build --quiet --workers 2 --iterations 2 --stress-seconds 5
	@./tests/test_multicore.sh --no-build --quiet --workers 4 --iterations 2 --stress-seconds 5
	@$(MAKE) -s -C tests/unit
	@$(MAKE) -s -C tests/security
