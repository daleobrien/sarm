rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))
DETECTED_OS := $(shell uname -s)

# Sources: every .S under src/ (recursively, so the per-function folders
# are picked up), except the shared headers (config.S, defs.S), the
# generated embedded table (built separately), and the generated HPACK
# Huffman table (included by src/hpack/data.S, never compiled standalone).
SRCS := $(filter-out src/config.S src/defs.S src/embedded.S src/tls/cert_data.S src/h2_huffman_table.S,$(call rwildcard,src,*.S))
OBJS := $(SRCS:src/%.S=build/%.o)
CFLAGS += -O3
# Link-time hardening (docs/SECURITY.md Step 13 / docs/security/hardening.md).
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
	@./tests/test_multicore.sh --no-build --quiet --workers 1 --iterations 2 --stress-seconds 5
	@./tests/test_multicore.sh --no-build --quiet --workers 2 --iterations 2 --stress-seconds 5
	@./tests/test_multicore.sh --no-build --quiet --workers 4 --iterations 2 --stress-seconds 5
	@$(MAKE) -s -C tests/unit
	@$(MAKE) -s -C tests/security
