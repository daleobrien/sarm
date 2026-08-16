rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

# Sources: every .S under src/ (recursively, so the per-function folders
# are picked up), except the shared headers (config.S, defs.S), the
# generated embedded table (built separately), and the generated HPACK
# Huffman table (included by src/hpack/data.S, never compiled standalone).
SRCS := $(filter-out src/config.S src/defs.S src/embedded.S src/h2_huffman_table.S,$(call rwildcard,src,*.S))
OBJS := $(SRCS:src/%.S=build/%.o)
CFLAGS += -O3
LDFLAGS := -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -e _main -arch arm64

# Build pipeline:
#   www/ ──embed_www.sh──> src/embedded.S ──cc──> build/embedded.o ──ld──> sarm

# Dependency graph:
#   www/* ──> src/embedded.S ──> build/embedded.o ──> sarm
#
# sarm depends on 'assets' so that changing any file under www/
# triggers regeneration of src/embedded.S, recompilation of
# build/embedded.o, and relinking of the final binary.
sarm: assets $(OBJS) build/embedded.o
	@ld $(OBJS) build/embedded.o -o sarm $(LDFLAGS)
	@rm -rf build

build/%.o: src/%.S
	@mkdir -p $(dir $@)
	@cc -g $(CFLAGS) -c $< -o $@

# Production build: same pipeline as the default target, but the final
# binary is stripped of local symbols with `strip -x`.
.PHONY: production
production: sarm
	@strip -x sarm

.PHONY: assets
assets: src/embedded.S

# Regenerate src/embedded.S whenever any file under www/ changes
# or when the embedding script itself is modified.
src/embedded.S: embed_www.sh $(call rwildcard,www,*)
	sh embed_www.sh

# Regenerate src/tls/cert_data.S whenever any file under certs/ changes
src/tls/cert_data.S: certs/embed_cert.sh $(call rwildcard,certs,*)
	sh certs/embed_cert.sh

.PHONY: clean
clean:
	rm -f sarm src/embedded.S
	rm -rf build www_gz www/err

.PHONY: test
test: sarm
	@./tests/test_files.sh --no-build --quiet
	@./tests/test_security.sh --no-build --quiet
	@./tests/test_protocols.sh --no-build --quiet
	@$(MAKE) -s -C tests/unit
