rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

SRCS := $(filter-out src/config.S src/defs.S src/embedded.S,$(wildcard src/*.S))
OBJS := $(SRCS:src/%.S=%.o)
CFLAGS += -O3
LDFLAGS := -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -e _main -arch arm64

# Build pipeline:
#   www/ ──embed_www.sh──> src/embedded.S ──cc──> embedded.o ──ld──> ymawky

# Dependency graph:
#   www/* ──> src/embedded.S ──> embedded.o ──> ymawky
#
# ymawky depends on 'assets' so that changing any file under www/
# triggers regeneration of src/embedded.S, recompilation of
# embedded.o, and relinking of the final binary.
ymawky: assets $(OBJS) embedded.o
	ld $(OBJS) embedded.o -o ymawky $(LDFLAGS)
	rm -f $(OBJS) embedded.o

%.o: src/%.S
	cc -g $(CFLAGS) -c $< -o $@

.PHONY: assets
assets: src/embedded.S

# Regenerate src/embedded.S whenever any file under www/ changes
# or when the embedding script itself is modified.
src/embedded.S: embed_www.sh $(call rwildcard,www,*)
	sh embed_www.sh

.PHONY: clean
clean:
	rm -f ymawky $(OBJS) embedded.o src/embedded.S
	rm -rf www_gz www/err

.PHONY: test
test: ymawky
	./test_files.sh --no-build
