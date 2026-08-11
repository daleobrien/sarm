rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))

SRCS := $(filter-out src/config.S src/defs.S src/embedded.S,$(wildcard src/*.S))
OBJS := $(SRCS:src/%.S=%.o)
CFLAGS += -O3
LDFLAGS := -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -e _main -arch arm64

# Build pipeline:
#   www/ ──embed_www.sh──> src/embedded.S ──cc──> embedded.o ──ld──> ymawky

ymawky: $(OBJS) embedded.o
	ld $(OBJS) embedded.o -o ymawky $(LDFLAGS)
	rm -f $(OBJS) embedded.o

%.o: src/%.S $(SRCS)
	cc -g $(CFLAGS) -c $< -o $@

.PHONY: assets
assets: src/embedded.S

src/embedded.S: embed_www.sh $(call rwildcard,www,*)
	sh embed_www.sh

.PHONY: clean
clean:
	rm -f ymawky $(OBJS) embedded.o src/embedded.S
	rm -rf www_gz

.PHONY: test
test: ymawky
	./test_files.sh --no-build
