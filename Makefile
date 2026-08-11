SRCS := $(filter-out src/config.S src/defs.S src/embedded.S,$(wildcard src/*.S))
OBJS := $(SRCS:src/%.S=%.o)
CFLAGS += -O3
LDFLAGS := -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -e _main -arch arm64

ymawky: $(OBJS) embedded.o
	ld $(OBJS) embedded.o -o ymawky $(LDFLAGS)
	rm -f $(OBJS) embedded.o

%.o: src/%.S $(SRCS)
	cc -g $(CFLAGS) -c $< -o $@

src/embedded.S: embed_www.sh $(wildcard www/* www/assets/*)
	sh embed_www.sh

clean:
	rm -f ymawky $(OBJS) embedded.o src/embedded.S
	rm -rf www_gz
