SRCS := $(wildcard src/*.S)
OBJS := $(SRCS:src/%.S=%.o)
CFLAGS += -O3
LDFLAGS := -l System -syslibroot $(shell xcrun --sdk macosx --show-sdk-path) -e _main -arch arm64

ymawky: $(OBJS)
	ld $(OBJS) -o ymawky $(LDFLAGS)
	rm -f $(OBJS)

%.o: src/%.S $(SRCS)
	cc -g $(CFLAGS) -c $< -o $@

clean:
	rm -f ymawky $(OBJS)
