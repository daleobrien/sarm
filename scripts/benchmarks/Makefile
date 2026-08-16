# Benchmarks for individual sarm assembly functions.
#
# Each bench_<function> target compiles the function's own .S file (so a
# candidate installed by the optimizer is picked up automatically) plus a
# small C driver that times it and prints machine-readable JSON:
#
#   {"function": "memcpy", "runtime_ns": 12.34, "sizes": {...}}
#
# Usage:
#   make bench_memcpy && ./bench_memcpy
#   make clean

AS      := cc
CC      := cc
ASFLAGS := -g -O2 -arch arm64
CFLAGS  := -g -O2 -arch arm64
LDFLAGS := -arch arm64

_bench_obj:
	mkdir -p _bench_obj

_bench_obj/memcpy.o: ../../src/util/memcpy.S | _bench_obj
	$(AS) $(ASFLAGS) -c $< -o $@

bench_memcpy: bench_memcpy.c _bench_obj/memcpy.o
	$(CC) $(CFLAGS) bench_memcpy.c _bench_obj/memcpy.o $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf _bench_obj bench_memcpy
