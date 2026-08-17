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

bench_primitives: bench_primitives.c _bench_obj/libsarm.a
	$(CC) $(CFLAGS) bench_primitives.c _bench_obj/libsarm.a $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf _bench_obj bench_memcpy bench_primitives
