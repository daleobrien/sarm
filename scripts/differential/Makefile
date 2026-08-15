# Differential-test drivers (OPTIMISATION.MD, "Differential testing").
#
# Builds two programs speaking the driver.h protocol:
#   _build/memcpy_ref  -- libc memcpy (the known-good reference)
#   _build/memcpy_asm  -- src/util/memcpy.S (the candidate)
#
# The asm driver depends on the .S file, so `make` rebuilds it after
# every candidate the optimizer installs.
#
# Note: no recipe-less forwarding targets here -- GNU make would fall
# back to the implicit `%: %.c` link rule and produce a broken binary.
#
# Usage:
#   make -C scripts/differential _build/memcpy_ref _build/memcpy_asm

AS      := cc
CC      := cc
ASFLAGS := -g -O2 -arch arm64
CFLAGS  := -g -O2 -arch arm64
LDFLAGS := -arch arm64

_build:
	mkdir -p _build

_build/memcpy.o: ../../src/util/memcpy.S | _build
	$(AS) $(ASFLAGS) -c $< -o $@

_build/memcpy_ref: memcpy_ref.c driver.h | _build
	$(CC) $(CFLAGS) memcpy_ref.c $(LDFLAGS) -o $@

_build/memcpy_asm: memcpy_asm.c driver.h _build/memcpy.o | _build
	$(CC) $(CFLAGS) memcpy_asm.c _build/memcpy.o $(LDFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf _build
