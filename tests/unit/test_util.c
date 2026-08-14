// Unit tests for src/util.S assembly functions
// Every util suite has been split out into its own dedicated file:
//   atoi in test_atoi.c; atoi_n in test_atoi_n.c; strlen in test_strlen.c;
//   streqn in test_streqn.c; streqn_i in test_streqn_i.c; memcpy in
//   test_memcpy.c; itoa in test_itoa.c; fnv1a_64 in test_fnv1a_64.c.
// This file is kept only as the harness entry point for the util object
// files; it runs no tests of its own anymore.
//
// NOTE: This file links against util.o which defines its own "strlen" with
// a non-standard calling convention (arg in x1, not x0). Do NOT call libc
// strlen() — use the asm strlen via the wrapper instead.

#include "test_harness.h"

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_summary();
	return 0;
}
