// Stub for bench_http1_reset_request -- docs/SCRIPTS.md.
//
// http1_reset_request zeroes range_buf along with everything else, but
// range_buf is defined in src/parse/parse_range.S next to the range parser
// itself, and linking that file pulls in get_header_field, atoi_n and
// streqn_i behind it. The benchmark does not exercise any of them, so it
// supplies the one symbol instead -- same size and alignment as the real
// one, matching the p256_reduce_probe.S / gcm_ghash_run_probe.S pattern.

#include "../../src/defs.S"

.bss
.align 4
OBJECT range_buf
    .skip (19 + 15) & ~15
ENDOBJ range_buf
