// Trampoline exposing the file-local p256_reduce for isolated
// benchmarking (prompts/02-benchmark-substrate.md).
//
// p256_reduce (src/crypto/p256/sqr_mul.S:37) has no `.global` -- it is a
// bare, unexported label (docs/ANALYSIS-TOOLING.MD's own table calls it
// "file-local") -- so it cannot be linked from a separate translation
// unit directly. As with gcm_ghash_run_probe.S's approach to the local
// label .Lgcm_ghash_run, this file reaches it via #include (the C
// preprocessor; sqr_mul.S already relies on cpp for its own
// #include "../../defs.S"), which pulls its literal instructions into
// this object, where `b`/`bl` to the label resolves at assemble time.
// This does not modify sqr_mul.S.
//
// Unlike the GHASH case, sqr_mul.S also defines two GLOBAL symbols in
// the same file -- p256_fe_mul and p256_fe_sqr -- so #include-ing it
// verbatim would give this object its own copies of those globals too,
// which collides at link time with the real sqr_mul.o whenever this
// probe is linked alongside it. bench_p256_fe_mul.c needs exactly that:
// the real p256_fe_mul (for its own isolated number) *and* this probe's
// isolated p256_reduce (to compute the reduction-vs-multiplication
// share), in one binary. The fix: rename those two tokens before
// including, with the same preprocessor -- #define rewrites them
// everywhere they appear in the included text, including their
// `.global` lines and their label definitions, leaving only
// p256_reduce (not renamed) reachable under its real name. This is a
// preprocessing choice made only in this file, over a private copy of
// the same instructions; sqr_mul.S itself is untouched, and the real
// sqr_mul.o (linked separately for the real p256_fe_mul) never
// conflicts with this object's renamed-away copies.
#define p256_fe_mul p256_fe_mul__shadowed_unused
#define p256_fe_sqr p256_fe_sqr__shadowed_unused
#include "../../src/crypto/p256/sqr_mul.S"
#undef p256_fe_mul
#undef p256_fe_sqr

// ─────────────────────────────────────────────────────────────────────
// bench_p256_reduce_entry -- p256_reduce's own ABI, unchanged (x0 = out
// pointer, x1 = T pointer, 8 limbs). A tail call, no frame of its own,
// so the isolated benchmark times exactly p256_reduce (plus whatever it
// calls internally -- currently `bl p256_bn_mul` for Barrett reduction,
// resolved against the real, .global p256_bn_mul linked alongside this
// probe; after prompt 04 replaces Barrett with Solinas folding, that
// call may disappear, which this trampoline does not need to know
// about -- it stays correct either way since it never modified
// p256_reduce's own ABI).
// ─────────────────────────────────────────────────────────────────────
.text
.align 2
.global bench_p256_reduce_entry
bench_p256_reduce_entry:
    b p256_reduce
