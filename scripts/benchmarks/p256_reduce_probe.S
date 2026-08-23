// Trampoline exposing p256_reduce for isolated benchmarking
// (docs/SCRIPTS.md).
//
// Historically p256_reduce (src/crypto/p256/sqr_mul.S) had no `.global`
// and this file worked around that by #include-ing sqr_mul.S with its
// own two global symbols (#p256_fe_mul, p256_fe_sqr) shadowed away, so
// the file-local label could be reached without colliding with the
// real sqr_mul.o linked alongside it for p256_fe_mul.
//
// prompt 04's replacement reduction exports p256_reduce (.global, like
// p256_bn_mul already was) for direct differential/unit testing, so
// that workaround is no longer needed: this is now a plain tail-call
// trampoline to the real, globally-linked p256_reduce. Kept as a
// trampoline (rather than having bench_p256_reduce.c/bench_p256_fe_mul.c
// call p256_reduce directly) so neither of those files needed to change.
.text
.align 2
.extern p256_reduce
.global bench_p256_reduce_entry
bench_p256_reduce_entry:
    b p256_reduce
