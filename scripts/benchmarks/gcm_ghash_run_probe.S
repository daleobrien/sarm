// Benchmark trampoline exposing the real GHASH implementation,
// .Lgcm_ghash_run, to a C driver (docs/SCRIPTS.md).
//
// .Lgcm_ghash_run (src/crypto/gcm/data.S:131) is a file-local ".L" label:
// invisible to the linker outside the translation unit that assembles it.
// encrypt.S, decrypt.S and ghash.S each reach it by C-preprocessor
// `#include "data.S"` -- confirmed by reading those files -- which is the
// exact same mechanism used below: including data.S pulls its literal
// instructions into *this* object, where a `bl` to the local label
// resolves at assemble time. This is not a reimplementation and does not
// modify data.S; it is the same bytes, assembled a second time into a
// second, standalone object that nothing else links against.
//
// Do not link this .o alongside encrypt.o/decrypt.o/ghash.o for anything
// that also needs their own private .Lgcm_* copies -- not because of a
// conflict (local symbols never collide across objects) but because this
// file's only purpose is isolating .Lgcm_ghash_run from the AES chain, and
// pulling in the AES/GCM globals too would defeat that isolation. It
// exports no name that collides with anything else in the tree.

#include "../../src/crypto/gcm/data.S"

.text
.align 2

// ─────────────────────────────────────────────────────────────────────
// bench_ghash_run_once -- mirrors ghash.S's own three-call sequence
// (AAD, then CT, then the big-endian bit-length block) exactly, so its
// result is byte-identical to the real `ghash` global for the same
// (H, aad, aad_len, ct, ct_len). This is a smoke test on *this probe's*
// setup of the entry conditions data.S:107-130 documents (v16-v18 the
// nibble/zero/0x87 constants, v19 = H', v20 = accumulator, x27/x28 the
// per-call data pointer/length) -- not an independent correctness oracle
// for .Lgcm_ghash_run itself, which tests/unit/test_gcm/ already covers.
// A mismatch here means this file's calling convention is wrong, which
// docs/SCRIPTS.md calls out explicitly: "faking a
// different calling convention would measure a different, unrepresentative
// code path."
//
// Input/Arguments:
//   x0 -- H pointer, 16 bytes, GCM wire order (E_K(0^128), pre-gcm_rbit)
//   x1 -- aad pointer (ignored when x2 == 0)
//   x2 -- aad length in bytes
//   x3 -- ct pointer (ignored when x4 == 0)
//   x4 -- ct length in bytes
//   x5 -- 16-byte output buffer
// ─────────────────────────────────────────────────────────────────────
FUNC bench_ghash_run_once
    // x27/x28 are callee-saved under AAPCS64; this function uses them as
    // scratch to feed .Lgcm_ghash_run (matching its documented contract,
    // data.S:107-130), so -- like the real ghash.S:39-45 prologue this
    // mirrors -- they must be saved/restored here even though the region
    // being called treats x27 as its own clobbered scratch. Omitting this
    // corrupts whatever the *caller* of this function keeps live there.
    sub     sp, sp, #80
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x27, x28, [sp, #48]
    // sp+64 .. sp+79: the 16-byte bit-length block

    mov     x19, x1                    // aad
    mov     x20, x2                    // aad_len
    mov     x21, x3                    // ct
    mov     x22, x4                    // ct_len

    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f

    ld1     {v19.16b}, [x0]
    gcm_rbit v19.16b, v19.16b          // H' (natural domain)
    movi    v20.16b, #0                // Y' = 0

    mov     x27, x19
    mov     x28, x20
    bl      .Lgcm_ghash_run
    mov     x27, x21
    mov     x28, x22
    bl      .Lgcm_ghash_run

    lsl     x9, x20, #3
    rev     x9, x9
    str     x9, [sp, #64]
    lsl     x9, x22, #3
    rev     x9, x9
    str     x9, [sp, #72]
    add     x27, sp, #64
    mov     x28, #16
    bl      .Lgcm_ghash_run

    gcm_rbit v20.16b, v20.16b          // back to GCM wire order
    st1     {v20.16b}, [x5]

    ldp     x27, x28, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #80
    ret
ENDFUNC bench_ghash_run_once

// ─────────────────────────────────────────────────────────────────────
// bench_ghash_run_timed -- the timed entry. Constants and H are loaded
// ONCE before the loop, then `iters` back-to-back calls to
// .Lgcm_ghash_run run over [data, len), each against a freshly zeroed
// accumulator (as if hashing a fresh record each time). This matches how
// the real call sites amortize setup: aes_gcm_encrypt loads v16-v21/H
// once per record, not once per .Lgcm_ghash_run call -- so this measures
// exactly the cost the inner loop actually pays in production, not setup
// noise. Divide the result by (len+15)/16 for a per-16-byte-block number.
//
// Input/Arguments:
//   x0 -- data pointer, x1 -- byte length, x2 -- H pointer (16B, wire
//   order), x3 -- iteration count
// ─────────────────────────────────────────────────────────────────────
FUNC bench_ghash_run_timed
    // x27/x28 are callee-saved under AAPCS64 -- same reasoning as
    // bench_ghash_run_once above; both must be saved/restored here even
    // though .Lgcm_ghash_run itself treats x27 as clobbered scratch.
    // (The first version of this file skipped this and it was not a
    // no-op: the caller's own loop-counter/timing locals landed in x27/x28
    // under -O2 and were silently overwritten, producing wall-clock
    // timings off by many orders of magnitude with no crash to flag it.)
    stp     x29, x30, [sp, #-48]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x27, x28, [sp, #32]
    mov     x19, x0                    // data
    mov     x20, x1                    // len

    adr_l   x9, .Lgcm_rbit_table
    ld1     {v16.16b}, [x9]
    mov     x10, #0x87
    dup     v17.2d, x10
    movi    v18.16b, #0
    movi    v21.16b, #0x0f
    ld1     {v19.16b}, [x2]
    gcm_rbit v19.16b, v19.16b

.Lbench_ghash_run_loop:
    movi    v20.16b, #0
    mov     x27, x19
    mov     x28, x20
    bl      .Lgcm_ghash_run
    subs    x3, x3, #1
    b.ne    .Lbench_ghash_run_loop

    ldp     x27, x28, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    ret
ENDFUNC bench_ghash_run_timed
