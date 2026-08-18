#!/usr/bin/env python3
"""P-256 folding reduction: derivation, exact carry bounds, and a
hardware-faithful reference implementation.

This is the generator behind `p256_reduce` (src/crypto/p256/sqr_mul.S) and
`docs/P256-REDUCE-DERIVATION.md` -- run it to re-derive the fold table from
first principles (not from a transcribed constant table), to re-prove the
exact carry bounds the assembly's correction rounds are sized against, and
to regenerate tests/unit/test_p256/reduce.c's vectors.

Usage:
    python3 scripts/p256_reduce_derivation.py derive     # print the fold table + verify it
    python3 scripts/p256_reduce_derivation.py bound       # exact (vertex-search) carry bounds
    python3 scripts/p256_reduce_derivation.py check [N]   # N random + edge cases through the
                                                            # hardware-faithful reference (default 200000)
    python3 scripts/p256_reduce_derivation.py gen-test > tests/unit/test_p256/reduce.c
"""
import random
import sys

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
MASK64 = (1 << 64) - 1


# ── 1. Derive the fold table from the exact Solinas identity ──────────────
# 2^256 = p + 2^224 - 2^192 - 2^96 + 1  (exact, from the definition of p),
# so for e >= 256: c*2^e == c*2^(e-32) - c*2^(e-64) - c*2^(e-160) + c*2^(e-256)  (mod p, exactly).
# Repeat until every exponent present is in [0, 224]; this always terminates
# because each rewrite strictly lowers the maximum exponent.
def rewrite_high_word(i):
    terms = {32 * i: 1}
    while True:
        high = [e for e in terms if e >= 256]
        if not high:
            break
        e = high[0]
        c = terms.pop(e)
        for delta, sign in ((-32, 1), (-64, -1), (-160, -1), (-256, 1)):
            ne = e + delta
            terms[ne] = terms.get(ne, 0) + sign * c
            if terms[ne] == 0:
                del terms[ne]
    return {e // 32: c for e, c in terms.items()}


TABLE = {i: rewrite_high_word(i) for i in range(8, 16)}
WORD_CONTRIBS = {j: [(j, 1)] for j in range(8)}
for _i in range(8, 16):
    for _j, _c in TABLE[_i].items():
        WORD_CONTRIBS[_j].append((_i, _c))


def cmd_derive():
    for i in range(8, 16):
        lhs = sum(c * (2 ** (32 * j)) for j, c in TABLE[i].items()) % P
        rhs = pow(2, 32 * i, P)
        assert lhs == rhs, (i, lhs, rhs)
    print("word i -> {output word j: coeff}  (each checked exactly mod p)")
    for i in range(8, 16):
        print(f"  {i}: {TABLE[i]}")
    print()
    print("per-output-word contributions:")
    for j in range(8):
        print(f"  word{j}: {WORD_CONTRIBS[j]}")


# ── 2. Exact carry_final bound (linear extrema at box vertices) ───────────
def cmd_bound():
    R = {i: sum(c * (2 ** (32 * j)) for j, c in TABLE[i].items()) for i in range(8, 16)}
    min_high = sum((2**32 - 1) * R[i] if R[i] < 0 else 0 for i in range(8, 16))
    max_high = sum((2**32 - 1) * R[i] if R[i] > 0 else 0 for i in range(8, 16))
    S_min, S_max = 0 + min_high, (2**256 - 1) + max_high
    carry_min, carry_max = S_min >> 256, S_max >> 256
    print(f"carry_final exact range: [{carry_min}, {carry_max}]")
    assert (carry_min, carry_max) == (-4, 4)
    print("(matches the bound documented in sqr_mul.S / P256-REDUCE-DERIVATION.md)")


# ── 3. Hardware-faithful reference: same ASR/AND two's-complement carry
#      semantics the assembly implements, register-op for register-op. ────
def s64(x):
    x &= MASK64
    return x - (1 << 64) if x >= (1 << 63) else x


def reduce_hw(T):
    lo = lambda x: x & 0xffffffff
    hi = lambda x: (x >> 32) & 0xffffffff
    acc = [0] * 8
    acc[0], acc[1] = lo(T[0]), hi(T[0])
    acc[2], acc[3] = lo(T[1]), hi(T[1])
    acc[4], acc[5] = lo(T[2]), hi(T[2])
    acc[6], acc[7] = lo(T[3]), hi(T[3])
    values = {8: lo(T[4]), 9: hi(T[4]), 10: lo(T[5]), 11: hi(T[5]),
              12: lo(T[6]), 13: hi(T[6]), 14: lo(T[7]), 15: hi(T[7])}
    for i in range(8, 16):
        v = values[i]
        for j, coeff in TABLE[i].items():
            acc[j] = s64(acc[j] + coeff * v)

    def propagate(vals):
        carry = 0
        digit = [0] * 8
        for j in range(8):
            s = s64(vals[j] + carry)
            digit[j] = s & 0xffffffff
            carry = s >> 32   # arithmetic (floor) shift, matches ASR
        return digit, carry

    digit, carry_final = propagate(acc)
    for j, coeff in TABLE[8].items():
        digit[j] = s64(digit[j] + coeff * carry_final)
    digitp, ext = propagate(digit)

    out = [(digitp[2 * k] | (digitp[2 * k + 1] << 32)) for k in range(4)]
    return out, ext


def canonicalize(r, ext):
    pl = [0xffffffffffffffff, 0x00000000ffffffff, 0, 0xffffffff00000001]
    r = list(r)
    if ext < 0:
        carry = 0
        for k in range(4):
            s = r[k] + pl[k] + carry
            r[k] = s & MASK64
            carry = s >> 64
        ext += carry
    for _ in range(2):
        borrow, cand = 0, [0] * 4
        for k in range(4):
            s = r[k] - pl[k] - borrow
            borrow = 1 if s < 0 else 0
            cand[k] = s & MASK64
        # The assembly's subtraction chain is FIVE limbs wide: after the
        # four `sbcs` over the limbs it runs `sbcs x17, x6, xzr` against
        # ext, and `cset x16, cs` reads the carry out of *that*, not out
        # of limb 3. So the round is taken whenever ext - borrow >= 0,
        # which includes the (ext == 1, borrow == 1) case -- exactly the
        # case a 4-limb-only test refuses. Modelling it as `borrow == 0`
        # made this reference reject values the hardware reduces
        # correctly, and it went unnoticed because a random 512-bit T
        # almost never leaves ext == 1 after the second fold. It is
        # reachable: T = (2^256-1) * 0xffffffffffffffff...ffffffffffffffff
        # (see edge_cases) lands there, and p256_reduce returns the right
        # canonical value for it.
        cand_ext = ext - borrow
        if cand_ext >= 0:
            r, ext = cand, cand_ext
    return r, ext


def reduce_full(T):
    out, ext = reduce_hw(T)
    r, ext = canonicalize(out, ext)
    assert ext == 0, f"ext not zero after correction: {ext}"
    val = sum(r[k] << (64 * k) for k in range(4))
    assert 0 <= val < P
    return val


def edge_cases():
    edge = [0, 1, 2**512 - 1, (P - 1) * (P - 1), (P - 1) * (P - 1) + 1,
            P * P, 2**256, 2**256 - 1, 2**511, 2**480, 2**224, 2**192,
            2**96, P, P - 1, P + 1, 2 * P, 2 * P - 1]
    for shift in range(0, 512, 64):
        edge.append((2**64 - 1) << shift)
        edge.append(1 << shift)
    for nz in range(1, 9):
        edge.append(int('1' * 16 * nz, 16))
    # The one T known to leave ext == 1 after the second fold, i.e. the
    # only case where the correction round's 5-limb `sbcs` against ext
    # is load-bearing. Found by the p256_fe_mul product derivation
    # (scripts/p256_fe_mul_derivation.py) sweeping edge x edge operand
    # pairs; 200k random T never produced it.
    edge.append(((2**256 - 1) *
                 0xffffffffffffffff00000000000000000000000000000000ffffffffffffffff)
                & (2**512 - 1))
    return [x & (2**512 - 1) for x in edge]


def cmd_check(n):
    random.seed(0xC0FFEE)
    fails = 0
    for x in edge_cases() + [random.getrandbits(512) for _ in range(n)]:
        T = [(x >> (64 * k)) & MASK64 for k in range(8)]
        got, want = reduce_full(T), x % P
        if got != want:
            print(f"MISMATCH x={x:#x} got={got:#x} want={want:#x}")
            fails += 1
    print(f"{n} random + {len(edge_cases())} edge cases: {fails} failures")


def cmd_gen_test():
    def c_hex(v):
        return f"0x{v:016x}ULL"

    def emit(x):
        x &= (1 << 512) - 1
        T = [(x >> (64 * k)) & MASK64 for k in range(8)]
        R = [(x % P >> (64 * k)) & MASK64 for k in range(4)]
        return f"    {{ {{ {', '.join(c_hex(v) for v in T)} }}, {{ {', '.join(c_hex(v) for v in R)} }} }},"

    random.seed(0x9E3779B9)
    vecs = edge_cases() + [random.getrandbits(512) for _ in range(250)]
    print("// Unit tests for p256_reduce (P-256 Solinas-style folding reduction)")
    print("//")
    print("// Vectors generated by scripts/p256_reduce_derivation.py gen-test, a")
    print("// Python arbitrary-precision reference (pow(x, 1, p) against the real")
    print("// NIST P-256 prime) -- not derived from this repo's assembly -- so a")
    print("// shared bug would not hide itself. See docs/P256-REDUCE-DERIVATION.md.")
    print()
    print('#include "test_harness.h"')
    print()
    print('extern void p256_reduce(uint64_t out[4], const uint64_t T[8])')
    print('    __asm__("p256_reduce");')
    print()
    print("struct reducevec { uint64_t T[8]; uint64_t r[4]; };")
    print(f"#define NVECS {len(vecs)}")
    print("static const struct reducevec VECS[NVECS] = {")
    for x in vecs:
        print(emit(x))
    print("};")
    print()
    print("static void test_reduce(void) {")
    print('    TEST_SUITE("p256_reduce — T mod p, canonical, against a Python oracle");')
    print()
    print("    for (int i = 0; i < NVECS; i++) {")
    print("        uint64_t out[4];")
    print("        p256_reduce(out, VECS[i].T);")
    print('        ASSERT_EQ("T mod p", 0, memcmp(out, VECS[i].r, sizeof(out)));')
    print("    }")
    print("}")
    print()
    print("int main(void) {")
    print("    test_reduce();")
    print("    test_summary();")
    print("    return 0;")
    print("}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "derive"
    if cmd == "derive":
        cmd_derive()
    elif cmd == "bound":
        cmd_bound()
    elif cmd == "check":
        cmd_check(int(sys.argv[2]) if len(sys.argv) > 2 else 200_000)
    elif cmd == "gen-test":
        cmd_gen_test()
    else:
        print(__doc__)
        sys.exit(2)
