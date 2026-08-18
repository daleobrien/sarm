#!/usr/bin/env python3
"""P-256 scalar inversion mod n: Montgomery arithmetic, the addition
chain for n-2, and a hardware-faithful reference implementation.

This is the generator behind `p256_scalar_mont_mul`
(src/crypto/p256_scalar/mont_mul.S), the rewritten `p256_scalar_inv`
(src/crypto/p256_scalar/inv.S) and the constants + chain program it
interprets (src/crypto/p256_scalar/inv_chain.S).

`p256_scalar_inv` computes a^-1 mod n by Fermat, a^(n-2) mod n. That
was already true before this change; what changed is *both* factors of
its cost:

  1. The modular multiply. p256_scalar_mul is a 4x4 product followed by
     a Barrett reduction, and the Barrett step is two more p256_bn_mul
     calls (5x5 and 5x4) -- 45 limb products to reduce a result that
     took only 16 limb products to compute. Montgomery reduction costs
     20 limb products instead of 45, and being a dedicated 4-limb
     routine it also drops p256_bn_mul's generic loop and three
     function calls per multiply.

  2. The exponentiation. Square-and-multiply over the bits of n-2 is
     256 squarings + 169 multiplies = 425 modular multiplications. n-2
     is a public curve constant, so the schedule can be anything at
     all; `build_chain` below emits a fixed addition chain of 302,
     derived from the run structure of n-2 rather than its bits.

Every claim above is checked rather than asserted: `prove` verifies the
chain reconstructs exactly n-2 and that the Montgomery bounds the
assembly relies on actually hold, `check` runs the hardware-faithful
model against Python's own modular inverse, and `interop` runs it
against a real ECDSA signature produced by the `cryptography` package
(OpenSSL), since k^-1 mod n is what signing actually needs it for.

Usage:
    python3 scripts/p256_scalar_inv_derivation.py prove         # chain + Montgomery bound proofs
    python3 scripts/p256_scalar_inv_derivation.py check [N]     # N random + edge cases vs. pow()
    python3 scripts/p256_scalar_inv_derivation.py interop [N]   # N signatures vs. `cryptography`
    python3 scripts/p256_scalar_inv_derivation.py gen-chain     > src/crypto/p256_scalar/inv_chain.S
    python3 scripts/p256_scalar_inv_derivation.py gen-test-mont > tests/unit/test_p256_scalar/mont_mul.c
    python3 scripts/p256_scalar_inv_derivation.py gen-test-inv  > tests/unit/test_p256_scalar/inv.c
"""
import random
import sys

# ── curve parameters (FIPS 186-4, P-256) ─────────────────────────────────
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
E = N - 2                       # the Fermat exponent, a public constant

MASK = (1 << 64) - 1
R = 1 << 256                    # the Montgomery radix
RR = (R * R) % N                # R^2 mod n, the "enter Montgomery form" constant
N0INV = (-pow(N, -1, 1 << 64)) % (1 << 64)      # -n^-1 mod 2^64

NW = [(N >> (64 * i)) & MASK for i in range(4)]


def words(v):
    return [(v >> (64 * i)) & MASK for i in range(4)]


def value(w):
    return sum(x << (64 * i) for i, x in enumerate(w))


# ── the hardware-faithful Montgomery multiply ────────────────────────────
# This is not "a * b * R^-1 % N"; it is the exact word-and-carry sequence
# src/crypto/p256_scalar/mont_mul.S executes, so that a carry-chain bug in
# the assembly is a bug the Python can also have -- and therefore one the
# `check` below can catch, instead of both being right for different
# reasons. The asserts mark the places where the assembly emits *no*
# instruction because the value is provably zero; if one ever fires, the
# assembly is silently dropping a bit.

def mont_mul_hw(aw, bw, audit=None):
    t = [0] * 8

    # Phase 1 -- schoolbook 4x4 product. Each row adds a * b[i] at offset
    # i using two carry chains: the low halves into t[i..i+3], then the
    # high halves into t[i+1..i+4]. t[i+4] is untouched before row i (the
    # partial product a * (b mod 2^(64i)) is < 2^(256+64i)), so the first
    # chain may write it rather than accumulate into it.
    for i in range(4):
        bi = bw[i]
        lo = [0] * 4
        hi = [0] * 4
        for j in range(4):
            pr = aw[j] * bi
            lo[j] = pr & MASK
            hi[j] = pr >> 64

        c = 0
        for j in range(4):
            s = t[i + j] + lo[j] + c
            t[i + j] = s & MASK
            c = s >> 64
        t[i + 4] = c

        c = 0
        for j in range(4):
            s = t[i + 1 + j] + hi[j] + c
            t[i + 1 + j] = s & MASK
            c = s >> 64
        assert c == 0, "product row %d carried past t[%d]" % (i, i + 4)

    assert value(aw) * value(bw) == sum(x << (64 * k) for k, x in enumerate(t))

    # Phase 2 -- Montgomery reduction, four rounds. Round i picks m so
    # that t[i] + m*n[0] == 0 mod 2^64, adds m*n at offset i (five words:
    # four low halves and four high halves, overlapping), then propagates
    # the single word that lands at t[i+4] up through t[7] and into ext.
    ext = 0
    for i in range(4):
        m = (t[i] * N0INV) & MASK
        lo = [0] * 4
        hi = [0] * 4
        for j in range(4):
            pr = m * NW[j]
            lo[j] = pr & MASK
            hi[j] = pr >> 64

        c = 0
        for j in range(4):
            s = t[i + j] + lo[j] + c
            t[i + j] = s & MASK
            c = s >> 64
        assert t[i] == 0, "round %d did not zero t[%d]" % (i, i)
        c1 = c

        c = 0
        for j in range(3):
            s = t[i + 1 + j] + hi[j] + c
            t[i + 1 + j] = s & MASK
            c = s >> 64
        s = c1 + hi[3] + c
        c1 = s & MASK
        c2 = s >> 64
        assert c2 <= 1

        # (c2:c1) is the two-word carry to deposit at t[i+4]. Positions
        # above that only ever receive a propagating carry bit.
        s = t[i + 4] + c1
        t[i + 4] = s & MASK
        c = s >> 64
        s = (t[i + 5] if i + 5 <= 7 else ext) + c2 + c
        if i + 5 <= 7:
            t[i + 5] = s & MASK
        else:
            ext = s
        c = s >> 64
        for k in range(i + 6, 8):
            s = t[k] + c
            t[k] = s & MASK
            c = s >> 64
        if i + 6 <= 8:
            ext += c
        assert ext <= 1, "reduction overflowed the 5th result word"

    res = t[4:8]
    resv = value(res) + (ext << 256)
    assert resv < 2 * N, "Montgomery output not < 2n -- one subtract is not enough"

    # One conditional subtraction is all that is ever needed, and the
    # borrow out of the 5th word is what decides it.
    d = [0] * 4
    borrow = 0
    for j in range(4):
        s = res[j] - NW[j] - borrow
        d[j] = s & MASK
        borrow = 1 if s < 0 else 0
    borrow = 1 if ext - borrow < 0 else 0
    out = res if borrow else d

    if audit is not None:
        audit["ext"] = ext
        audit["subtracted"] = not borrow
    val = value(out)
    assert val < N
    assert val == (value(aw) * value(bw) * pow(R, -1, N)) % N
    return out


def mont_mul(a, b):
    """Integer-level convenience wrapper around the word-level model."""
    return value(mont_mul_hw(words(a), words(b)))


# ── the addition chain for n-2 ───────────────────────────────────────────
# n-2 is a public constant, so the schedule is free to be anything. Its
# binary form is a 32-bit run of ones, 32 zeros, a 65-bit run of ones,
# then 128 bits of no structure at all:
#
#   n-2 = 0xffffffff 00000000 ffffffffffffffff  bce6faada7179e84f3b9cac2fc63254f
#
# so the chain is built around x^(2^k - 1) ("k ones") values. The low 128
# bits decompose into 33 runs of ones, none longer than 6, which is why
# the ladder stops at ones6 for the low half; ones8/16/32 exist only to
# serve the two long runs up top. The 65-run is covered by applying
# ones32 twice and then a single ones1, which is two multiplies more than
# building ones65 would cost but 35 chain steps cheaper.
#
# Slot numbering below is the table index the assembly uses.
SLOT = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5, 8: 6, 16: 7, 32: 8}
ACC = 9
NSLOTS = 10
NO_MUL = 0xFF


def build_chain():
    """Return a list of (dst, src, nsq, mul) instructions.

    Each means: t = src; square t nsq times; if mul != NO_MUL multiply t
    by slot `mul`; store t into slot `dst`. nsq is always >= 1, so the
    first squaring can read `src` and write `dst` directly and no slot
    copy instruction is needed.
    """
    prog = []

    # Ladder: ones2..ones6 one bit at a time, then doubling up to ones32.
    for k in (2, 3, 4, 5, 6):
        prog.append((SLOT[k], SLOT[k - 1], 1, SLOT[1]))
    for k in (8, 16, 32):
        prog.append((SLOT[k], SLOT[k // 2], k // 2, SLOT[k // 2]))

    # Main pass. The accumulator starts as ones32 (the top 32 one-bits),
    # which the first instruction reads directly.
    bits = bin(E)[2:]
    assert len(bits) == 256
    assert bits[:32] == "1" * 32 and bits[32:64] == "0" * 32
    assert bits[64:129] == "1" * 65

    prog.append((ACC, SLOT[32], 32, NO_MUL))    # 32 zero bits
    prog.append((ACC, ACC, 32, SLOT[32]))       # 65 ones, first 32
    prog.append((ACC, ACC, 32, SLOT[32]))       # ... next 32
    prog.append((ACC, ACC, 1, SLOT[1]))         # ... and the 65th

    # The unstructured low 128 bits, one instruction per run of ones:
    # shift past the preceding zeros and the run itself, then multiply in
    # ones<runlength>.
    low = bits[129:]
    i = 0
    pending = 0
    while i < len(low):
        if low[i] == "0":
            pending += 1
            i += 1
            continue
        j = i
        while j < len(low) and low[j] == "1":
            j += 1
        run = j - i
        assert run in SLOT, "low half has a %d-run, not in the ladder" % run
        prog.append((ACC, ACC, pending + run, SLOT[run]))
        pending = 0
        i = j
    assert pending == 0, "n-2 ends in a zero bit -- trailing shift unhandled"
    return prog


def run_chain(x, prog, mul=lambda a, b: None):
    """Execute `prog` over an opaque multiply. Used twice: with integer
    exponents to prove what the chain computes, and with mont_mul to
    compute it."""
    slots = [None] * NSLOTS
    slots[SLOT[1]] = x
    for dst, src, nsq, m in prog:
        t = slots[src]
        for _ in range(nsq):
            t = mul(t, t)
        if m != NO_MUL:
            t = mul(t, slots[m])
        slots[dst] = t
    return slots[ACC]


def chain_cost(prog):
    sq = sum(nsq for _, _, nsq, _ in prog)
    ml = sum(1 for _, _, _, m in prog if m != NO_MUL)
    return sq, ml


# ── the reference inversion, structured exactly as the assembly ──────────
def scalar_inv_hw(a):
    """a^-1 mod n, following src/crypto/p256_scalar/inv.S step for step."""
    x = a % N                                   # p256_scalar_reduce
    xm = mont_mul(x, RR)                        # enter Montgomery form
    prog = build_chain()
    accm = run_chain(xm, prog, mont_mul)
    return mont_mul(accm, 1)                    # leave Montgomery form


# ── proofs ───────────────────────────────────────────────────────────────
def prove():
    print("n      =", hex(N))
    print("n-2    =", hex(E))
    print("R^2%%n  =", hex(RR))
    print("n0inv  =", hex(N0INV))
    print()

    prog = build_chain()
    sq, ml = chain_cost(prog)
    print("chain: %d instructions, %d squarings + %d multiplies = %d "
          "modular multiplications" % (len(prog), sq, ml, sq + ml))
    naive = 256 + bin(E).count("1")
    print("       (square-and-multiply over the bits of n-2 is 256 + %d = "
          "%d, so %.1f%% fewer)" % (bin(E).count("1"), naive,
                                    100.0 * (naive - sq - ml) / naive))

    # 1. The chain computes exactly n-2, checked on the exponents
    #    themselves rather than on sampled outputs: run it with "multiply"
    #    replaced by integer addition, so each slot literally holds the
    #    exponent it stands for.
    e = run_chain(1, prog, lambda a, b: a + b)
    assert e == E, "chain builds %s, wanted %s" % (hex(e), hex(E))
    print("\n[1] chain exponent == n-2 exactly (integer-exponent replay)")

    # Every slot the program reads must have been written first, and every
    # ones<k> slot must actually hold 2^k - 1.
    written = {SLOT[1]}
    for dst, src, nsq, m in prog:
        assert src in written, "instruction reads unwritten slot %d" % src
        assert m == NO_MUL or m in written, "multiply by unwritten slot %d" % m
        assert nsq >= 1, "instruction with no squaring needs a slot copy"
        written.add(dst)
    slots = [None] * NSLOTS
    slots[SLOT[1]] = 1
    for dst, src, nsq, m in prog:
        t = slots[src] * (1 << nsq)
        if m != NO_MUL:
            t += slots[m]
        slots[dst] = t
    for k, s in SLOT.items():
        assert slots[s] == (1 << k) - 1, "slot ones%d holds %s" % (k, hex(slots[s]))
    print("[2] every read is of an already-written slot; each ones<k> "
          "slot holds 2^k - 1")

    # 3. The Montgomery bounds the assembly relies on. mont_mul_hw asserts
    #    them internally on every call (product row carries stay inside
    #    five words, each round zeroes its own limb, the 5th result word
    #    never exceeds 1, the output is < 2n so a single conditional
    #    subtract suffices); drive it with the extremes plus randoms.
    rng = random.Random(20260818)
    edge = [0, 1, 2, N - 1, N - 2, RR, MASK, R - 1, (1 << 255), N - (1 << 32)]
    cases = [(a % N, b % N) for a in edge for b in edge]
    cases += [(rng.randrange(N), rng.randrange(N)) for _ in range(4000)]
    cases += [(N - 1 - rng.randrange(1 << 32), N - 1 - rng.randrange(1 << 32))
              for _ in range(1000)]
    nsub = 0
    maxext = 0
    for a, b in cases:
        audit = {}
        got = value(mont_mul_hw(words(a), words(b), audit))
        assert got == (a * b * pow(R, -1, N)) % N
        nsub += audit["subtracted"]
        maxext = max(maxext, audit["ext"])
    print("[3] Montgomery model held on %d products (%d needed the "
          "conditional subtract, max 5th word = %d)" % (len(cases), nsub, maxext))

    # 4. End to end, through the exact structure of inv.S.
    tests = [1, 2, 3, N - 1, N - 2, N // 2, R - 1, N, N + 1]
    tests += [rng.randrange(1, N) for _ in range(200)]
    for a in tests:
        want = pow(a % N, N - 2, N)
        got = scalar_inv_hw(a)
        assert got == want, hex(a)
        if a % N:
            assert (got * a) % N == 1
    print("[4] hardware-faithful inversion == pow(a, n-2, n) on %d inputs, "
          "including a >= n and a == n" % len(tests))
    print("\nall proofs passed")


def check(count):
    count = count or 2000
    rng = random.Random(4242)
    vals = [0, 1, 2, N - 1, N - 2, N, N + 1, R - 1, RR]
    vals += [rng.randrange(1, N) for _ in range(count)]
    for a in vals:
        want = pow(a % N, N - 2, N)
        got = scalar_inv_hw(a)
        assert got == want, "a=%s got=%s want=%s" % (hex(a), hex(got), hex(want))
    print("%d inversions match pow(a mod n, n-2, n)" % len(vals))


def interop(count):
    """Sign with `cryptography` (OpenSSL), recover k, and confirm that the
    model's k^-1 is the value the real signature was built from. This
    checks the inversion against an independent implementation on the one
    computation the server actually uses it for."""
    count = count or 200
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes

    rng = random.Random(99)
    ok = 0
    for _ in range(count):
        key = ec.generate_private_key(ec.SECP256R1())
        d = key.private_numbers().private_value
        msg = bytes(rng.randrange(256) for _ in range(32))
        sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(sig)
        dg = hashes.Hash(hashes.SHA256())
        dg.update(msg)
        z = int.from_bytes(dg.finalize(), "big") % N

        # s = k^-1 (z + r*d) mod n, so k = s^-1 (z + r*d) mod n. Invert s
        # with the model, rebuild k, then invert k with the model too and
        # confirm it reproduces s.
        sinv = scalar_inv_hw(s)
        assert (sinv * s) % N == 1
        k = (sinv * (z + r * d)) % N
        kinv = scalar_inv_hw(k)
        assert (kinv * (z + r * d)) % N == s, "model k^-1 does not rebuild s"
        ok += 1
    print("%d OpenSSL signatures round-tripped through the model's "
          "inversion" % ok)


# ── generators ───────────────────────────────────────────────────────────
GEN_CMD = "python3 scripts/p256_scalar_inv_derivation.py"


def quads(v, indent="    "):
    return "\n".join("%s.quad 0x%016x" % (indent, w) for w in words(v))


def gen_chain():
    prog = build_chain()
    sq, ml = chain_cost(prog)
    out = []
    out.append("// P-256 scalar-inversion constants and addition chain")
    out.append("//")
    out.append("// GENERATED FILE -- do not edit by hand. Regenerate with:")
    out.append("//   %s gen-chain > src/crypto/p256_scalar/inv_chain.S" % GEN_CMD)
    out.append("//")
    out.append("// p256_scalar_inv_chain is the program p256_scalar_inv")
    out.append("// (src/crypto/p256_scalar/inv.S) interprets. Four bytes per")
    out.append("// instruction -- dst slot, src slot, squaring count, multiply")
    out.append("// slot (0xFF for none) -- meaning:")
    out.append("//")
    out.append("//     t = slot[src]; t = t^(2^nsq); if mul != 0xFF: t *= slot[mul]")
    out.append("//     slot[dst] = t")
    out.append("//")
    out.append("// with every multiply a Montgomery multiply, so the whole run")
    out.append("// stays in Montgomery form. nsq is always >= 1, which is why")
    out.append("// there is no slot-copy opcode: the first squaring reads src")
    out.append("// and writes dst. A dst of 0xFF terminates the program.")
    out.append("//")
    out.append("// Slots 0..8 hold x^(2^k - 1) for k = 1,2,3,4,5,6,8,16,32 and")
    out.append("// slot 9 is the accumulator. %d instructions, %d squarings +"
               % (len(prog), sq))
    out.append("// %d multiplies = %d Montgomery multiplications, against the"
               % (ml, sq + ml))
    out.append("// %d of square-and-multiply over the bits of n-2."
               % (256 + bin(E).count("1")))
    out.append("")
    out.append("#include \"../../defs.S\"")
    out.append("")
    out.append(".data")
    out.append(".align 4")
    out.append("")
    out.append("// R^2 mod n, R = 2^256 -- multiplying by this in Montgomery")
    out.append("// form is what converts a plain scalar into Montgomery form.")
    out.append(".global p256_scalar_rr_n")
    out.append("p256_scalar_rr_n:")
    out.append(quads(RR))
    out.append("")
    out.append("// -n^-1 mod 2^64, the Montgomery reduction multiplier.")
    out.append(".global p256_scalar_n0inv")
    out.append("p256_scalar_n0inv:")
    out.append("    .quad 0x%016x" % N0INV)
    out.append("")
    out.append(".align 4")
    out.append(".global p256_scalar_inv_chain")
    out.append("p256_scalar_inv_chain:")

    names = {v: "ones%d" % k for k, v in SLOT.items()}
    names[ACC] = "acc"
    for dst, src, nsq, m in prog:
        mtxt = "0xFF" if m == NO_MUL else "%4d" % m
        desc = "%s = %s^(2^%d)" % (names[dst], names[src], nsq)
        if m != NO_MUL:
            desc += " * %s" % names[m]
        out.append("    .byte %4d, %4d, %4d, %s   // %s"
                   % (dst, src, nsq, mtxt, desc))
    out.append("    .byte 0xFF, 0xFF, 0xFF, 0xFF   // end of program")
    out.append("")
    return "\n".join(out)


def c_bytes(v, per=8, indent="      "):
    b = v.to_bytes(32, "big")
    rows = ["0x%02x," % x for x in b]
    return "\n".join(indent + " ".join(rows[i:i + per]) for i in range(0, 32, per))


def gen_test_mont():
    rng = random.Random(1234)
    edge = [(0, 0), (1, 1), (1, RR), (0, RR), (N - 1, N - 1), (N - 1, RR),
            (RR, RR), (2, RR), (N - 1, 1), (1, N - 1), (N // 2, N // 2),
            (N - 1, N - 2), ((1 << 255), RR), (MASK, RR)]
    cases = [(a % N, b % N) for a, b in edge]
    cases += [(rng.randrange(N), rng.randrange(N)) for _ in range(30)]

    out = []
    out.append("// Unit tests for p256_scalar_mont_mul -- Montgomery multiplication")
    out.append("// mod n (out = a * b * R^-1 mod n, R = 2^256).")
    out.append("//")
    out.append("// GENERATED FILE -- do not edit by hand. Regenerate with:")
    out.append("//   %s gen-test-mont \\" % GEN_CMD)
    out.append("//       > tests/unit/test_p256_scalar/mont_mul.c")
    out.append("//")
    out.append("// Expected values come from Python big-integer arithmetic against")
    out.append("// the published order n, not from the assembly under test. The")
    out.append("// vectors deliberately include the operand pairs that stress the")
    out.append("// carry chains -- both operands near n-1, values above 2^255, and")
    out.append("// the R^2 constant the real entry-to-Montgomery step uses.")
    out.append("")
    out.append("#include \"test_harness.h\"")
    out.append("")
    out.append("extern void p256_scalar_mont_mul(uint64_t out[4], const uint64_t a[4],")
    out.append("                                 const uint64_t b[4])")
    out.append("    __asm__(\"p256_scalar_mont_mul\");")
    out.append("extern void p256_fe_frombytes(uint64_t out[4], const uint8_t in[32])")
    out.append("    __asm__(\"p256_fe_frombytes\");")
    out.append("extern void p256_fe_tobytes(uint8_t out[32], const uint64_t in[4])")
    out.append("    __asm__(\"p256_fe_tobytes\");")
    out.append("")
    out.append("struct mmvec { uint8_t a[32], b[32], want[32]; };")
    out.append("#define NMM %d" % len(cases))
    out.append("static const struct mmvec MMS[NMM] = {")
    for a, b in cases:
        want = (a * b * pow(R, -1, N)) % N
        out.append("    { {")
        out.append(c_bytes(a))
        out.append("    }, {")
        out.append(c_bytes(b))
        out.append("    }, {")
        out.append(c_bytes(want))
        out.append("    } },")
    out.append("};")
    out.append("")
    out.append("static void test_mont_mul(void) {")
    out.append("    TEST_SUITE(\"p256_scalar_mont_mul — a*b*R^-1 mod n\");")
    out.append("    for (int i = 0; i < NMM; i++) {")
    out.append("        uint64_t a[4], b[4], out[4];")
    out.append("        uint8_t outb[32];")
    out.append("        p256_fe_frombytes(a, MMS[i].a);")
    out.append("        p256_fe_frombytes(b, MMS[i].b);")
    out.append("        p256_scalar_mont_mul(out, a, b);")
    out.append("        p256_fe_tobytes(outb, out);")
    out.append("        ASSERT_EQ(\"a*b*R^-1 mod n\", 0, memcmp(outb, MMS[i].want, 32));")
    out.append("    }")
    out.append("")
    out.append("    // out may alias either input: the routine loads both operands")
    out.append("    // into registers up front and stores only at the end.")
    out.append("    for (int i = 0; i < NMM; i++) {")
    out.append("        uint64_t a[4], b[4];")
    out.append("        uint8_t outb[32];")
    out.append("        p256_fe_frombytes(a, MMS[i].a);")
    out.append("        p256_fe_frombytes(b, MMS[i].b);")
    out.append("        p256_scalar_mont_mul(a, a, b);")
    out.append("        p256_fe_tobytes(outb, a);")
    out.append("        ASSERT_EQ(\"aliasing out == a\", 0, memcmp(outb, MMS[i].want, 32));")
    out.append("        p256_fe_frombytes(a, MMS[i].a);")
    out.append("        p256_fe_frombytes(b, MMS[i].b);")
    out.append("        p256_scalar_mont_mul(b, a, b);")
    out.append("        p256_fe_tobytes(outb, b);")
    out.append("        ASSERT_EQ(\"aliasing out == b\", 0, memcmp(outb, MMS[i].want, 32));")
    out.append("        p256_fe_frombytes(a, MMS[i].a);")
    out.append("        p256_scalar_mont_mul(a, a, a);")
    out.append("        p256_fe_tobytes(outb, a);")
    out.append("        uint64_t sq[4], a2[4];")
    out.append("        p256_fe_frombytes(a2, MMS[i].a);")
    out.append("        p256_scalar_mont_mul(sq, a2, a2);")
    out.append("        uint8_t sqb[32];")
    out.append("        p256_fe_tobytes(sqb, sq);")
    out.append("        ASSERT_EQ(\"aliasing out == a == b\", 0, memcmp(outb, sqb, 32));")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("int main(void) {")
    out.append("    test_mont_mul();")
    out.append("    test_summary();")
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out)


def gen_test_inv():
    rng = random.Random(777)
    vals = [1, 2, 3, 4, 7, 0x10, 0xFF,
            N - 1, N - 2, N - 3, N // 2, N // 2 + 1,
            0, N, N + 1, N + 2,               # reduce-to-0 and wrap cases
            R - 1,                            # 2^256-1, above n
            1 << 255, (1 << 255) - 1,
            RR, N0INV]
    vals += [rng.randrange(1, N) for _ in range(24)]

    out = []
    out.append("// Unit tests for p256_scalar_inv — scalar inversion mod n, the")
    out.append("// P-256 group order.")
    out.append("//")
    out.append("// GENERATED FILE -- do not edit by hand. Regenerate with:")
    out.append("//   %s gen-test-inv \\" % GEN_CMD)
    out.append("//       > tests/unit/test_p256_scalar/inv.c")
    out.append("//")
    out.append("// Expected values are computed independently in Python against the")
    out.append("// real published order n, not derived from the assembly under test.")
    out.append("// The inputs cover the whole 4-limb range rather than just [1, n-1]:")
    out.append("// p256_ecdsa_sign_with_k feeds its nonce straight from")
    out.append("// p256_fe_frombytes without reducing mod n first, so 0, n, n+1 and")
    out.append("// 2^256-1 are all reachable and must behave as (a mod n)^(n-2).")
    out.append("")
    out.append("#include \"test_harness.h\"")
    out.append("")
    out.append("extern void p256_scalar_inv(uint64_t out[4], const uint64_t a[4])")
    out.append("    __asm__(\"p256_scalar_inv\");")
    out.append("extern void p256_scalar_mul(uint64_t out[4], const uint64_t a[4],")
    out.append("                            const uint64_t b[4])")
    out.append("    __asm__(\"p256_scalar_mul\");")
    out.append("extern void p256_fe_frombytes(uint64_t out[4], const uint8_t in[32])")
    out.append("    __asm__(\"p256_fe_frombytes\");")
    out.append("extern void p256_fe_tobytes(uint8_t out[32], const uint64_t in[4])")
    out.append("    __asm__(\"p256_fe_tobytes\");")
    out.append("")
    out.append("struct scinvvec { uint8_t a[32], inv[32]; };")
    out.append("#define NSCINV %d" % len(vals))
    out.append("static const struct scinvvec SCINVS[NSCINV] = {")
    for a in vals:
        inv = pow(a % N, N - 2, N)
        out.append("    { {")
        out.append(c_bytes(a % (1 << 256)))
        out.append("    }, {")
        out.append(c_bytes(inv))
        out.append("    } },")
    out.append("};")
    out.append("")
    out.append("static void test_inv(void) {")
    out.append("    TEST_SUITE(\"p256_scalar_inv — a^-1 mod n\");")
    out.append("    for (int i = 0; i < NSCINV; i++) {")
    out.append("        uint64_t a[4], out[4];")
    out.append("        uint8_t outb[32];")
    out.append("        p256_fe_frombytes(a, SCINVS[i].a);")
    out.append("        p256_scalar_inv(out, a);")
    out.append("        p256_fe_tobytes(outb, out);")
    out.append("        ASSERT_EQ(\"a^-1 mod n\", 0, memcmp(outb, SCINVS[i].inv, 32));")
    out.append("    }")
    out.append("")
    out.append("    // Independent of the vectors above: a * a^-1 must be 1 mod n,")
    out.append("    // checked through p256_scalar_mul, which shares no code with")
    out.append("    // the Montgomery path p256_scalar_inv now runs on.")
    out.append("    for (int i = 0; i < NSCINV; i++) {")
    out.append("        uint64_t a[4], ainv[4], one[4];")
    out.append("        uint8_t oneb[32];")
    out.append("        p256_fe_frombytes(a, SCINVS[i].a);")
    out.append("        int zero = 1;")
    out.append("        for (int j = 0; j < 32; j++) if (SCINVS[i].inv[j]) zero = 0;")
    out.append("        if (zero) continue;          // a == 0 mod n has no inverse")
    out.append("        p256_scalar_inv(ainv, a);")
    out.append("        p256_scalar_mul(one, a, ainv);")
    out.append("        p256_fe_tobytes(oneb, one);")
    out.append("        int ok = (oneb[31] == 1);")
    out.append("        for (int j = 0; j < 31; j++) if (oneb[j] != 0) ok = 0;")
    out.append("        ASSERT_EQ(\"a * a^-1 == 1\", 1, ok);")
    out.append("    }")
    out.append("}")
    out.append("")
    out.append("int main(void) {")
    out.append("    test_inv();")
    out.append("    test_summary();")
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 else None
    if cmd == "prove":
        prove()
    elif cmd == "check":
        check(arg)
    elif cmd == "interop":
        interop(arg)
    elif cmd == "gen-chain":
        print(gen_chain())
    elif cmd == "gen-test-mont":
        print(gen_test_mont())
    elif cmd == "gen-test-inv":
        print(gen_test_inv())
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
