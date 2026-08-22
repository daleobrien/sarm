// P-256 scalar-inversion constants and addition chain
//
// GENERATED FILE -- do not edit by hand. Regenerate with:
//   python3 scripts/p256_scalar_inv_derivation.py gen-chain > src/crypto/p256_scalar/inv_chain.S
//
// p256_scalar_inv_chain is the program p256_scalar_inv
// (src/crypto/p256_scalar/inv.S) interprets. Four bytes per
// instruction -- dst slot, src slot, squaring count, multiply
// slot (0xFF for none) -- meaning:
//
//     t = slot[src]; t = t^(2^nsq); if mul != 0xFF: t *= slot[mul]
//     slot[dst] = t
//
// with every multiply a Montgomery multiply, so the whole run
// stays in Montgomery form. nsq is always >= 1, which is why
// there is no slot-copy opcode: the first squaring reads src
// and writes dst. A dst of 0xFF terminates the program.
//
// Slots 0..8 hold x^(2^k - 1) for k = 1,2,3,4,5,6,8,16,32 and
// slot 9 is the accumulator. 44 instructions, 257 squarings +
// 43 multiplies = 300 Montgomery multiplications, against the
// 425 of square-and-multiply over the bits of n-2.

#include "../../defs.S"

rodata
.align 4

// R^2 mod n, R = 2^256 -- multiplying by this in Montgomery
// form is what converts a plain scalar into Montgomery form.
.global p256_scalar_rr_n
p256_scalar_rr_n:
    .quad 0x83244c95be79eea2
    .quad 0x4699799c49bd6fa6
    .quad 0x2845b2392b6bec59
    .quad 0x66e12d94f3d95620

// -n^-1 mod 2^64, the Montgomery reduction multiplier.
.global p256_scalar_n0inv
p256_scalar_n0inv:
    .quad 0xccd1c8aaee00bc4f

.align 4
.global p256_scalar_inv_chain
p256_scalar_inv_chain:
    .byte    1,    0,    1,    0   // ones2 = ones1^(2^1) * ones1
    .byte    2,    1,    1,    0   // ones3 = ones2^(2^1) * ones1
    .byte    3,    2,    1,    0   // ones4 = ones3^(2^1) * ones1
    .byte    4,    3,    1,    0   // ones5 = ones4^(2^1) * ones1
    .byte    5,    4,    1,    0   // ones6 = ones5^(2^1) * ones1
    .byte    6,    3,    4,    3   // ones8 = ones4^(2^4) * ones4
    .byte    7,    6,    8,    6   // ones16 = ones8^(2^8) * ones8
    .byte    8,    7,   16,    7   // ones32 = ones16^(2^16) * ones16
    .byte    9,    8,   32, 0xFF   // acc = ones32^(2^32)
    .byte    9,    9,   32,    8   // acc = acc^(2^32) * ones32
    .byte    9,    9,   32,    8   // acc = acc^(2^32) * ones32
    .byte    9,    9,    1,    0   // acc = acc^(2^1) * ones1
    .byte    9,    9,    5,    3   // acc = acc^(2^5) * ones4
    .byte    9,    9,    5,    2   // acc = acc^(2^5) * ones3
    .byte    9,    9,    4,    1   // acc = acc^(2^4) * ones2
    .byte    9,    9,    6,    4   // acc = acc^(2^6) * ones5
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    3,    1   // acc = acc^(2^3) * ones2
    .byte    9,    9,    3,    1   // acc = acc^(2^3) * ones2
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    5,    2   // acc = acc^(2^5) * ones3
    .byte    9,    9,    4,    0   // acc = acc^(2^4) * ones1
    .byte    9,    9,    5,    3   // acc = acc^(2^5) * ones4
    .byte    9,    9,    6,    3   // acc = acc^(2^6) * ones4
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    5,    0   // acc = acc^(2^5) * ones1
    .byte    9,    9,    6,    3   // acc = acc^(2^6) * ones4
    .byte    9,    9,    5,    2   // acc = acc^(2^5) * ones3
    .byte    9,    9,    4,    2   // acc = acc^(2^4) * ones3
    .byte    9,    9,    5,    2   // acc = acc^(2^5) * ones3
    .byte    9,    9,    3,    0   // acc = acc^(2^3) * ones1
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    3,    1   // acc = acc^(2^3) * ones2
    .byte    9,    9,    5,    0   // acc = acc^(2^5) * ones1
    .byte    9,    9,    7,    5   // acc = acc^(2^7) * ones6
    .byte    9,    9,    5,    1   // acc = acc^(2^5) * ones2
    .byte    9,    9,    5,    1   // acc = acc^(2^5) * ones2
    .byte    9,    9,    3,    0   // acc = acc^(2^3) * ones1
    .byte    9,    9,    3,    0   // acc = acc^(2^3) * ones1
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    2,    0   // acc = acc^(2^2) * ones1
    .byte    9,    9,    6,    3   // acc = acc^(2^6) * ones4
    .byte 0xFF, 0xFF, 0xFF, 0xFF   // end of program

