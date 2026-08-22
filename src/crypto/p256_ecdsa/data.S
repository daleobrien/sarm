// P-256 ECDSA data constants

#include "../../defs.S"

rodata
.align 4
// The P-256 base point G, little-endian 64-bit limbs.
.global p256_gx
p256_gx:
    .quad 0xf4a13945d898c296
    .quad 0x77037d812deb33a0
    .quad 0xf8bce6e563a440f2
    .quad 0x6b17d1f2e12c4247

.global p256_gy
p256_gy:
    .quad 0xcbb6406837bf51f5
    .quad 0x2bce33576b315ece
    .quad 0x8ee7eb4a7c0f9e16
    .quad 0x4fe342e2fe1a7f9b

// The P-256 curve equation constant b (y^2 = x^3 - 3x + b mod p).
.global p256_b
p256_b:
    .quad 0x3bce3c3e27d2604b
    .quad 0x651d06b0cc53b0f6
    .quad 0xb3ebbd55769886bc
    .quad 0x5ac635d8aa3a93e7
