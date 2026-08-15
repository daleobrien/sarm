// P-256 field arithmetic constants

#include "../../defs.S"

.data
.align 4
.global p256_p
p256_p:
    .quad 0xffffffffffffffff
    .quad 0x00000000ffffffff
    .quad 0x0000000000000000
    .quad 0xffffffff00000001

.global p256_mu
p256_mu:
    .quad 0x0000000000000003
    .quad 0xfffffffeffffffff
    .quad 0xfffffffefffffffe
    .quad 0x00000000ffffffff
    .quad 0x0000000000000001

.global p256_p_minus_2
p256_p_minus_2:
    .quad 0xfffffffffffffffd
    .quad 0x00000000ffffffff
    .quad 0x0000000000000000
    .quad 0xffffffff00000001
