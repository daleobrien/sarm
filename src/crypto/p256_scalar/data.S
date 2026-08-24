// P-256 scalar ring constants

#include "../../defs.S"

rodata
.align 4
OBJECT p256_n
    .quad 0xf3b9cac2fc632551
    .quad 0xbce6faada7179e84
    .quad 0xffffffffffffffff
    .quad 0xffffffff00000000
ENDOBJ p256_n

OBJECT p256_mu_n
    .quad 0x012ffd85eedf9bfe
    .quad 0x43190552df1a6c21
    .quad 0xfffffffeffffffff
    .quad 0x00000000ffffffff
    .quad 0x0000000000000001
ENDOBJ p256_mu_n

OBJECT p256_n_minus_2
    .quad 0xf3b9cac2fc63254f
    .quad 0xbce6faada7179e84
    .quad 0xffffffffffffffff
    .quad 0xffffffff00000000
ENDOBJ p256_n_minus_2
