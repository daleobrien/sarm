#include "../../../defs.S"

.data
.align 4
// RFC 7748 §5: the X25519 base point, u = 9, little-endian, 32 bytes.
.global x25519_basepoint9
x25519_basepoint9:
    .byte 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
