#include "../../../defs.S"

rodata
.align 4
// RFC 7748 §5: the X25519 base point, u = 9, little-endian, 32 bytes.
OBJECT x25519_basepoint9
    .byte 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
ENDOBJ x25519_basepoint9
