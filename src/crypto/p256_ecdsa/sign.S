// P-256 ECDSA signing with supplied nonce

#include "../../defs.S"

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_ecdsa_sign_with_k
//
// Description: Produce an ECDSA signature (r,s) over a 32-byte hash
//   with private key d and nonce k, all as big-endian byte arrays.
//   The nonce k is supplied by the caller (not generated here) to allow
//   testing and to keep the CSPRNG concern at the caller's layer.
//
// Algorithm:
//   z = hash mod n
//   (Rx,Ry) = k*G  (p256_point_mul_base, the fixed-base comb)
//   r = Rx mod n                 -- fail if r == 0
//   s = k^-1 * (z + r*d) mod n   -- fail if s == 0
//
// Input/Arguments:
//   x0 — sig_r out (32 bytes), x1 — sig_s out (32 bytes)
//   x2 — hash (32 bytes), x3 — d, the private key (32 bytes)
//   x4 — k, the nonce (32 bytes)
//
// Output/Returns:
//   x0 — 0 on success, 1 on failure (r == 0 or s == 0; probability
//        ~2^-256 for a valid random k — the caller should treat this
//        as "generate a fresh k and retry", per FIPS 186-4)
//
// Stack Usage:
//   416 bytes: saved x29/x30, 3 pairs of saved x19-x24, 11 4-limb
//   scratch slots
// ─────────────────────────────────────────────────────────────────────

.text
.align 2

FUNC p256_ecdsa_sign_with_k
    sub     sp, sp, #416
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    // scratch slots start at sp+64, 32 bytes each:
    // 0 hash  1 d  2 k  3 z  4 Rx  5 Ry  6 r  7 kinv  8 rd  9 t  10 s

    mov     x19, x0                 // sig_r out
    mov     x20, x1                 // sig_s out
    mov     x21, x2                 // hash ptr
    mov     x22, x3                 // d ptr
    mov     x23, x4                 // k ptr

#define ESLOT(i) (64 + 32*(i))

    add     x0, sp, #ESLOT(0)
    mov     x1, x21
    bl      p256_fe_frombytes       // hash_limbs
    add     x0, sp, #ESLOT(1)
    mov     x1, x22
    bl      p256_fe_frombytes       // d_limbs
    add     x0, sp, #ESLOT(2)
    mov     x1, x23
    bl      p256_fe_frombytes       // k_limbs

    add     x0, sp, #ESLOT(3)
    add     x1, sp, #ESLOT(0)
    bl      p256_scalar_reduce      // z = hash mod n

    add     x0, sp, #ESLOT(4)       // Rx
    add     x1, sp, #ESLOT(5)       // Ry
    add     x2, sp, #ESLOT(2)       // k
    bl      p256_point_mul_base     // (Rx,Ry) = k*G

    add     x0, sp, #ESLOT(6)
    add     x1, sp, #ESLOT(4)
    bl      p256_scalar_reduce      // r = Rx mod n

    ldr     x9, [sp, #ESLOT(6) + 0]
    ldr     x10, [sp, #ESLOT(6) + 8]
    orr     x9, x9, x10
    ldr     x10, [sp, #ESLOT(6) + 16]
    orr     x9, x9, x10
    ldr     x10, [sp, #ESLOT(6) + 24]
    orr     x9, x9, x10
    cbz     x9, .Lsign_fail         // r == 0

    add     x0, sp, #ESLOT(7)
    add     x1, sp, #ESLOT(2)
    bl      p256_scalar_inv         // kinv = k^-1 mod n

    add     x0, sp, #ESLOT(8)
    add     x1, sp, #ESLOT(6)
    add     x2, sp, #ESLOT(1)
    bl      p256_scalar_mul         // rd = r*d mod n

    add     x0, sp, #ESLOT(9)
    add     x1, sp, #ESLOT(3)
    add     x2, sp, #ESLOT(8)
    bl      p256_scalar_add         // t = z+rd mod n

    add     x0, sp, #ESLOT(10)
    add     x1, sp, #ESLOT(7)
    add     x2, sp, #ESLOT(9)
    bl      p256_scalar_mul         // s = kinv*t mod n

    ldr     x9, [sp, #ESLOT(10) + 0]
    ldr     x10, [sp, #ESLOT(10) + 8]
    orr     x9, x9, x10
    ldr     x10, [sp, #ESLOT(10) + 16]
    orr     x9, x9, x10
    ldr     x10, [sp, #ESLOT(10) + 24]
    orr     x9, x9, x10
    cbz     x9, .Lsign_fail         // s == 0

    mov     x0, x19
    add     x1, sp, #ESLOT(6)
    bl      p256_fe_tobytes         // sig_r = r
    mov     x0, x20
    add     x1, sp, #ESLOT(10)
    bl      p256_fe_tobytes         // sig_s = s

    mov     x0, #0
    b       .Lsign_done

.Lsign_fail:
    mov     x0, #1

.Lsign_done:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #416
    ret

#undef ESLOT
ENDFUNC p256_ecdsa_sign_with_k
