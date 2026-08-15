// ====================================================================
// ARM64 (AArch64) ECDSA P-256 sign/verify for ymawky
// (PLAN.MD Phase 16.5/16.6)
// File: p256_ecdsa.S
//
//   p256_ecdsa_sign_with_k — ECDSA signing (RFC 6979 §2.4 / FIPS
//                            186-4, with the nonce k supplied by the
//                            caller rather than generated here)
//   p256_ecdsa_verify      — ECDSA signature verification
//
// ── Why "sign_with_k" instead of "sign" ─────────────────────────────
// Real signing needs a fresh, secret, uniformly-random nonce k per
// signature (reusing k, or a biased/predictable k, leaks the private
// key — the classic ECDSA nonce attack). Taking k as an explicit
// parameter here keeps that concern (and the CSPRNG call) at the
// caller, and makes this function's math independently testable
// against known-k vectors without needing to intercept a random
// source. The Phase 17 CertificateVerify wiring is expected to source
// k from crypto_random_bytes (src/crypto/random.S) and call this.
//
// ── Algorithm ────────────────────────────────────────────────────────
// Sign:   z = hash mod n
//         (Rx,Ry) = k*G  (p256_point_mul)
//         r = Rx mod n                 -- fail if r == 0
//         s = k^-1 * (z + r*d) mod n   -- fail if s == 0
// Verify: reject if r or s not in [1, n-1]
//         reject if Q isn't on the curve (y^2 = x^3 - 3x + b mod p)
//         z = hash mod n
//         w = s^-1 mod n
//         u1 = z*w mod n, u2 = r*w mod n
//         (vx,vy) = u1*G + u2*Q        -- reject if this is infinity
//         accept iff vx mod n == r
//
// p256_ecdsa_verify operates entirely on public data (signature,
// message hash, public key) — nothing here is secret, so unlike the
// point/field/scalar layers underneath it, this function is not
// written to be constant-time; the early-reject branches on
// out-of-range r/s and the infinity check are plain branches.
// p256_ecdsa_sign_with_k, by contrast, only calls into the
// constant-time building blocks (p256_point_mul, p256_scalar_*) and
// adds no secret-dependent branch of its own — the r==0/s==0 checks
// it does add are on freshly-computed public-shaped results (r and s
// are the signature being produced, not secret inputs), and both
// conditions have probability ~2^-256 for any honestly-random k, so
// they're not a meaningful side channel either way.
//
// Both functions were validated against a real, independent ECDSA
// implementation (Python's `cryptography` library, which wraps
// OpenSSL) before this file was written: p256_ecdsa_sign_with_k's
// output was checked against `cryptography`'s own verify(), and
// p256_ecdsa_verify was checked against real signatures `cryptography`
// produced (including tampered-signature rejection tests). See the
// commit that introduced this file, and tests/unit/test_p256_ecdsa.c.
//
// Exported Symbols:
//   p256_ecdsa_sign_with_k — doc block below
//   p256_ecdsa_verify      — doc block below
//
// ====================================================================

#include "../defs.S"

.data
.align 4
// The P-256 base point G, little-endian 64-bit limbs.
p256_gx:
    .quad 0xf4a13945d898c296
    .quad 0x77037d812deb33a0
    .quad 0xf8bce6e563a440f2
    .quad 0x6b17d1f2e12c4247
p256_gy:
    .quad 0xcbb6406837bf51f5
    .quad 0x2bce33576b315ece
    .quad 0x8ee7eb4a7c0f9e16
    .quad 0x4fe342e2fe1a7f9b

// The P-256 curve equation constant b (y^2 = x^3 - 3x + b mod p).
p256_b:
    .quad 0x3bce3c3e27d2604b
    .quad 0x651d06b0cc53b0f6
    .quad 0xb3ebbd55769886bc
    .quad 0x5ac635d8aa3a93e7

.text

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_ecdsa_sign_with_k
//
// Description: Produce an ECDSA signature (r,s) over a 32-byte hash
//   with private key d and nonce k, all as big-endian byte arrays. See
//   the file header for the algorithm and the constant-time notes.
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
.align 2
.global p256_ecdsa_sign_with_k
p256_ecdsa_sign_with_k:
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
    adr_l   x3, p256_gx
    adr_l   x4, p256_gy
    bl      p256_point_mul          // (Rx,Ry) = k*G

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

// ─────────────────────────────────────────────────────────────────────
// Function Name: p256_ecdsa_verify
//
// Description: Verify an ECDSA signature (r,s) over a 32-byte hash
//   against a public key (Qx,Qy), all as big-endian byte arrays. See
//   the file header for the algorithm; operates on public data only,
//   so unlike the rest of this module it uses plain branches.
//
// Input/Arguments:
//   x0 — hash (32 bytes), x1 — sig_r (32 bytes), x2 — sig_s (32 bytes)
//   x3 — Qx (32 bytes), x4 — Qy (32 bytes)
//
// Output/Returns:
//   x0 — 1 if the signature is valid, 0 otherwise
//
// Stack Usage:
//   992 bytes: saved x29/x30, 3 pairs of saved x19-x24, 29 4-limb
//   scratch slots (Jacobian points need 3 slots each; the largest
//   users are the two Jacobian operands and their sum for the final
//   u1*G + u2*Q combination)
// ─────────────────────────────────────────────────────────────────────
.align 2
.global p256_ecdsa_verify
p256_ecdsa_verify:
    sub     sp, sp, #992
    stp     x29, x30, [sp]
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    // scratch slots start at sp+64, 32 bytes each:
    //  0 hash   1 r    2 s    3 Qx    4 Qy    5 z     6 w
    //  7 u1     8 u2   9 p1x  10 p1y  11 p2x  12 p2y
    // 13..15 jac1 (X,Y,Z)   16..18 jac2 (X,Y,Z)   19..21 jacsum
    // 22 vx  23 vy(unused)  24 v(final, reduced mod n)
    // 25 t_a  26 t_b  27 t_c  28 rhs   (curve-equation scratch)

    mov     x19, x0                 // hash ptr
    mov     x20, x1                 // sig_r ptr
    mov     x21, x2                 // sig_s ptr
    mov     x22, x3                 // Qx ptr
    mov     x23, x4                 // Qy ptr

#define VSLOT(i) (64 + 32*(i))

    add     x0, sp, #VSLOT(0)
    mov     x1, x19
    bl      p256_fe_frombytes       // hash_limbs
    add     x0, sp, #VSLOT(1)
    mov     x1, x20
    bl      p256_fe_frombytes       // r_limbs
    add     x0, sp, #VSLOT(2)
    mov     x1, x21
    bl      p256_fe_frombytes       // s_limbs
    add     x0, sp, #VSLOT(3)
    mov     x1, x22
    bl      p256_fe_frombytes       // Qx_limbs
    add     x0, sp, #VSLOT(4)
    mov     x1, x23
    bl      p256_fe_frombytes       // Qy_limbs

    // reject if r or s not in [1, n-1]
    add     x1, sp, #VSLOT(1)
    bl      .Lverify_in_range
    cbz     x0, .Lverify_reject
    add     x1, sp, #VSLOT(2)
    bl      .Lverify_in_range
    cbz     x0, .Lverify_reject

    // reject if Q is not on the curve: Qy^2 == Qx^3 - 3*Qx + b (mod p)
    add     x0, sp, #VSLOT(25)
    add     x1, sp, #VSLOT(4)
    bl      p256_fe_sqr             // t_a = Qy^2
    add     x0, sp, #VSLOT(26)
    add     x1, sp, #VSLOT(3)
    bl      p256_fe_sqr             // t_b = Qx^2
    add     x0, sp, #VSLOT(26)
    add     x1, sp, #VSLOT(26)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_mul             // t_b = Qx^3
    add     x0, sp, #VSLOT(27)
    add     x1, sp, #VSLOT(3)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_add             // t_c = 2*Qx
    add     x0, sp, #VSLOT(27)
    add     x1, sp, #VSLOT(27)
    add     x2, sp, #VSLOT(3)
    bl      p256_fe_add             // t_c = 3*Qx
    add     x0, sp, #VSLOT(28)
    add     x1, sp, #VSLOT(26)
    add     x2, sp, #VSLOT(27)
    bl      p256_fe_sub             // rhs = Qx^3 - 3*Qx
    adr_l   x2, p256_b
    add     x0, sp, #VSLOT(28)
    add     x1, sp, #VSLOT(28)
    bl      p256_fe_add             // rhs = Qx^3 - 3*Qx + b
    add     x0, sp, #VSLOT(25)
    add     x1, sp, #VSLOT(28)
    bl      p256_fe_eq              // Qy^2 == rhs ?
    cbz     x0, .Lverify_reject

    // z = hash mod n, w = s^-1 mod n
    add     x0, sp, #VSLOT(5)
    add     x1, sp, #VSLOT(0)
    bl      p256_scalar_reduce
    add     x0, sp, #VSLOT(6)
    add     x1, sp, #VSLOT(2)
    bl      p256_scalar_inv

    // u1 = z*w mod n, u2 = r*w mod n
    add     x0, sp, #VSLOT(7)
    add     x1, sp, #VSLOT(5)
    add     x2, sp, #VSLOT(6)
    bl      p256_scalar_mul
    add     x0, sp, #VSLOT(8)
    add     x1, sp, #VSLOT(1)
    add     x2, sp, #VSLOT(6)
    bl      p256_scalar_mul

    // (p1x,p1y) = u1*G
    add     x0, sp, #VSLOT(9)
    add     x1, sp, #VSLOT(10)
    add     x2, sp, #VSLOT(7)
    adr_l   x3, p256_gx
    adr_l   x4, p256_gy
    bl      p256_point_mul

    // (p2x,p2y) = u2*Q
    add     x0, sp, #VSLOT(11)
    add     x1, sp, #VSLOT(12)
    add     x2, sp, #VSLOT(8)
    add     x3, sp, #VSLOT(3)
    add     x4, sp, #VSLOT(4)
    bl      p256_point_mul

    // jac1 = (p1x,p1y,1), jac2 = (p2x,p2y,1)
    add     x9, sp, #VSLOT(13)
    add     x10, sp, #VSLOT(9)
    ldr     x11, [x10, #0]
    ldr     x12, [x10, #8]
    ldr     x13, [x10, #16]
    ldr     x14, [x10, #24]
    str     x11, [x9, #0]
    str     x12, [x9, #8]
    str     x13, [x9, #16]
    str     x14, [x9, #24]
    ldr     x11, [x10, #32]
    ldr     x12, [x10, #40]
    ldr     x13, [x10, #48]
    ldr     x14, [x10, #56]
    str     x11, [x9, #32]
    str     x12, [x9, #40]
    str     x13, [x9, #48]
    str     x14, [x9, #56]
    mov     x11, #1
    str     x11, [x9, #64]
    str     xzr, [x9, #72]
    str     xzr, [x9, #80]
    str     xzr, [x9, #88]

    add     x9, sp, #VSLOT(16)
    add     x10, sp, #VSLOT(11)
    ldr     x11, [x10, #0]
    ldr     x12, [x10, #8]
    ldr     x13, [x10, #16]
    ldr     x14, [x10, #24]
    str     x11, [x9, #0]
    str     x12, [x9, #8]
    str     x13, [x9, #16]
    str     x14, [x9, #24]
    ldr     x11, [x10, #32]
    ldr     x12, [x10, #40]
    ldr     x13, [x10, #48]
    ldr     x14, [x10, #56]
    str     x11, [x9, #32]
    str     x12, [x9, #40]
    str     x13, [x9, #48]
    str     x14, [x9, #56]
    mov     x11, #1
    str     x11, [x9, #64]
    str     xzr, [x9, #72]
    str     xzr, [x9, #80]
    str     xzr, [x9, #88]

    // jacsum = jac1 + jac2
    add     x0, sp, #VSLOT(19)
    add     x1, sp, #VSLOT(13)
    add     x2, sp, #VSLOT(16)
    bl      p256_point_add

    // reject if the combination is infinity
    ldr     x9, [sp, #VSLOT(21) + 0]
    ldr     x10, [sp, #VSLOT(21) + 8]
    orr     x9, x9, x10
    ldr     x10, [sp, #VSLOT(21) + 16]
    orr     x9, x9, x10
    ldr     x10, [sp, #VSLOT(21) + 24]
    orr     x9, x9, x10
    cbz     x9, .Lverify_reject

    // v = vx mod n; accept iff v == r
    add     x0, sp, #VSLOT(22)
    add     x1, sp, #VSLOT(23)
    add     x2, sp, #VSLOT(19)
    bl      p256_point_to_affine
    add     x0, sp, #VSLOT(24)
    add     x1, sp, #VSLOT(22)
    bl      p256_scalar_reduce
    add     x0, sp, #VSLOT(24)
    add     x1, sp, #VSLOT(1)
    bl      p256_fe_eq

    b       .Lverify_done

.Lverify_in_range:
    // x1 -> a 4-limb scalar; returns x0 = 1 if 1 <= *x1 < n
    ldr     x2, [x1, #0]
    ldr     x3, [x1, #8]
    ldr     x4, [x1, #16]
    ldr     x5, [x1, #24]
    orr     x6, x2, x3
    orr     x6, x6, x4
    orr     x6, x6, x5
    cmp     x6, #0
    b.eq    .Lverify_in_range_no
    adr_l   x9, p256_n
    ldr     x6, [x9, #0]
    ldr     x7, [x9, #8]
    ldr     x10, [x9, #16]
    ldr     x11, [x9, #24]
    subs    x6, x2, x6
    sbcs    x7, x3, x7
    sbcs    x10, x4, x10
    sbcs    x11, x5, x11
    cset    x0, cc                  // 1 if borrowed, i.e. value < n
    ret
.Lverify_in_range_no:
    mov     x0, #0
    ret

.Lverify_reject:
    mov     x0, #0
    b       .Lverify_return

.Lverify_done:
    // x0 already holds the fe_eq result (0/1)

.Lverify_return:
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp]
    add     sp, sp, #992
    ret

#undef VSLOT
