# 04 — Asymmetric crypto: algorithmic wins on the handshake path

**Likely the largest per-connection win.** Algorithmic, not micro-optimization.

## Context

Every new connection runs a TLS 1.3 handshake, and the handshake's cost is
dominated by elliptic-curve scalar multiplication. For a server holding a
**fixed, embedded certificate and signing key**, several of these operations
have precomputable structure that the current implementation does not exploit.

Two concrete findings:

### P-256 uses naive double-and-add

`src/crypto/p256_point/mul.S` implements constant-time Jacobian
double-and-add over all 256 bits: one double plus one always-executed add per
bit, selected with `cmov`. That is ~256 doubles and ~256 adds.

A **fixed-base comb** replaces this with a precomputed table of multiples of
the generator. With a 4-bit window over 64 windows, cost drops to ~64 additions
and no doublings — typically **4–8×** for base-point multiplication.

This applies wherever the point is the fixed generator G:

- the server's ECDHE key share (`d·G`), if the P-256 group is negotiated;
- ECDSA signing (`k·G`) in `p256_ecdsa_sign_with_k`, run **every connection**
  for CertificateVerify.

Variable-base multiplication (the ECDH shared secret, `d·peer_public`) cannot
use a build-time table, but still benefits from a windowed method with a small
runtime table.

**This fits the program's existing design.** `sarm` already precomputes assets
at build time — `embed_www.sh` embeds pre-compressed files, `certs/embed_cert.sh`
embeds the certificate. A generator comb table is the same idea applied to
crypto: computed once at build time, embedded as read-only data, never
recomputed.

### X25519's ladder is call-bound

`src/crypto/x25519/main.S` runs a Montgomery ladder with ~18 field-operation
calls per bit over 255 bits — roughly **4,600 `bl` calls per handshake**, of
which ~1,275 are `x25519_fe_mul`. That structure is addressed in prompt 05;
the algorithm itself is already the right one.

## Objective

Reduce per-connection handshake CPU cost through algorithmic improvement to
scalar multiplication, without weakening constant-time guarantees.

## Method

1. **Determine what actually runs.** Before optimizing either curve, establish
   from prompt 00 which group TLS actually negotiates in practice and how many
   scalar multiplications a real handshake performs. Optimizing the curve the
   server never selects is wasted work. Check
   `src/tls/handshake/client_hello.S` and the key-schedule path for which
   groups are offered and chosen.
2. **Benchmark the baseline** — `p256_point_mul`, `p256_ecdsa_sign_with_k`, and
   `x25519` end-to-end, per operation.
3. **Implement the fixed-base comb** for generator multiplication:
   - Generate the table with a **Python reference implementation first**, and
     cross-check it against a known-good source before writing any assembly.
     The repo skill `verified-asm-crypto` documents this
     prototype-then-cross-check-then-port workflow — follow it. Do not
     hand-derive the table format in assembly.
   - Emit it as a build-time-generated `.S` data file, following the pattern of
     `certs/embed_cert.sh` and `src/tls/cert_data.S`. Make it reproducible.
   - Size the window against the table cost: a 4-bit comb over P-256 is
     ~16 × 64 × 64 bytes = 64 KB. Weigh that against binary size, which matters
     for an embedded static server. A smaller window trades table size for
     additions — measure both.
4. **Keep the variable-base path** for the ECDH shared secret; optionally add a
   windowed method with a runtime-built table.
5. **Re-measure** per-operation and end-to-end handshake cost.

## Constraints

Non-negotiable, and more important here than anywhere else in the codebase:

- **Constant time.** Table lookups must be **oblivious**: scan every table
  entry and select with `cmov`-style masking, exactly as the current code does
  for its always-add. A table indexed directly by secret scalar bits is a
  cache-timing vulnerability, and it is the classic way this optimization goes
  wrong. No secret-dependent branches, no secret-dependent addresses.
- **The scalar is secret.** Both the ECDSA nonce `k` and the ECDH private key
  are secret. Window extraction must be branch-free.
- **Verify against known-answer tests before trusting anything.** RFC 6979
  deterministic ECDSA vectors and RFC 7748 X25519 vectors give exact expected
  outputs. Wrong crypto that passes a smoke test is the worst outcome here.
- **No heap, no dynamic allocation.** Tables are static read-only data.
- Binary size increase must be reported explicitly — this program is a small
  self-contained server and a 64 KB table is a real trade, not a free win.

## Testing

- `tests/unit/test_p256/`, `test_p256_point/`, `test_p256_ecdsa/`,
  `test_x25519` suites.
- **Differential against the current implementation** over thousands of random
  scalars, including edge cases: scalar 0, 1, n−1, and scalars with leading
  zero bits (a classic comb-implementation bug).
- RFC 6979 and RFC 7748 known-answer vectors.
- End-to-end: `tests/h2_browser_sim.py` and `tests/test_protocols.sh` must
  complete a real handshake with a real client.

## Acceptance criteria

- Byte-exact agreement with the current implementation on every differential
  case and every known-answer vector.
- Measured reduction in per-handshake CPU time, beyond prompt 02's noise floor.
- Constant-time properties preserved — state explicitly what you checked and
  how.
- Table generation is reproducible from source at build time, not a committed
  binary blob of unknown provenance.
- Binary size delta reported.

## Deliverable

Implementation plus a report: per-operation and per-handshake cost before and
after, binary size delta, table generation method, and the constant-time
argument for the table lookup.
