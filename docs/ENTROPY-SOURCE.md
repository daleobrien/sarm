# Entropy — /dev/urandom → getentropy, and measured effect

The item `docs/P256-FIXED-BASE-COMB.md` §6 first listed and
`docs/P256-SCALAR-INVERSION.md` §6 repeated: `crypto_random_bytes` re-opening
`/dev/urandom` on every call. It kept getting deferred because the P-256 work
was larger. It is not larger any more — with the field multiply fixed
(`docs/P256-FIELD-MULTIPLY.md`), a fresh `scripts/profile_samples.py` run put
**`crypto_random_bytes` at 11.80% of the handshake workload's busy samples, the
largest single non-syscall-wait cost in the server**.

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback.

---

## The one-line answer

Three syscalls per call — `open("/dev/urandom")`, `read`, `close` — became one,
`getentropy(2)`. **8.9 µs per call becomes 0.79 µs, 11.3x**, which is ~24 µs off
every TLS connection, and takes the marginal handshake connection from 235.2 µs
to 192.4 µs of server CPU.

| | before | after | ratio |
|---|---:|---:|---:|
| `crypto_random_bytes` (16 B) | 8.88 µs | **0.78 µs** | **11.3x** |
| `crypto_random_bytes` (32 B) | 8.88 µs | **0.79 µs** | **11.2x** |
| `crypto_random_bytes` (64 B) | 8.93 µs | **0.80 µs** | **11.2x** |
| share of handshake busy samples | 11.80% | **0.42%** | — |
| handshake connection (server CPU, marginal) | 235.2 µs | **192.4 µs** | **1.22x** |
| page-load connection (server CPU, marginal) | 386.5 µs | **338.6 µs** | **1.14x** |

The connection figures are for this change *and* the field multiply together;
the two are separated in §4.

---

## 1. Why it was 8.9 µs

The old implementation opened the device, read, and closed, every call. The
benchmark's most informative number is not the total but its **flatness**:
8.88 µs at 16 bytes, 8.88 at 32, 8.93 at 64. Reading four times as much data
costs 0.5% more. Essentially none of the 8.9 µs was moving bytes — it was
`open`, and specifically the kernel's path resolution for `/dev/urandom`.

Three calls happen per TLS connection:

| call site | what for |
|---|---|
| `tls_build_server_hello` | `server_random` (32 B) |
| `tls_build_server_hello` | the ephemeral X25519 private key (32 B) |
| `tls_certificate_verify_write` | the ECDSA nonce `k` (32 B) |

So ~27 µs per connection, against a connection that costs ~235 µs.

## 2. What it is now

`getentropy(2)` on macOS, `getrandom(2)` on Linux. Both read the same kernel
CSPRNG that backs `/dev/urandom`, with no descriptor in between: one syscall,
no path lookup, no fd, no close.

The syscall number was **confirmed on this machine rather than recalled** — a
direct `svc #0x80` with x16 = 500 against a zeroed buffer, checked for a
non-zero fill, and checked to reject 512 bytes with EINVAL. That second check
matters: `getentropy` caps a single call at 256 bytes, so anything larger has to
be filled in several passes, and the assembly loops accordingly. Every caller in
this tree asks for 32 bytes, so the loop runs once in practice; it exists
because the function's contract takes a length.

Linux differs enough to need its own path (`#ifdef __linux__`, the split
`src/defs.S` already uses): `getrandom` returns a count rather than 0/-1, may
return short, and may fail with `EINTR`, so that path loops on all three.

### Two things this improves besides speed

1. **No descriptor.** The old code could fail because the process was out of
   file descriptors, or because `/dev` was not mounted where it ran. Neither is
   reachable now, and there is no fd to leak or to inherit across the per-
   connection `fork`.
2. **On Linux it is strictly safer.** `getrandom` with `flags = 0` blocks until
   the CSPRNG is seeded. Reading `/dev/urandom` does not, and will hand back
   unseeded output very early in boot. This is the interface the kernel
   documents for generating keys; `/dev/urandom` is the one that predates it.

The entropy *source* is unchanged. This is not a userspace PRNG, not a seeded
generator, and not a cache — every call still goes to the kernel.

---

## 3. Verification

| check | what it establishes |
|---|---|
| direct syscall probe | syscall 500 fills a buffer with non-zero bytes and returns 0; 512 bytes returns EINVAL — the 256-byte cap is real, not assumed |
| `tests/unit/test_crypto_random.c` (pre-existing) | success, non-zero output, two calls differ, zero-length is a no-op, no overrun past the requested length |
| `tests/unit/test_crypto_random.c` (new `test_chunked`) | sizes 255/256/257/512/1000 — the loop running 1, 2, 3 and 4 times — fill the whole buffer, do not overrun, and differ across *both* chunks between calls |
| **mutation test** | with `add x19, x19, x21` (the pointer advance between chunks) deliberately broken, the new tests fail on 3 assertions; restored, they pass |
| `make test` | 4285 → 4304 tests, all passing |
| `scripts/validate_clobbers.py` | `crypto_random_bytes` agrees with what the binary clobbers |
| `tests/h2_browser_sim.py` | a real TLS 1.3 handshake and HTTP/2 page load against the built server |

The mutation test is the one worth keeping. A skipped chunk leaves 256 bytes of
a key buffer untouched — which is to say predictable — while every other test in
the file still passes, because they all use 32-byte requests. The new assertions
were written to fail on exactly that, and were checked to actually do so rather
than assumed to.

---

## 4. Cost, and how it splits from the field-multiply change

`__text` **shrinks** by 96 bytes (44,732 → 44,636): the open/read/close
sequence, its error and EOF handling, and the `/dev/urandom` string are all
gone, and `crypto_random_bytes` is now a leaf that needs no x30 save.

The two changes in this batch land on different halves of a connection, which is
why they were worth doing together:

| | handshake connection CPU | of which user | of which sys |
|---|---:|---:|---:|
| before both | 235.2 µs | 120.8 µs | 114.2 µs |
| field multiply only | 243.8 µs | 111.7 µs | 131.8 µs |
| both | **192.4 µs** | 112.0 µs | 80.6 µs |

The field multiply moves user time and leaves kernel time alone; this change
does the reverse. The middle row also shows the profiler's noise honestly — its
*total* went up by 3.7% while its user component genuinely fell, because
per-scenario sys time varies by ±5–10% between runs. Only the combined figure
(1.22x) is outside that band, so the split above should be read as
attribution, not as three precise measurements.

---

## 5. What this exposes next

`crypto_random_bytes` drops from 11.80% of busy samples to **0.42%**, which
takes it off the list. `raw_read_exact` (63%) and `raw_write_all` (11%) now
dominate the profile, but `raw_read_exact` is mostly the server blocking on the
Python test client rather than work — `scripts/profile_samples.py` samples a
blocked thread as readily as a running one, and the harness's own idle count
went from 16,336 to 19,299 samples over the same 25 seconds, which is the
throughput gain showing up as idleness.

Of the remaining real compute, **X25519 is now the largest** at 13.3% of busy
samples across its routines, against 8.0% for all of P-256. See
`docs/P256-FIELD-MULTIPLY.md` §7.
