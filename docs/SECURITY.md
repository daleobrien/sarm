A key security distinction here is that **“no filesystem access” is an excellent reduction in attack surface, but it does not protect secrets already present in process memory**. If an attacker gains arbitrary code execution or can cause a memory disclosure, an embedded private key may still be recoverable.

I’d structure the work as a security-hardening programme around four goals: **prevent compromise, detect memory corruption early, contain damage if compromise occurs, and continuously regression-test the attack surface**.


## Recommended approach: build a security test and hardening programme

Because `sarm` is a low-level ARMv8 server with substantial handwritten assembly and cryptographic code, I would treat **memory safety, parser safety, cryptographic correctness, secret handling, and denial of service** as separate test tracks.

One important caveat: the private key issue cannot be solved merely by embedding the key and removing filesystem access. A determined attacker who can read the process's memory—or who obtains the binary—may be able to recover an embedded private key. The correct objective is:

> **Make the key inaccessible through normal server behaviour, prevent memory disclosure and arbitrary code execution, minimise its lifetime and copies in RAM, and, ideally, avoid distributing a reusable long-lived secret in the binary at all.**

The search results I found did not reliably expose the repository itself, so I would make the first implementation step an automated source and binary inventory rather than assuming details about files I cannot verify. The project should still be examined directly from the checked-out repository during implementation.

---

# 1. Define the threat model first

Create a short document describing what an attacker can do.

For this server I would assume an attacker can:

* Open arbitrary numbers of TCP connections.
* Send arbitrary bytes at every protocol stage.
* Send truncated packets.
* Fragment records in unusual places.
* Send extremely large declared lengths.
* Send malformed TLS handshakes.
* Replay, reorder, or duplicate network input where relevant.
* Cause concurrent connections to exercise races.
* Disconnect at inconvenient points.
* Send requests extremely slowly.
* Send valid but computationally expensive cryptographic inputs.
* Inspect the public binary.
* Run the binary locally if it is distributed.

But initially assume they **cannot**:

* Read arbitrary process memory.
* Execute arbitrary code.
* Attach a debugger to the production process.
* Modify the executable after deployment.

The entire security programme should try to ensure that malformed network input cannot move an attacker from the first list into the second.

---

# 2. Build a security regression harness before fixing things

The most useful architecture would be:

```text
                    ┌─────────────────────┐
 arbitrary bytes ──►│ protocol entrypoint │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                ▼              ▼              ▼
             TLS parser    HTTP parser     crypto
                │              │              │
                └──────────────┼──────────────┘
                               ▼
                         invariants
                               │
                      crash / hang / leak?
```

Every discovered security bug should eventually become a permanent regression test.

Create separate test modes:

```text
make test
make test-security
make fuzz
make fuzz-tls
make fuzz-http
make fuzz-crypto
make test-sanitizers
make test-stress
```

Even if the production binary contains no external libraries, the **test environment absolutely can use external testing tools**.

That gives you much better security coverage without changing the standalone production binary.

---

# 3. Phase 1 — Memory-safety audit

This should probably be the highest priority.

Handwritten assembly bypasses many of the protections normally provided by C or Rust, so every memory access should be considered potentially dangerous.

## Things to search for

Every instruction equivalent to:

```asm
ldr
str
ldp
stp
ldrb
strb
ldrh
strh
```

should be classified according to where its address and size come from.

For each function, establish:

```text
Input pointer:
Input length:
Output pointer:
Output capacity:
Maximum read:
Maximum write:
```

The goal is to prove:

```text
read_start <= address < read_start + read_length
```

and:

```text
write_start <= address < write_start + write_capacity
```

for every externally influenced path.

### Common bugs to look for

#### 1. Buffer overflow

```text
attacker-controlled length
        ↓
pointer increment loop
        ↓
writes beyond stack or heap buffer
```

Test with:

* zero length
* length 1
* exact buffer size
* buffer size + 1
* maximum integer
* values near `2^32`
* values near `2^64`

---

#### 2. Integer overflow in length arithmetic

This is particularly important.

For example:

```c
total = header_length + payload_length;
```

If:

```text
header_length = 100
payload_length = UINT64_MAX - 50
```

then `total` can wrap.

Likewise:

```text
end = ptr + length
```

can produce an address below `ptr`.

All externally derived arithmetic should use explicit overflow checks.

The assembly equivalent should not simply rely on wrapping arithmetic.

A useful pattern is:

```asm
adds    xEnd, xPtr, xLength
b.cs    overflow_error
```

And for addition of two lengths:

```asm
adds    xTotal, xA, xB
b.cs    overflow_error
```

Every security-sensitive length calculation should have a test specifically targeting integer wraparound.

---

#### 3. Off-by-one errors

Especially loops like:

```asm
subs xLen, xLen, #1
b.ne loop
```

or pointer processing where the final iteration is special.

Test all boundaries:

```text
0
1
2
15
16
17
31
32
33
63
64
65
127
128
129
```

These values are especially useful because your crypto and networking code will probably have block boundaries at 16, 32, or 64 bytes.

---

#### 4. Out-of-bounds reads

These are particularly dangerous because they can become **secret disclosure vulnerabilities**.

A server might not crash. Instead it could accidentally include adjacent memory in:

* a TLS response
* an HTTP response
* an error message
* a MAC calculation
* a compressed buffer

That adjacent memory could contain the private key.

This makes OOB reads just as important as OOB writes.

---

# 4. Add AddressSanitizer-style testing where possible

Your final ARM assembly cannot automatically benefit from ASan in the same way as C, but you can still build a powerful testing strategy.

Create C or C++ reference wrappers around assembly functions.

For example:

```c
int test_tls_record(
    uint8_t *input,
    size_t input_len
);
```

Then compile the test harness with:

```text
-fsanitize=address
-fsanitize=undefined
-fno-omit-frame-pointer
```

The wrappers and surrounding allocations can detect:

* corrupted red zones
* invalid heap accesses
* stack corruption
* use-after-free
* undefined integer behaviour in C support code

For the assembly functions themselves, add **guard pages**.

Allocate buffers like:

```text
[ inaccessible page ][ valid buffer ][ inaccessible page ]
```

Then call the assembly routine.

If it reads or writes past either end, it immediately faults.

This is likely to be extremely valuable for `sarm`.

I would create a reusable test helper:

```text
tests/security/guard_pages.c
```

with an interface approximately like:

```c
struct guarded_buffer {
    void   *mapping;
    size_t mapping_size;
    uint8_t *data;
    size_t size;
};
```

Then every assembly crypto function can be tested against boundaries.

---

# 5. Phase 2 — Build differential tests for assembly

This is one of the strongest testing techniques available for this project.

For every assembly crypto primitive, maintain a slow, obviously correct reference implementation used **only in tests**.

For example:

```text
assembly implementation
          │
          ├── random test vectors ──► output A
          │
reference implementation
          │
          └──────────────────────────► output B

assert(A == B)
```

Apply this to:

* AES
* GHASH
* SHA-256
* SHA-256 streaming if present
* P-256 field operations
* modular reduction
* X25519
* ECDSA
* HKDF
* TLS transcript hashing
* record authentication

This catches a different class of bug from memory safety:

> **The code can be perfectly memory-safe and still cryptographically wrong.**

Given the recent optimisation work on GHASH and P-256 reduction, every optimisation should be required to pass differential testing before benchmarking.

---

# 6. Phase 3 — Fuzz every parser independently

Do not begin by fuzzing only the complete server.

Break the protocol into independently fuzzable components.

## TLS record parser

Fuzz:

```text
record type
legacy version
length
payload
```

Test cases should include:

```text
all-zero
all-0xff
truncated
one-byte increments
oversized length
declared length != actual length
random mutations
structured mutations
```

Success criteria:

* no crash
* no hang
* no memory violation
* no unexpected syscall
* no secret-dependent output
* deterministic rejection

---

## TLS handshake parser

Fuzz each message type separately.

Important cases include:

* invalid extension lengths
* duplicate extensions
* nested length inconsistencies
* empty fields
* huge fields
* unexpected message ordering
* repeated handshake messages
* malformed key shares
* malformed certificate messages if certificates are parsed
* malformed signatures

Also test valid messages mutated one byte at a time.

That often finds much deeper bugs than purely random input.

---

## HTTP parser

Attack cases include:

### Request line attacks

```text
GET
GET /
GET / HTTP/1.1
```

plus extremely long:

* methods
* paths
* headers
* versions

### Header attacks

* missing CRLF
* CRLF in unexpected positions
* enormous header counts
* duplicate headers
* invalid whitespace
* embedded NUL bytes
* invalid control characters

### Smuggling-related behaviour

Even if this server is intentionally simple, explicitly test:

* conflicting `Content-Length`
* `Transfer-Encoding`
* duplicate length headers
* malformed chunking if supported

The safest strategy for a minimal embedded-file server is often:

> **Support the smallest possible HTTP grammar and reject everything else.**

Every optional protocol feature is additional attack surface.

---

# 7. Phase 4 — Network-level fuzzing

Once the individual parsers are fuzzed, attack the real socket interface.

Create a tool that:

1. Starts the server.
2. Opens a connection.
3. Sends generated input.
4. Randomly fragments writes.
5. Randomly closes the socket.
6. Repeats.

For example:

```text
full TLS packet
       │
       ▼
split into:

1 byte
3 bytes
17 bytes
0-byte delay
1-byte delay
rest
```

This tests state-machine bugs caused by assumptions such as:

```text
one recv() == one protocol message
```

which must never be assumed.

Test:

* one byte at a time
* multiple records in one packet
* partial headers
* partial encrypted records
* EOF at every possible byte
* reset during handshake
* thousands of simultaneous partial connections

---

# 8. Phase 5 — Denial-of-service testing

For a small standalone server, DoS resistance is critical.

The biggest categories are:

## Slow connections

The classic pattern is:

```text
connect
send one byte
wait
send one byte
wait
```

Thousands of these can exhaust:

* file descriptors
* connection state
* stack
* worker threads
* memory

Add explicit limits for:

```text
maximum concurrent connections
maximum handshake duration
maximum incomplete request duration
maximum buffered input per connection
maximum TLS record size
maximum HTTP request size
maximum headers
```

---

## CPU exhaustion

Cryptography can be attacked with valid but expensive requests.

Measure:

```text
connections/sec
CPU time/connection
maximum concurrent handshakes
```

Then deliberately flood:

* incomplete handshakes
* malformed key shares
* signature verification paths
* repeated handshake attempts

A malformed packet should generally be rejected **before expensive crypto** wherever protocol ordering permits.

---

## Memory exhaustion

Every allocation or buffer reservation should have an explicit maximum.

Avoid:

```text
allocate(length_from_network)
```

Prefer:

```text
if length > MAX_TLS_RECORD:
    reject
```

For this project, fixed-size buffers may actually make the security model simpler, provided all bounds are rigorously enforced.

---

# 9. Phase 6 — Private-key threat model

This deserves its own workstream.

## First: recognise the binary extraction problem

If the key is literally embedded as static bytes in the executable:

```text
private_key:
    .byte ...
```

then someone who obtains the executable can potentially extract it without attacking the server at all.

Filesystem restrictions do not help here.

A private key embedded in a publicly distributed binary should be considered **eventually extractable**.

Obfuscation is not a strong defence.

---

## Better options, from strongest to weakest

### Option A — Hardware-backed key

Use a system or hardware facility where the private key never appears as ordinary application memory.

The application requests:

```text
sign(hash)
```

and receives:

```text
signature
```

This is the strongest architectural approach.

The downside is platform dependency and possibly violating your standalone/minimal design.

---

### Option B — Generate the key during deployment

Do not compile the production key into the distributed binary.

Instead:

```text
binary
   +
deployment secret injection
   ↓
running server
```

This is much better than one universal private key embedded in every copy.

The server still has the key in memory, but compromise of one binary does not compromise every deployment.

---

### Option C — Ephemeral or per-installation keys

Generate a unique key during provisioning.

Again:

```text
compromise of server A
≠
compromise of server B
```

---

### Option D — Embedded encrypted key

You can embed:

```text
encrypted_private_key
```

rather than the raw key.

However, the encryption key must eventually be available somehow.

So unless it comes from outside the binary or hardware, this mainly increases extraction difficulty rather than providing strong cryptographic protection.

I would not rely on this as the primary defence.

---

# 10. Protect the key while it is in memory

If the process must hold the private key, reduce its exposure.

## Keep one copy

Audit all copies.

Avoid:

```text
key → temporary buffer → parsed structure → crypto workspace
```

Try to establish one canonical key representation.

---

## Zero temporary buffers

Any temporary sensitive values should be explicitly cleared.

Do not rely on an optimiser preserving a naive:

```c
memset(key, 0, size);
```

Use a mechanism designed for secure zeroisation.

In assembly this is easier to control, but make sure:

* every error path clears secrets where appropriate
* stack temporaries are overwritten
* crypto intermediate values do not unnecessarily survive

Candidates include:

* ECDSA nonce material
* X25519 private scalar
* TLS traffic secrets
* handshake secrets
* derived keys

---

## Prevent core dumps

A crash dump can be a complete memory disclosure.

Production should disable core dumps or mark sensitive mappings as non-dumpable where the operating system supports it.

Then explicitly test:

```text
force crash
inspect generated artifacts
verify no secret-containing dump exists
```

---

## Avoid logging secrets

Create an automated test that scans:

* stderr
* debug logs
* error paths

for known test secrets.

Use a deliberately recognisable test key:

```text
TEST_SECRET_7F31...
```

Run:

```text
handshake
malformed handshake
forced crypto failure
connection reset
internal error
```

Then assert the marker never appears in output.

---

# 11. Add a secret-leak regression test

This is something I strongly recommend for `sarm`.

Build the test binary with a deliberately unique fake private key.

For example, generate a deterministic test key containing a recognisable byte sequence.

Then:

1. Start the server.
2. Send millions of malformed and fuzzed requests.
3. Capture every byte received from the server.
4. Search for:

   * the complete key
   * long substrings
   * TLS secret markers
   * known canary values

Conceptually:

```text
secret = "UNIQUE_TEST_SECRET_..."
```

Then:

```text
fuzz input
       │
       ▼
server
       │
       ▼
capture all responses
       │
       ▼
assert secret not present
```

This will not prove the production key is impossible to extract, but it is an excellent regression detector for accidental memory disclosure.

---

# 12. Stack-corruption testing

Because the project uses AArch64 assembly, I would specifically test ABI and stack correctness.

Every function should obey:

* stack pointer alignment requirements
* callee-saved register preservation
* correct frame restoration
* no writes below allocated stack space

Create a stress test that repeatedly calls assembly functions with randomised:

* stack-adjacent canaries
* input alignment
* output alignment
* boundary lengths

Check:

```text
before_canary == expected
after_canary  == expected
```

Also deliberately call functions with buffers aligned at:

```text
1
2
4
8
16
32
64
```

where the API permits unaligned input.

Optimised assembly often accidentally assumes stronger alignment than the API guarantees.

---

# 13. Control-flow and code-execution protections

For production builds, evaluate which platform hardening features can be enabled without harming the standalone design.

At minimum investigate:

* ASLR / PIE
* NX / non-executable writable memory
* stack canaries for C code
* RELRO where dynamically relevant
* branch protection / BTI
* pointer authentication where supported
* read-only protection for static tables

For AArch64 specifically, branch-target protections and hardware-supported control-flow protections can reduce the usefulness of some memory-corruption bugs.

These are defence-in-depth measures.

They do **not** replace fixing the overflow.

---

# 14. Add syscall-level containment

Since the server should not access the filesystem, turn that into a testable security property.

Create a syscall allowlist.

For example, the server should only need a limited set of operations such as:

```text
socket
bind
listen
accept / accept4
read / recv
write / send
close
poll / epoll / kqueue
clock_gettime
memory-management syscalls
thread-related syscalls if multicore
```

The exact list will depend on macOS/Linux and the final architecture.

Then test:

```text
run server under syscall tracing
exercise normal TLS and HTTP traffic
assert:
    no open
    no openat
    no unlink
    no rename
    no mkdir
    no execve after startup
```

This is extremely useful because it gives you a concrete invariant:

> **A remote attacker cannot trick the server into reading a file because the server contains no code path that successfully performs a file-open syscall.**

On Linux, if compatible with your deployment model, this can be strengthened with a syscall filter.

---

# 15. Test filesystem non-access explicitly

Add a test approximately like:

```text
1. Run server in an empty directory.
2. Make directory read-only.
3. Remove all unnecessary files.
4. Exercise:
   - normal TLS
   - malformed TLS
   - fuzzed HTTP
   - error conditions
5. Verify no files were opened or created.
```

Also use a restricted sandbox/container where the process has access only to:

```text
/proc or required OS interfaces
network
minimal runtime requirements
```

Then attempt all malformed inputs.

This catches accidental code paths such as:

* certificate reload
* error logging to files
* temporary files
* configuration reads
* `/dev/urandom` fallback
* dynamic library loading where unexpected

Given your recent work on `RNDR`, `getentropy`, and `getrandom`, the entropy path should also be included in this audit so that an unexpected fallback does not violate the intended operating model.

---

# 16. Crypto-specific security tests

For the TLS implementation, performance optimisation must not weaken side-channel resistance.

## Constant-time testing

Identify operations involving:

* private key bits
* ECDSA nonce
* X25519 scalar
* TLS traffic secrets

Then audit for:

```text
branch based on secret
memory lookup based on secret
variable iteration count based on secret
```

For example:

```asm
cmp secret_bit, #0
b.eq path_a
```

would be suspicious.

The goal is not merely:

```text
correct signature
```

but:

```text
correct signature without secret-dependent behaviour
```

Use timing experiments as a regression signal, while recognising that timing tests alone cannot prove constant-time behaviour.

---

## ECDSA nonce failures

This deserves particularly aggressive testing.

A repeated or predictable nonce can compromise the private key.

Test:

* uniqueness across very large numbers of signatures
* entropy failure paths
* partial entropy
* repeated entropy values in test harnesses
* failure handling

Never silently substitute a predictable value if the secure random source fails.

Fail closed.

---

# 17. State-machine testing

TLS and HTTP security bugs are often state bugs rather than buffer bugs.

Construct a transition table.

For TLS:

```text
NEW
 ↓
CLIENT_HELLO
 ↓
KEY_EXCHANGE
 ↓
HANDSHAKE_KEYS
 ↓
FINISHED
 ↓
APPLICATION_DATA
 ↓
CLOSED
```

For every state, test every invalid message.

For example:

```text
APPLICATION_DATA in NEW       → reject
FINISHED twice                → reject
CLIENT_HELLO after handshake  → reject
CLOSE then application data   → reject
```

Generate this automatically.

A very useful test property is:

> For every protocol state, every possible input either produces a valid next state or a clean rejection. It must never produce an undefined state.

---

# 18. Add long-running chaos tests

Once the basic fuzzers work:

```text
24-hour test
```

with:

* random connections
* valid traffic
* invalid traffic
* partial packets
* concurrent clients
* forced disconnects
* repeated server restarts

Monitor:

```text
RSS
open file descriptors
thread count
connection count
CPU
crashes
assertion failures
```

Look specifically for:

* memory leaks
* descriptor leaks
* state not released after errors
* stuck connections
* CPU spinning

---

# 19. Suggested implementation order

I would do this in the following small, testable sequence.

### Step 1 — Security inventory

Create:

```text
docs/security/threat-model.md
```

Document:

* network entrypoints
* externally controlled lengths
* secret locations
* memory allocations
* syscalls
* protocol states

**Test:** reviewable inventory with no code changes.

---

### Step 2 — Add guard-page buffer tests

Create a reusable guarded allocation helper.

**Test:** deliberately broken test function reliably faults on:

* read before
* read after
* write before
* write after

---

### Step 3 — Test every crypto primitive at boundaries

For every assembly routine:

```text
0
1
block - 1
block
block + 1
large
maximum supported
```

**Test:** no crash and reference output matches.

---

### Step 4 — Add differential crypto testing

Reference implementation versus assembly.

**Test:** thousands or millions of random vectors match exactly.

---

### Step 5 — Audit all length arithmetic

Introduce explicit checked-add and checked-range patterns.

**Test:** integer-overflow corpus is rejected.

---

### Step 6 — Fuzz TLS record parsing

Standalone harness.

**Test:** millions of generated cases with no crash or hang.

---

### Step 7 — Fuzz TLS handshake state transitions

Structured mutation plus random input.

**Test:** invalid transitions are rejected.

---

### Step 8 — Fuzz HTTP parsing

Standalone harness.

**Test:** no crash, hang, or excessive allocation.

---

### Step 9 — Add socket fragmentation testing

Send every valid corpus item split at arbitrary byte positions.

**Test:** behaviour matches unsplit input.

---

### Step 10 — Add secret-leak tests

Use recognisable fake secrets.

**Test:** fuzz responses and logs never contain the secret marker.

---

### Step 11 — Add syscall allowlist testing

Trace a normal and malformed workload.

**Test:** no filesystem-opening syscall succeeds.

---

### Step 12 — Add resource-limit tests

Attack:

* connections
* handshake state
* buffers
* CPU

**Test:** resource use remains bounded.

---

### Step 13 — Add production hardening

Enable supported binary and OS protections.

**Test:** inspect the final binary and verify the expected protections are present.

---

### Step 14 — Run continuous fuzzing

Every crash produces:

```text
corpus input
       ↓
minimal reproducer
       ↓
unit/regression test
       ↓
fix
```

Never just fix a fuzzer crash without preserving the input.

---

## The security priorities I would use

| Priority | Area                                                     | Risk                                       |
| -------- | -------------------------------------------------------- | ------------------------------------------ |
| **P0**   | Out-of-bounds read/write                                 | Remote code execution or secret disclosure |
| **P0**   | Integer overflow in lengths                              | Bypass bounds checks                       |
| **P0**   | TLS state-machine errors                                 | Authentication/protocol bypass             |
| **P0**   | ECDSA nonce/randomness failure                           | Private-key compromise                     |
| **P0**   | Private key embedded identically in distributed binaries | Offline extraction risk                    |
| **P1**   | DoS/resource exhaustion                                  | Service unavailable                        |
| **P1**   | Secret copies and logging                                | Key leakage                                |
| **P1**   | Crypto correctness differential testing                  | Broken TLS security                        |
| **P1**   | Constant-time audit                                      | Side-channel exposure                      |
| **P2**   | Syscall sandboxing                                       | Defence in depth                           |
| **P2**   | Binary hardening                                         | Defence in depth                           |
| **P2**   | Long-running chaos testing                               | Reliability/security regression            |

## My strongest recommendation

For `sarm`, I would start with **a dedicated security test harness around every assembly function**, using guard pages, canaries, random boundary testing, and reference implementations. Then fuzz the TLS and HTTP parsers.

The second major architectural decision is the private key. If the binary is distributed to untrusted machines or users, **a long-lived private key compiled directly into it cannot be considered permanently secret**. The ideal design is a per-deployment or hardware-backed key; otherwise, a compromise of one binary can potentially compromise every deployment using that same key.

The most valuable invariant to aim for is:

> **Arbitrary network input can cause only a bounded, clean rejection. It can never cause an out-of-bounds access, integer wraparound, undefined protocol state, unbounded resource consumption, filesystem access, or any output derived from memory outside the explicitly defined response buffers.**

That gives you a concrete security standard against which every optimisation to this assembly-heavy server can be tested. ([codebrowser.dev][1])

[1]: https://codebrowser.dev/linux/linux/arch/arm/include/asm/tls.h.html?utm_source=chatgpt.com "tls.h source code [linux/arch/arm/include/asm/tls.h] - Codebrowser"
