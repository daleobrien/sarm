# sarm — fuzzing the TLS record layer and the handshake

Steps 6 and 7 of the programme in `docs/SECURITY.md`:

> **Step 6 — Fuzz TLS record parsing.** Standalone harness.
> **Test:** millions of generated cases with no crash or hang.
>
> **Step 7 — Fuzz TLS handshake state transitions.** Structured mutation
> plus random input. **Test:** invalid transitions are rejected.

Sections 1–7 are Step 6, which built the harness and pointed it at the record
layer. Sections 8–14 are Step 7, which pointed the same harness one layer up
and found a five-byte pre-authentication crash — §9.

Steps 3–5 asked whether the record layer is correct at the edges of its
contract, and whether the arithmetic that carries a wire length to an address
can wrap. Both are questions about inputs somebody thought of. This step asks
about the others.

It delivers a harness (`tests/security/fuzz_common.h`), six campaigns against
the record layer (`tests/security/test_fuzz_tls_record.c`), and the evidence in
§5 and §6 that both actually detect the things they claim to.

No production code changed. **No defects were found** — which is a weaker
statement than it looks, and §5 exists to give it teeth.

---

## 1. What a fuzzer has to be, here

Three constraints, none of them optional, and between them they rule out every
off-the-shelf answer.

**Nothing can instrument the code under test.** The routines are hand-written
`.S`. ASan, MSan, and libFuzzer's coverage instrumentation all work by
rewriting compiler IR that does not exist here. There is no allocator either
(`threat-model.md` §5: every buffer is a fixed-size `.bss`/`.data` global), so
there are no heap red zones. A fuzzer that only watches for a crash will not
see a two-byte over-read into the next global — it will see plausible bytes.

The replacement is the guard page, exactly as in Steps 2–5. Every generated
record is placed so its **last byte is the last byte of a page**, with
`PROT_NONE` immediately after, and every output buffer is sized to exactly what
the contract permits and placed the same way. "Did not read past the record"
and "did not write past the output" are then answered by the MMU, on the
instruction that got it wrong.

**A crash is not the only failure.** A parser can return success while handing
its caller a fragment pointer past the end of the buffer, and nothing crashes
until some later caller uses it. So each campaign checks the routine's whole
published output contract on every case — carry flag, error-code range,
fragment placement, length relations — not just that the process survived. The
invariants are listed in §3, and they are what the campaigns are really for.

**Millions of cases means the loop cannot fork.** Steps 3–5 run one forked
child per case, which is right for a few dozen cases and costs about a
millisecond each. At that rate a million cases is twenty minutes.

So the harness inverts it: the **campaign** is forked, and the loop runs
in-process. One child runs the whole batch, publishing into a page shared with
the parent the index and seed of the case it is *about* to try. When the child
dies, the parent reads that page and knows precisely which case killed it. A
crash costs one campaign; a case costs a few hundred nanoseconds.

---

## 2. The harness

`tests/security/fuzz_common.h`. About 300 lines, no dependencies beyond
`guard_pages.h` and the existing test harness.

**Determinism.** A case is a pure function of `(campaign seed, case index)`,
through splitmix64 — chosen over anything in libc because `rand()` differs
between platforms and this corpus must not. The seed is fixed by default, so
the committed suite runs the same corpus every time and a regression is a
regression rather than a coincidence. Because the per-case seed is *derived*
from the index rather than carried along, case 900123 generates the same bytes
whether or not the 900122 before it ran. That is what makes the reproducer
work:

```bash
SARM_FUZZ_SEED=<seed> SARM_FUZZ_CASE=<index> ./tests/security/_obj/test_fuzz_tls_record
```

re-runs that one case **in-process** — no fork, no signal handler — so a fault
lands on the faulting instruction under a debugger. Every failure message ends
with the exact command.

**Crash and hang are distinguished.** A crash is a signal: `SIGSEGV` or
`SIGBUS` from a guard page, `SIGILL`, an abort. A hang is the parent's deadline
expiring — and the deadline is against *progress*, not wall time. The child
bumps a heartbeat after every completed case, and the campaign fails only if
the heartbeat has not moved for `SARM_FUZZ_SECS` (default 300). A campaign that
is merely long is not called a hang; one that is stuck is, within seconds of
getting stuck, however long it had already been running.

**Vacuity is a test failure.** The failure mode of a generator is not that it
crashes, it is that it drifts. A record generator that stops producing records
the parser accepts still satisfies every invariant on the accepting path —
vacuously — and the suite stays green while testing one branch a million times.
So each campaign tallies which outcome every case reached, and declares which
of those outcomes it *must* reach. An empty required bucket fails the campaign:

```
✗ read_record — VACUOUS: 20000 cases and not one reached "past the buffer"
```

That is not a hypothetical. It is what the first run of this suite printed, and
§4 explains what it turned out to mean.

`SARM_FUZZ_STATS=1` prints the full histogram; `SARM_FUZZ_MULT=<n>` scales
every campaign, which is how the long runs in §6 were produced.

---

## 3. The campaigns

All six live in `tests/security/test_fuzz_tls_record.c`.

The generator is shared. Fully random bytes almost never get past the
content-type check, so most of the corpus is *structurally* valid and wrong
only where it matters: the type against the four accepted values, the version
against the two, and — the whole attack surface of a length-prefixed format —
the claimed length against the number of bytes actually present, which are
chosen independently a third of the time. A mutation pass puts some of the pure
chaos back.

| Campaign | Target | What it asserts beyond "no crash" |
|---|---|---|
| `parse` | `tls_record_parse` | On success: type in 20..23 and equal to `buf[0]`; fragment pointer is exactly `buf + 5`; `total == frag_len + 5`; **`total <= buf_len`**; `frag_len` within the limit for its type (2^14, or 2^14+256 for type 23); the reported length is the one in the header. On failure: error code in `SHORT..BOUNDS`. |
| `decrypt` | `tls_record_decrypt` | Error code in the documented set. **On every rejection, the output buffer is byte-for-byte the poison it was filled with** — a record that fails to authenticate must not have leaked one keystream byte into the caller's buffer. On success: inner type in 20..23, content length leaves room for the type byte, content length within the output buffer. |
| `roundtrip` | `encrypt` → `decrypt` | The plaintext comes back exactly, with the same inner type and length; the outer header is `application_data / 0x0303` with a length that matches the record; `encrypt` refuses only the zero-length handshake/alert cases. Decrypting the same record under a **different sequence number** must fail `MAC` with the output untouched. |
| `tamper` | `encrypt`, flip one bit, `decrypt` | Every byte of a TLS 1.3 record is authenticated — the header is the AEAD's additional data and the rest is ciphertext and tag — so there is **no bit anywhere in the record that can be flipped without the open failing**. A success here is a finding. So is a different plaintext. |
| `read_record` | `tls_read_record` | The same output contract as `parse`, plus `total <= cap`, over a real `socketpair` fed adversarial bytes with the writer closed first — so a record claiming more than was sent hits EOF rather than blocking, and a hang here would be a genuine finding rather than a test artefact. |
| `read_prefilled` | `tls_read_record_prefilled` | The same, with the split between "already in the buffer" and "still on the wire" chosen independently of the record's own length. This routine subtracts what is present from what the record needs, twice — once for the header, once for the fragment — on wire-derived values both times, which makes it the subtlest length calculation in the module. |

The `decrypt` campaign uses a fixed key and never authenticates by chance;
roughly one case in 2^128 would. Its job is the path from the length checks to
the padding scan on input the attacker controls completely. The accepting path
belongs to `roundtrip`, which is why `decrypt` does not require an "accepted"
bucket and `roundtrip` does.

---

## 4. What the corpus actually reaches

`SARM_FUZZ_STATS=1`, default seed, default case counts:

| Outcome | `parse` (1,000,000) | `decrypt` (60,000) | `read_record` (20,000) |
|---|---|---|---|
| accepted | 31.3% | — | 20.5% |
| too short for a header | 5.5% | 5.6% | 32.9% |
| bad content type | 34.4% | — | 10.4% |
| bad version | 17.6% | — | 8.0% |
| bad length | 4.9% | 31.2% | 28.2% |
| fragment past the buffer | 6.4% | 15.8% | — |
| bad MAC | — | 47.5% | — |

`roundtrip` round-trips 99.1% of its cases and hits the legal zero-length
refusal in the other 0.9%. `tamper` is refused as `MAC` in 95.4% of cases, as
`LENGTH` or `BOUNDS` in the remaining 4.6% — those are the bit flips that
landed in the two-octet length field, which change how much record there is
before the tag is ever reached. Not one tampered record was accepted.

The empty cells are worth more than the full ones.

`decrypt` never reports a bad type or version because it does not check them:
the outer header is consumed verbatim as the AEAD's additional data, which
binds it, and the caller has already parsed it. That is the module's design and
the histogram agrees with it.

The one in `read_record` is a real finding about the code's shape, and it is
what the vacuity check caught on the first run. **`tls_read_record` cannot
produce `BOUNDS`.** It reads exactly `total` bytes and then hands
`tls_record_parse` a buffer length of exactly `total`, so parse's "fragment
runs past the end of the buffer" branch is structurally unreachable from the
network path — the check that stands in its place is the size test against the
destination buffer, which is `LENGTH`, and that one is required and reached
28% of the time. This is a fact about the record layer nothing in the tree said
out loud before, and the suite now records it as a comment on that campaign's
bucket list rather than as a gap.

---

## 5. Verified by sabotage

A fuzzer that finds nothing has said nothing until you know it can find
something. Each of these breaks one line of production assembly, runs the
suite, and is reverted.

| Sabotage | Campaigns that failed, and how |
|---|---|
| `tls_record_parse` drops `b.hi .Lrec_parse_bounds_err` — the fragment may run past the buffer | `parse`: *success with a record running past the end of the buffer*, case 13 |
| `tls_record_parse` accepts content type 24 (`cmp w6, #4` → `#5`) | `parse`, `read_record`, `read_prefilled`: *success with a content type outside 20..23*, case 251 in all three |
| `tls_record_decrypt` drops its `b.hi .Lrec_dec_bounds` | `decrypt` and `tamper`: **CRASH: SIGBUS** — the guard page, on the instruction that read past the record |
| `aes_gcm_decrypt` skips the tag comparison (`cbnz w9, .Lgcm_dec_fail` → `nop`) | `decrypt`: *wrote plaintext into the output buffer for a record it then rejected*; `roundtrip`: *accepted a record under the wrong sequence number*; `tamper`: *accepted a record with a flipped bit* |
| `raw_read_exact` drops its EOF check (`cbz x0, .Lraw_read_eof`) | `read_record`, `read_prefilled`: **HANG: no progress for 5s at case 10** |

Five sabotages, four detection mechanisms: an invariant on a returned value, a
guard-page fault, a leaked-plaintext check on a buffer that should not have
been touched, and the heartbeat deadline. Every reported failure carried a
`SARM_FUZZ_SEED=… SARM_FUZZ_CASE=…` reproducer, and replaying case 251 of the
second row in single-case mode reproduces it exactly:

```
[parse] replaying case 251 of seed 0x5a524d66757a7a
✗ case 251: tls_record_parse: success with a content type outside 20..23
```

The MAC row is the one to keep. The same broken line was caught three separate
ways, and one of them — *wrote plaintext for a record it then rejected* — is
not a correctness check at all. It is the confidentiality claim in
`decrypt.S`'s own header comment, tested.

---

## 6. Results

Two independent campaigns, each `SARM_FUZZ_MULT=100`, on the committed code:

| Campaign | Cases | Result |
|---|---|---|
| `parse` | 100,000,000 | ✓ |
| `decrypt` | 6,000,000 | ✓ |
| `roundtrip` | 2,000,000 | ✓ |
| `tamper` | 2,000,000 | ✓ |
| `read_record` | 2,000,000 | ✓ |
| `read_prefilled` | 2,000,000 | ✓ |

**114,000,000 cases per campaign, run twice** — once at the committed default
seed `0x5a524d66757a7a` and once at `0xf1b31` — for 228 million generated cases
in total. No crash, no hang, no invariant violation, no vacuous campaign. The
two seeds' histograms agree to within 0.03% on every bucket, which is what you
want to see: the generator's shape is a property of the generator, not of the
seed.

Of those, 31.3 million records were *accepted* by `tls_record_parse`, 4.0
million by the two socket entrypoints, and 4.0 million sealed records made the
full encrypt→decrypt→compare trip byte-for-byte intact. Two million records had
a single bit flipped somewhere in the header, the ciphertext or the tag; every
one of them was refused.

The default (`SARM_FUZZ_MULT=1`) is 1,140,000 cases in about 1.4 seconds, which
is what `make test-security` runs. That is already over a million, so the
step's test condition is met by the committed suite and not only by the soak.

---

## 7. Carried forward

1. **The handshake parsers are not fuzzed.** `tls_record_parse` hands its
   fragment to the ClientHello walk, which is the largest pre-auth parser in
   the tree (`threat-model.md` §3.1) and reaches `tls_session_id`,
   `tls_client_key_share` and `tls_alpn`. Everything in this document is
   reusable against it — the harness is target-agnostic. → Step 7.
2. **Nothing measures coverage.** The histogram in §4 counts *outcomes*, which
   is enough to catch a generator that has stopped reaching a branch it used
   to, and it is not the same as knowing every branch is reached. There is no
   coverage instrumentation for hand-written `.S` and building one is a
   substantially larger project than this step. The outcome buckets are the
   affordable approximation; their limit is that they see the paths somebody
   named.
3. ~~**`decrypt`'s inner-type scan is reached, but only from `roundtrip`.**~~
   **Closed in Step 7** by a seventh record-layer campaign,
   `inner_plaintext` — see §10. The original note follows.

   **`decrypt`'s inner-type scan is reached, but only from `roundtrip`.** The
   padding scan in `decrypt.S` runs after a successful tag check, so the only
   plaintexts it ever sees in this suite are ones `tls_record_encrypt`
   produced, which never carry padding. Nothing generates an authentic record
   with a long zero pad or an all-zero plaintext — the `INNER` bucket is empty
   in every campaign. A generator that seals a *chosen* inner plaintext, rather
   than only `content || type`, would close that. It needs no new
   infrastructure, just a second sealing helper. → worth doing in Step 7,
   alongside the handshake work.
4. **The socket campaigns use a `socketpair`, not a real network.** Short
   reads are exercised (the writer closes first, and `raw_read_exact` loops),
   but fragmentation at arbitrary byte positions is Step 9's subject and is not
   attempted here.

Item 1 is Step 7, below.

---

# Step 7 — the handshake

Step 6 asked what the record layer does with five header bytes nobody wrote
down. Everything it checked happens *before* the handshake begins. Step 7 asks
the next question: given that a record arrived intact, does the handshake
accept it only in the states where it is legal?

It delivers three campaigns in `tests/security/test_fuzz_tls_handshake.c`, one
more in `tests/security/test_fuzz_tls_record.c` that closes §7's item 3, **one
production fix** — a remote pre-authentication crash reachable with five bytes,
§9 — and one correction to a module's documented contract.

---

## 8. The same harness, two new shapes

`fuzz_common.h` is unchanged apart from the wording of a signal name. Nothing
in it was record-specific: the forked campaign with an in-process case loop,
the derived per-case seed that makes `SARM_FUZZ_CASE` replay a single case
standalone, the progress-based hang detector, and the vacuity check all applied
as they stood. That was the claim §7 item 1 made, and it held.

What is new is what a "case" can be.

**A case can drive a stateful function against a live socket.** The `flight`
campaign writes a generated flight into a `socketpair`, closes the write end,
and calls `tls_server_handshake` **in the campaign process**. No fork per case:
the whole flight is already in the socket buffer before the call, and the
server's own replies fit in the peer's, so nothing can block and every read
ends at a real EOF. A fault inside the assembly kills the campaign child, which
is exactly the detector — the harness reports the case index and the
reproducer.

**A case can be an adversary that has to do real work first.** The `finished`
campaign forks the server so it gets its own copy of `tls_state`, then plays a
real TLS 1.3 client from the case itself: X25519 against the ServerHello's
key_share, `tls_derive_handshake_secrets`, `tls_record_decrypt` over the four
records of the server's flight under the server handshake key, and
`tls_finished_key` / `tls_finished_verify_data` over the resulting transcript.
Only then does it hold the one value that authenticates a client, and only then
can the question "is this transition accepted?" be asked of both answers.

The client's ServerHello parse is written by hand rather than reusing
`tls_server_hello_write`'s knowledge of its own format — otherwise a change
that broke the wire format would produce two matching bugs and a passing test.
Everything below it (the curve, the key schedule, the AEAD) is deliberately the
same code: there is one implementation of each in this tree, and a differential
test of those is Step 4's job, not this one's.

---

## 9. What it found: a five-byte pre-authentication crash

Case 83 of the `flight` campaign, on the first run:

```
✗ flight — CRASH: SIGSEGV at case 83 of 3000
  (reproduce: SARM_FUZZ_SEED=25423240288893562 SARM_FUZZ_CASE=83)
```

The whole input:

```
16 03 01 00 00        # handshake record, fragment length 0
```

`tls_server_handshake` reads the record, checks the content type is
`handshake`, and then does this (`src/tls/server/handshake.S`, before the fix):

```asm
    mov     x20, x1                     # fragment pointer
    mov     x21, x2                     # fragment length
    ...
    add     x1, x20, #TLS_HS_HEADER_LEN
    sub     x2, x21, #TLS_HS_HEADER_LEN # ← unsigned
    bl      tls_transcript_add
```

The 4-byte handshake header is skipped by pointer arithmetic and subtracted
from the length. The subtraction is unsigned, and nothing had established that
the fragment was at least 4 bytes long, so a fragment of 0, 1, 2 or 3 bytes
makes the length `2^64 - 4` and `tls_transcript_add` starts hashing the entire
address space. Confirmed by hand outside the fuzzer, at every fragment length:

```
fragment len 0 -> KILLED by signal 11
fragment len 1 -> KILLED by signal 11
fragment len 2 -> KILLED by signal 11
fragment len 3 -> KILLED by signal 10
fragment len 4 -> exit 1        (rejected cleanly)
```

This is reachable by any peer that can open a TCP connection, as the very first
thing it says, before any key exchange or authentication has happened —
`threat-model.md` §3.1's first row. Five bytes crash the process.

`tls_record_parse` is right to accept the record: a zero-length fragment is
legal at the record layer, and the record layer has no idea what a handshake
header is. The missing check belongs to the driver, and is now the two
instructions immediately after the content-type test:

```asm
    cmp     x2, #TLS_HS_HEADER_LEN
    b.lo    .Lhs_fail_generic
```

The same subtraction appears four more times in that function, on the server's
own messages, where the length is one the server just produced. The client's
Finished is the only other peer-controlled length, and it is checked
(`cmp x0, #(TLS_HS_HEADER_LEN + 32)`) before anything subtracts from it.

Also found, and much smaller: `tls_parse_client_hello` returns a sixth alert,
`illegal_parameter`, for a compression method that is not `null`. Its own file
header documents it; the module README's API reference listed five. The
campaign's "an alert its header does not document" invariant reported it on
case 130, and the README is now corrected.

---

## 10. The campaigns

| Campaign | Cases | What it asserts |
|---|---|---|
| `client_hello` | 2,000,000 | `tls_parse_client_hello` over generated bodies ending flush against a guard page. On failure, the alert is one of the six its header documents. On success, `x0` is 0, `tls_session_id_len <= 32`, and ALPN was negotiated as exactly `"h2"`. On **either** — because the ServerHello and EncryptedExtensions writers read them later and trust them — `tls_session_id_len` and `tls_alpn_len` are inside their buffers. |
| `flight` | 6,000 | `tls_server_handshake` against a generated flight. No flight this generator can produce can complete a handshake, so every case must end carry-set, at `TLS_HS_FAILED`, with `transport_mode` still `TRANSPORT_PLAIN` and **the four application traffic key/IV fields still holding the poison they were filled with** — a handshake that fails after installing application keys would leave a live key schedule no peer ever authenticated. |
| `finished` | 1,000 | The iff. Thirteen generated transitions at the one point where a peer can act: correct; correct behind 1–3 `change_cipher_spec` records and behind 200 of them (RFC 8446 D.4); one bit of `verify_data`; a `HandshakeType` other than 20; a body that is not 32 bytes; sealed with the wrong inner content type; sealed under the *server's* handshake key; sealed at the wrong sequence number; random bytes in an `application_data` record; a correct Finished sent in the clear; a correctly sealed *different* handshake message; and nothing at all. The server must connect **exactly** on the first three and refuse the rest, and a claimed success must also carry `TLS_HS_CONNECTED` and `TRANSPORT_TLS`. |
| `inner_plaintext` | 20,000 | (In the record suite — this is §7 item 3.) RFC 8446 §5.4's `content \|\| type \|\| zeros(padding)`, sealed with `aes_gcm_encrypt` directly, because `tls_record_encrypt` appends the type octet last and so can never produce a plaintext ending in a zero. Padded records must come back with the padding stripped and the content byte-for-byte; the all-zero plaintext of Appendix C.3 and a type octet outside 20..23 must both be rejected as `INNER`. |

`inner_plaintext` derives what the answer should be from the bytes it built
rather than from the knobs that built them: it scans back from the end for the
first non-zero octet in C, the same rule §5.4 states, and compares. The two are
not the same thing — a type octet of `0x00` *is* padding, and then the last
non-zero octet of the content becomes the type, which is correct behaviour that
the knobs alone would have called a defect. A 50-million-case soak reported
exactly that, from the version of this campaign that trusted the knobs.

The `finished` campaign is the expensive one — a fork, an ECDSA signature, two
X25519 operations and a full key schedule per case — and it is the one that
makes the other two mean something. Without it, "invalid transitions are
rejected" is satisfied by a function that rejects everything.

---

## 11. What the corpus reaches

`SARM_FUZZ_STATS=1`, default seed and case counts:

| `client_hello` (2,000,000) | | `finished` (1,000) | |
|---|---|---|---|
| accepted | 11.8% | completed (valid Finished) | 7.7% |
| `decode_error` | 45.4% | completed after change_cipher_spec | 15.3% |
| `handshake_failure` | 22.7% | rejected: verify_data | 7.7% |
| `protocol_version` | 13.3% | rejected: message or framing | 30.9% |
| `no_application_protocol` | 4.3% | rejected: key, sequence or ciphertext | 23.1% |
| `unrecognized_name` | 1.3% | rejected: not encrypted | 7.6% |
| `illegal_parameter` | 1.3% | rejected: nothing sent | 7.7% |
| an alert it does not document | 0 | accepted an invalid transition | 0 |

Of 6,000 `flight` cases, 76.5% were refused before the server said anything at
all and 23.5% got the complete five-record server flight out of it before being
refused at the client's Finished.

One bucket is deliberately not required: **`flight`'s "ServerHello sent, then
rejected" is always empty**, and that is a property of the driver rather than a
gap in the corpus. Between sending the ServerHello and sending its own
Finished, `tls_server_handshake` has no failure path a peer can trigger — every
step in between is serialization, hashing and encryption of the server's own
material. A flight that reaches the ServerHello reaches all five records unless
the socket itself fails. This is the same kind of observation Step 6's vacuity
check produced about `tls_read_record` and `BOUNDS` (`threat-model.md` §9),
and it is recorded for the same reason: so an empty bucket is not mistaken for
coverage.

---

## 12. Verified by sabotage

Each row breaks one line of production assembly, runs the suite, and is
reverted.

| Sabotage | What failed, and how |
|---|---|
| The §9 fix removed — `cmp x2, #TLS_HS_HEADER_LEN` deleted | `flight`: **CRASH: SIGSEGV** at case 83 of 6,000. This is the original defect, and it is how it was found |
| `tls_server_handshake` skips the `verify_data` comparison (`cbnz x0, .Lhs_fail_generic` → `nop`) | `finished`: *accepted an invalid client Finished*, case 19 |
| `tls_server_handshake` accepts any inner content type on the client's Finished | `finished`: *accepted an invalid client Finished*, case 0 |
| `tls_server_handshake` derives the application traffic secrets before reading the client's Finished | `flight`: *failed after installing application traffic keys*, case 1 |
| `tls_server_handshake` computes `TLS_HS_FAILED` but does not store it | `flight`: *failed without leaving tls_hs_state at TLS_HS_FAILED*, case 0 |
| `tls_parse_client_hello` drops the `cipher_suites` bounds check | `client_hello`: **CRASH: SIGBUS** at case 79 of 2,000,000 — the guard page, on the scan that walked off the end |
| `tls_record_decrypt` accepts inner type 24 (`cmp w7, #4` → `#5`) | `inner_plaintext`: *accepted an inner plaintext with no valid content type*, case 812. **Only** this campaign caught it — the six Step 6 campaigns all passed |
| `tls_record_decrypt` stops its padding scan at the first octet (`cbz w7, .Lrec_dec_scan` → `nop`) | `inner_plaintext`: *rejected a record it sealed correctly itself*, case 2 |

Eight sabotages. The detection mechanisms are the four Step 6 established — an
invariant on a returned value, a guard-page fault, a poison check on memory
that should not have been touched, and the heartbeat — plus two the handshake
needed: **an invariant on global state after the call** (`tls_hs_state`,
`transport_mode`, the application keys), and **an invariant on a second
process's verdict** (the forked server's exit code against what the case knows
it sent).

The last two rows matter for a different reason: they are the evidence that
§7's item 3 was a real hole and not a bookkeeping note. The same broken line of
`decrypt.S` passes all six Step 6 campaigns and fails the seventh.

---

## 13. Results

Two independent campaigns, `SARM_FUZZ_MULT=200`, at the committed default seed
`0x5a524d66757a7a` and at `0xf1b31`:

| Campaign | Cases per seed | Result |
|---|---|---|
| `client_hello` | 400,000,000 | ✓ |
| `flight` | 1,200,000 | ✓ |
| `finished` | 200,000 | ✓ |

**401,400,000 generated cases per seed, run twice — 802,800,000 in total.** No
crash, no hang, no invariant violation, no vacuous campaign. The two seeds'
`client_hello` histograms agree to within 0.1 percentage point on every bucket.

Of those, about 92,000 complete TLS 1.3 handshakes were driven all the way to
`TLS_HS_CONNECTED` — 46,000 of them behind change_cipher_spec records — and
about 308,000 client Finished messages that were wrong in one of ten generated
ways were refused, alongside 1.83 million ClientHello flights the server never
replied to at all.

`inner_plaintext` was soaked separately with the rest of the record suite, at
`SARM_FUZZ_MULT=50` on the same two seeds: 1,000,000 sealed inner plaintexts
per seed, ✓ on both.

The default (`SARM_FUZZ_MULT=1`) is 2,007,000 cases in about 1.2 seconds, which
is what `make test-security` runs.

---

## 14. Carried forward

1. **`tls_server_handshake` ignores the handshake message's own 3-octet length
   field.** Twice: the ClientHello's, where the body handed to the parser is
   "everything left in the record" rather than "the declared length", and the
   client Finished's, where a Finished declaring length `0xABCDEF` in a 36-byte
   record is accepted (verified by hand). Neither is exploitable as it stands —
   the record length is what bounds every read, the Finished is never re-parsed
   or re-hashed, and a ClientHello whose declared length disagrees with the
   record is rejected by the parser's exact-fit extensions check almost
   always — but "almost always" is the wrong shape of argument, and a strict
   peer would answer `decode_error`. Recorded in `threat-model.md` §9.
2. **A handshake message split across two records, or two messages in one
   record, is not handled** — by the code or by this suite. RFC 8446 §5.1
   permits both. The driver reads exactly one record and treats its fragment as
   exactly one message, so a legitimate client that fragments its ClientHello
   fails the handshake. This is a pre-existing interoperability limit rather
   than something Step 7 introduced, and it is the same missing concept as
   item 1: there is no handshake-message reassembly layer. → worth a step of
   its own; Step 9 (socket fragmentation) will make it easy to demonstrate.
3. **An unbounded number of `change_cipher_spec` records is tolerated before
   the client's Finished.** RFC 8446 Appendix D.4 requires tolerating them and
   sets no limit, so this is conformant, but it lets a peer hold a handshake
   open for as long as it can keep writing 6-byte records. The `FK_CCS_FLOOD`
   generator sends 200 and the handshake still completes. → Step 12 (resource
   limits).
4. **The handshake campaigns test the server against one client.** The
   `finished` campaign's client is correct by construction except where the
   generator makes it wrong, so it explores the neighbourhood of the valid
   transition thoroughly and the rest of the space not at all. `flight` covers
   the other direction with garbage, and the gap between them — a peer that is
   plausible for several messages and then diverges — is only partly covered.
5. **Still nothing measures coverage** (§7 item 2 is unchanged, and applies to
   the handshake exactly as it applied to the record layer).
