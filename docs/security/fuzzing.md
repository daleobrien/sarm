# sarm — fuzzing the TLS record layer

Step 6 of the programme in `docs/SECURITY.md`:

> **Step 6 — Fuzz TLS record parsing.** Standalone harness.
> **Test:** millions of generated cases with no crash or hang.

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
3. **`decrypt`'s inner-type scan is reached, but only from `roundtrip`.** The
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
