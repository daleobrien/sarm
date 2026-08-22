# sarm — continuous fuzzing

Step 14 of the programme in `docs/SECURITY.md`:

> **Step 14 — Run continuous fuzzing.** Every crash produces:
>
> ```text
> corpus input
>        ↓
> minimal reproducer
>        ↓
> unit/regression test
>        ↓
> fix
> ```
>
> Never just fix a fuzzer crash without preserving the input.

Steps 6, 7, 8 and 9 built the campaigns (`fuzzing.md`, `frag_*`). This step is
about what happens *around* them: running them on inputs nobody has run before,
and making sure that when one of those runs finds something, the input survives
long enough to become a test.

It is the smallest step in the programme by volume of new code and the one with
the most process in it. That is the right shape. The last sentence of the step
is not a suggestion about tooling, it is a claim about what a fix is worth: a
crash fixed without its input is a fix nobody can ever check again.

No production code changed. **No defects were found in the server**: §6 has the
first soak's numbers — 455 M cases over thirteen seeds nobody had run — and the
one thing that did fail, which is a hang in Step 9's own test harness that
predates this step and now has a stack trace and a preserved input. §7 says
what a clean soak is and is not evidence of. §5 shows the machinery catching
two real defects that earlier steps had already fixed, and finding a gap in the
corpus that covered them.

---

## 1. Why the committed suite is not enough, and why it must stay fixed

Every campaign in this tree runs from a fixed seed by default
(`FUZZ_DEFAULT_SEED`). That is deliberate, and `fuzzing.md` §2 gives the
reason: a suite whose corpus changes from run to run cannot distinguish a
regression from a coincidence, and a red build nobody can reproduce is a red
build people learn to ignore.

The cost is that `make test` asks the same few million questions every time.
After the first green run, every later green run is evidence about the *code*,
not about the *inputs* — the inputs are already known to pass.

So there are two jobs, and they need two mechanisms:

| | seed | who runs it | what a failure means |
|---|---|---|---|
| the committed suite | fixed | `make test`, every time | this change broke something |
| the soak | random, logged | `scripts/fuzz_soak.py`, when there is machine time | these inputs are new and one of them is bad |

The soak never changes what `make test` runs. What it produces is not a new
seed to commit — it is a *file*, and §3 is about why that distinction is the
whole step.

---

## 2. The soak runner

`scripts/fuzz_soak.py`. Each round picks a random 63-bit seed, runs the five
seeded suites at a case multiplier, and logs the seed, the suite, the duration
and the verdict to `tests/security/findings/soak.log`.

```bash
scripts/fuzz_soak.py                       # 4 rounds at x4, every suite
scripts/fuzz_soak.py --minutes 60          # soak for an hour
scripts/fuzz_soak.py --forever --minimize  # until it finds something
scripts/fuzz_soak.py --suite http --mult 20 --keep-going
make fuzz-soak                             # the default run, from the root
```

Three details worth naming.

**The seed is logged before the round, not after.** A round that kills the
machine still leaves the seed behind.

**Every round is a fresh process per suite.** A campaign that corrupts the
`.bss` globals it shares with the next campaign — `tls_*` state, `filename_buf`
— would otherwise make the following suite's failure a story about the previous
one.

**`--mult`, not `--time`, is the knob.** The campaigns are sized so that x1 is
a few seconds; the multiplier scales every campaign in proportion, so a x20
round keeps the same *balance* between them as `make test` has. Spending an
hour on whichever campaign happens to be slowest is not the same thing as
spending an hour fuzzing.

---

## 3. Preserving the input is the harness's job, not the reader's

The rule Step 14 ends on — never fix a crash without preserving the input — is
the kind of rule that gets broken by people who agree with it. The moment a
fuzzer prints a SIGSEGV, the interesting thing is the bug; the input is a
detail you are sure you can get back.

You cannot. Here is the proof, from this tree:

```
✗ flight — CRASH: SIGSEGV at case 83 of 3000
  (reproduce: SARM_FUZZ_SEED=25423240288893562 SARM_FUZZ_CASE=83)
```

That is `fuzzing.md` §9, the five-byte pre-authentication crash. The reproducer
was recorded faithfully, and it is a recipe that regenerates the input *from
the generator*. Replaying it today:

```
$ SARM_FUZZ_TARGET=flight SARM_FUZZ_SEED=25423240288893562 \
  SARM_FUZZ_CASE=83 SARM_FUZZ_DUMP=/tmp/83.bin ./_obj/test_fuzz_tls_handshake
  [flight] wrote 238 input bytes to /tmp/83.bin
```

238 bytes — a full, well-formed flight. Not the five bytes that crashed.
`gen_flight` changed in Step 7's later work, and every seed-based reproducer
recorded against it changed meaning silently. The recipe still runs. It just
cooks something else.

So the harness keeps the bytes instead. Every campaign hands its generated
input to `fuzz_input()` before calling the routine under test, which copies it
into the shared report page — the same page that already carries the case index,
and for the same reason: a child that dies on a guard page dies holding its
input in memory the parent cannot read. When a campaign crashes, hangs or
violates an invariant, the parent writes those bytes out and names the file in
the failure:

```
✗ path — CRASH: SIGBUS at case 38 of 200000
  (reproduce: SARM_FUZZ_SEED=25423240288893562 SARM_FUZZ_CASE=38)
      input preserved: findings/http-path-seed…-case38-crash.bin
      minimise:  scripts/fuzz_minimize.py ./_obj/test_fuzz_http path findings/…
      replay:    SARM_FUZZ_TARGET=path SARM_FUZZ_REPLAY=findings/… ./_obj/test_fuzz_http
```

Nothing has to be remembered, and nothing depends on the generator staying
still. The cost is a copy of a few hundred bytes per case against a case that
costs a few hundred nanoseconds; the `parse` campaign's million cases still run
in 1.2 seconds.

### What a campaign captures when its input is not one buffer

`fuzz_input` takes a flat byte string, and not every case is one. Where a case
is bytes *plus* a knob — a destination capacity, a sequence number, the field
name being looked up — the capture is the part the peer controls, because that
is the part a reproducer needs. Where a case is bytes plus *structure* the peer
also controls — the `frag_*` suites, where a case is a byte string and the
positions it is cut at — there is no byte-level replay at all, and those
campaigns say so in their target tables. Their findings are still captured as
evidence; they are reproduced by seed and case, with the caveat above — and §6
is what that caveat cost the first time it mattered.

---

## 4. From a finding to a test

### The second arrow: `scripts/fuzz_minimize.py`

Delta debugging over bytes, with the harness's replay mode as the oracle. The
whole interface is an exit code:

```bash
SARM_FUZZ_TARGET=<campaign> SARM_FUZZ_REPLAY=<file> <suite binary>
```

zero if those bytes were handled cleanly, non-zero if they still fail. The
minimiser does not know what the failure is — a guard-page SIGSEGV, a broken
invariant and a hang all reduce to "non-zero", which is exactly what makes one
search valid for all three.

Two passes, repeated until a whole pass changes nothing: remove ever-smaller
runs of bytes while the failure survives, then try to replace each surviving
byte with `0x00` and then `'A'`. The second pass is not about size. A
reproducer that is all zeros says *the value of this byte does not matter* more
clearly than a comment can.

On the §9 finding above, from the 238 bytes the harness preserved:

```
$ scripts/fuzz_minimize.py tests/security/_obj/test_fuzz_tls_handshake flight \
      tests/security/findings/tls_handshake-flight-…-crash.bin
flight: 238 bytes -> 5 (49 replays)
  0000  16 03 01 00 00                                   .....
```

Five bytes, in three and a half seconds, and they are byte-for-byte the input
§9 recorded by hand. That is the arrow working: a human wrote those five bytes
into a document once, and the machine now derives them.

### The third arrow: the corpus

`tests/security/corpus/<suite>/<campaign>/<name>.bin`. Every file there is
replayed — from bytes, through the same invariants a generated case runs —
before its campaign starts, on every run, including `make test`:

```
  ✓ flight — corpus: 5 preserved inputs replayed clean
  ✓ flight — 6000 cases
```

and a failure is reported as a regression, by filename:

```
  ✗ flight — corpus REGRESSION: hs-fragment-under-header-len0.bin: SIGSEGV …
```

`--keep <name>` on the minimiser installs the result directly. What it cannot
do is write the row in `corpus/MANIFEST.md` saying what the input is and which
fix it guards — a corpus file nobody can explain is a file nobody dares delete,
and a directory of those is how a regression suite rots into a directory of
superstitions.

**A campaign gets a corpus by having a replay entry.** Splitting each case
function into "generate the bytes" and "run the bytes and check everything" is
the only change this step made to the existing suites. Thirteen of the tree's
24 campaigns now have one — every campaign whose input is a byte string a peer
sends. The eleven that do not are the seven fragmentation campaigns (a case
there is bytes *and* cuts) and four whose input is not a peer's bytes at all:
`roundtrip` and `tamper` seal the server's own plaintext, `read_prefilled`
splits a record between a buffer and a socket, and `finished` drives a real
client through a full handshake.

---

## 5. Verified by sabotage

The machinery makes two claims — that a corpus entry fails when its fix is
removed, and that the preservation path really produces a usable input from a
real crash. Both were checked by putting the two defects of `fuzzing.md` §9 and
§16 back.

**The handshake fragment underflow.** Removing the two-instruction check in
`src/tls/server/handshake.S`:

```
✗ flight — corpus REGRESSION: hs-fragment-under-header-len0.bin: SIGSEGV …
✗ flight — corpus REGRESSION: hs-fragment-under-header-len1.bin: SIGSEGV …
✗ flight — corpus REGRESSION: hs-fragment-under-header-len2.bin: SIGSEGV …
✗ flight — corpus REGRESSION: hs-fragment-under-header-len3.bin: SIGSEGV …
✗ flight — CRASH: SIGSEGV … at case 83 of 6000
      input preserved: findings/tls_handshake-flight-…-case83-crash.bin
```

Four entries fail, the fifth — `hs-fragment-header-exact-len4.bin`, the first
fragment length that is *not* an underflow — stays green, which is what stops a
"fix" that rejects every handshake from passing. And the campaign itself
crashed and preserved its input, which is what §4's minimisation then ran on.

**The three `parse_path` over-reads.** Putting back the two `b.hi`s and the
16-byte window:

```
✗ path — corpus REGRESSION: parse-path-overread-16-byte-window.bin: SIGBUS …
✗ path — corpus REGRESSION: parse-path-overread-step8-original.bin: SIGBUS …
✗ path — corpus REGRESSION: parse-path-overread-trailing-slash.bin: SIGBUS …
✗ path — corpus REGRESSION: parse-path-overread-filename-copy-loop.bin: SIGBUS …
```

The interesting part is what happened when the three instructions were reverted
**one at a time**, which is the question "does this corpus cover the fix?"
rather than "does it notice a broken build?". It did not: with only the copy
loop's `b.hs` put back, every entry stayed green. The three inputs Step 8
recorded reach two of the three sites, and the one the §16 write-up names as
the copy loop's own bound was covered by none of them.

So the missing entry was derived rather than argued about — the pipeline of §3
and §4, run on purpose against a defect that was already fixed:

```
$ SARM_FUZZ_TARGET=path SARM_FUZZ_MULT=10 ./_obj/test_fuzz_http     # copy loop reverted
✗ path — CRASH: SIGBUS at case 22162 of 2000000
      input preserved: findings/http-path-…-case22162-crash.bin
$ scripts/fuzz_minimize.py … path findings/http-path-…-case22162-crash.bin \
      --keep parse-path-overread-filename-copy-loop
path: 17 bytes -> 17 (122 replays)
  0000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 20 2f    AAAAAAAAAAAAAAA /
kept as tests/security/corpus/http/path/parse-path-overread-filename-copy-loop.bin
```

Seventeen bytes, and the byte the loop reads past the end is now a byte one
entry in the corpus is about. The full attribution table — which entry catches
which instruction — is in `corpus/MANIFEST.md`.

This is the evidence that the corpus is a test rather than a museum. An entry
that cannot fail is not preserving anything, and a set of entries that cannot
fail *individually* is not covering a fix.

---

## 6. The first soaks, and what they found

**Soak A** — thirteen rounds at `--mult 8`, on this machine, while other work
was running:

| suite | suite-runs | cases |
|---|---|---|
| `test_fuzz_tls_record` | 12 | 111.4 M |
| `test_fuzz_tls_handshake` | 11 | 176.6 M |
| `test_fuzz_http` | 11 | 158.4 M |
| `test_frag_http` | 10 | 8.0 M |
| `test_frag_socket` | 10 | 0.6 M |
| | | **455 M** |

No crash, no hang, no invariant violation, on thirteen seeds no run had used
before. Every seed is in `soak.log`.

**Soak B** — five rounds over 15.5 minutes, same suites, same multiplier —
failed twice, and so, separately, did a concurrent fixed-seed
`make test-security`. Every failure was the same thing:

```
frag_socket — HANG: no progress for 300s at case 23350
      input preserved: findings/frag_socket-prefilled-…-case23350-hang.bin  (971 bytes)
```

### The hang is real, and it is not in `src/`

Five occurrences over an afternoon, in three different campaigns (`prefilled`,
`record`, `plain`) and on two different builds, and `sample` says the same thing
about each: the campaign child is blocked in a `read()` that will never return
—

```
main -> tls_read_record_prefilled -> .Lraw_read_loop
main -> rec_case -> tls_read_record -> .Lraw_read_loop
main -> plain_case -> tr_deliver -> .Ltr_plain_loop
```

— with `lsof` showing both ends of the case's socketpair still open in that
process and no feeder thread alive to write to them or close them. Replaying
the exact cases in isolation (`SARM_FUZZ_TARGET=prefilled
SARM_FUZZ_CASE=6778`, `record`/`23383`) returns in milliseconds, so it is
scheduling-dependent, not input-dependent.

It is also **not** something this step introduced. Built from a clean worktree
of the commit before it, four concurrent `test_frag_socket` runs at `--mult 8`
produced two hangs within a minute:

```
✗ record — HANG: no progress for 60s at case 23383
✗ prefilled — HANG: no progress for 60s at case 6778
```

The mechanism is somewhere in `frag_common.h`'s feeder — a reader waiting on a
socket that nobody will write to or close again — and finding it belongs to
Step 9's suite rather than to this one. What Step 14 contributed is the part
that was missing before: a failure with a stack, an fd state, a preserved
input, and the knowledge that it predates the change in front of it rather
than being caused by it.

### And it tested this step's own tooling

The first thing the soak did with that finding was hand it to
`fuzz_minimize.py`, which happily reported:

```
prefilled: 971 bytes -> 0 (4 replays)
```

Zero bytes, "minimal", and meaningless: `prefilled` has no byte-level replay
entry, so every replay exited non-zero for the wrong reason and the oracle read
"cannot do this" as "still reproduces". A minimiser whose oracle cannot fail
safely will confidently shrink anything to nothing. The harness now exits **2**
for that case — a distinct code from both "clean" and "reproduces" — and the
minimiser stops on it and says why. It took a real finding, on the first day,
to notice.

---

## 7. What a soak run is evidence of

A clean soak is a weaker statement than it looks, and the same three caveats
`fuzzing.md` §28 records apply here — the campaigns test the routines they
name, generated inputs are not all inputs, and a guard page catches an access
that leaves the buffer, not one that stays inside it and is still wrong.

Step 14 adds a fourth, which is specific to running on random seeds: **a soak
that finds nothing has tested more inputs than the committed suite, and it has
tested them once.** Nothing re-runs them. The only inputs this tree will keep
asking about forever are the ones in `corpus/`, and the only way an input gets
there is by failing. That asymmetry is intentional — it is what keeps `make
test` fast — but it means the honest summary of a green soak is "these
particular new inputs were fine", not "the parser is fine".

What a soak *is* good for is the thing the fixed seed cannot do: it makes the
input space genuinely larger over time, at a cost that is machine time rather
than test time. Run it on the machines and hours nobody is waiting on.

---

## 8. Carried forward

* **Every campaign whose input is a flat byte string has a replay entry.** The
  seven fragmentation campaigns do not, and a case there is bytes plus cuts.
  One of them has already produced a finding (§6) that needed exactly what it
  does not have: preserving that hang properly wants a corpus format carrying
  the split plan as well as the bytes. Until then the harness refuses the
  question (exit 2) rather than answering it wrongly.
* **`test_frag_socket` can hang, and nobody knows why yet.** §6: three
  occurrences, three campaigns, blocked in a `read()` with both ends of the
  socketpair open and no feeder thread; reproducible on the commit before this
  one; not reproducible from the case alone. It belongs to Step 9's suite
  rather than to this one, and it is recorded here because this is where the
  evidence is.
* **`FUZZ_INPUT_MAX` is 20480 bytes.** Larger inputs are captured truncated and
  flagged. Every campaign in this tree generates less than that; a future one
  that does not will need this raised, and a truncated finding is a finding
  whose reproducer needs a human.
* **The corpus is replayed, not fuzzed from.** Nothing here mutates corpus
  entries as a starting population, which is what a coverage-guided fuzzer
  would do with them. That is a deliberate limit of a harness with no coverage
  instrumentation (`fuzzing.md` §1): without coverage there is no signal to
  tell a productive mutation of a preserved input from an unproductive one, and
  the generators already know the structure a mutation would have to
  rediscover.
* **`soak.log` is the only record of what has been run.** It is not committed
  (`findings/` is ignored), because a list of seeds that once passed is not
  evidence anyone can act on. What gets committed is what failed.
