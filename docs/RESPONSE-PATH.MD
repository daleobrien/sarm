# Response-path precomputation — evidence gate, prompts/08

Empirical answer to `prompts/08-precomputed-response-path.md`. **No `.S`
file is changed by this report.** The prompt requires workload evidence
before starting, and the evidence — most of it already gathered by
`docs/PROFILE-POST.MD` (prompt 05), extended here with a source-level
instruction count and a direct `memcpy` benchmark to close the one gap —
says the response path is not worth touching yet.

**Target:** Apple M3 Pro, macOS 27.0, arm64, loopback (same machine/build as
`docs/PROFILE-POST.MD`, commit `b0a868e`). No source changed; `make`
rebuilt only to read symbol sizes with `nm`/`objdump`.

---

## The one-line answer

**Response construction — lookup, header construction, HPACK, frame
construction combined — is ≤0.02% of a connection (≤0.15 µs), and the one
real response-path cost, the body `memcpy`, is ~1.70 µs for a 76,739 B
transfer (2.4% of the transfer scenario, 0.26% of a page-load connection).
Both numbers sit below this session's own stated noise floors (6%
connection-level, 12% transfer-level, from `docs/PROFILE-POST.MD` §1).
None of the five candidates in the prompt clear the gate. No implementation
work is justified.**

---

## 1. Cost breakdown, in the categories the prompt's Method section asks for

| Stage | Where | Share (busy time) | Absolute | Source |
|---|---|---:|---:|---|
| lookup | `lookup_embedded` | not observed (0 self-time samples, 56,935 busy samples across all scenarios) | — | `docs/PROFILE-POST.MD` §4, ranked table; own brief is prompt 10 |
| header construction | `h2_write_headers`, `http1_write_response`, `create_response` (all HPACK-encoding inline, see §2) | folded into "H2 / HTTP framing": 0.15% (pageload), 0.52% (transfer), 1.56% (request) | ≤0.15 µs/conn (pageload) | `docs/PROFILE-POST.MD` §3, §7 ("Response construction" row) |
| HPACK | same functions — the response path has no separate encode step (§2) | counted above; decode-side `h2_hpack_decode_field` separately <0.1% | — | `docs/PROFILE-POST.MD` §4 |
| frame construction | frame-header stamping in `h2_write_headers`/`h2_write_body` | counted above (same functions) | — | — |
| copying | `memcpy` (`util` bucket) | 3.95% of **transfer** busy time; negligible elsewhere | **~1.70 µs** for a 76,739 B body (measured, §3 below) | `docs/PROFILE-POST.MD` §3 + this report's `bench_memcpy` run |
| encryption | AES-GCM record crypto | 17.38% (transfer), 2.37% (pageload) | ~15.6 µs/conn total | `docs/PROFILE-POST.MD` §1, §3 — already prompt 03's territory, not this one's |
| write | `transport / syscalls / accept loop` | 76.63% (transfer), 93.97% (request) | dominant | `docs/PROFILE-POST.MD` §3 — fixed per-`write()`-call syscall cost, not reducible by precomputation (§4 below) |

"Header construction", "HPACK" and "frame construction" are one measured
bucket because they are one function in this codebase — see §2. The
`docs/PROFILE-POST.MD` §7 table already has a row for exactly this
prompt: **"Response construction … ≤0.02% everywhere measured … ≤0.15
µs/conn … Not measurable."** This report does not repeat that measurement;
it explains *why* (§2) and closes the one thing that table left as a
named-but-unquantified follow-on — the `memcpy` (§3).

---

## 2. Why header construction, HPACK and frame construction are one cost, and why it's small

`src/h2/h2_write_headers.S` is the entire response-side HPACK encoder: it
builds `:status`, `content-type`, `content-length`, `content-range`
(ranged only) and `content-encoding: gzip` (gzipped assets only) directly
into `h2_frame_buf` behind the 9-byte frame header, in HPACK's
literal-with-indexed-name form, then stamps the frame header and does one
`write_all`. `objdump`/`nm` on the current binary:

```
h2_write_headers   0x100006160–0x100006454   756 B  (189 instructions)
h2_write_body      0x100005f0c–0x100006160   596 B  (149 instructions)
http1_write_response  0x100007878–0x100007bb8  832 B  (208 instructions)
create_response    0x100007550–0x1000075b8   104 B  ( 26 instructions)
```

Called 6 times per page-load connection (`docs/PROFILE-POST.MD` §4's
ranked table, cross-checked with `scripts/count_calls.py`). Even crediting
every instruction in `h2_write_headers` + `h2_write_body` (338
instructions × 6 calls ≈ 2,000 instructions) at a generous 1 instr/cycle
on a ~3 GHz core gives well under 1 µs — consistent with, and a sanity
check on, the sampled ≤0.15 µs/conn figure. There is no separate HPACK
encode/frame-build/copy stage to precompute independently: the prompt's
candidates 2–4 (precompute headers, precompute HPACK, precompute whole
frames) all target the same ~189+149-instruction, 6-call-per-connection
piece of code, which the profile already places at the sampler's
resolution floor.

`lookup_embedded` (candidate 1) is explicitly out of scope here — own
brief, `prompts/10-embedded-lookup.md` — and independently confirmed
unmeasurable (0 self-time samples).

---

## 3. The one real signal: the body `memcpy` (candidate 5)

`h2_write_body.S:113-117` copies each ≤16,384 B DATA-frame chunk from the
embedded body pointer into `h2_frame_buf` right behind the frame header —
the code's own comment flags this ("zero-copy DATA is a later stage").
This is the only response-path cost `docs/PROFILE-POST.MD` measured as
non-trivial (3.95% of **transfer**-scenario busy time), so it's the one
candidate worth quantifying precisely rather than citing secondhand.

Measured directly (`scripts/benchmarks/bench_memcpy`, current tree, same
`asm_memcpy` the response path calls):

```
{"16":2.030,"64":4.144,"256":8.666,"1024":27.034,"4096":109.381,"65536":1468.852} ns
```

Asymptotic rate from the two largest points: `(1468.852-109.381)/(65536-4096)
× 1024 ≈ 22.66 ns/KiB`. A page-load's largest transfer (76,739 B, the
`docs/PROFILE-POST.MD` transfer-scenario payload, split into 5 DATA-frame
chunks of ≤16,384 B each) costs:

```
76,739 B × 22.66 ns/KiB / 1024 ≈ 1.70 µs total memcpy for the whole body
```

against that scenario's ~71.6–79.3 µs marginal cost (**2.3%**) and the
657.2 µs page-load connection total (**0.26%**). No TLS-side copy exists to
add to this: `tls_record_encrypt` (`src/tls/record/encrypt.S`) has no
`memcpy` — the AES-GCM chain reads/writes via NEON directly — so the
"copied into a staging buffer, then again during record encryption" case
the prompt's candidate 5 describes is only a single copy in this codebase,
not two.

The prompt's own noise-floor rule (`docs/PROFILE-POST.MD` §1): **don't
claim a win below 6% connection-level or 12% transfer-level on this
harness today.** A **complete, 100% elimination** of this `memcpy` — which
"encrypt directly from the embedded table into the output buffer" would
have to achieve, and which is a real engineering effort against
`tls_app_data_write`'s single-contiguous-plaintext interface and the H2
frame-header-then-body layout — clears neither floor (2.3% < 12%, 0.26% <
6%).

---

## 4. Why "write" (syscalls) isn't fixed by this prompt's candidates either

`transport / syscalls / accept loop` dominates every scenario except
handshake (76.63% transfer, 93.97% request) — but it is not response
*construction* cost, and none of the five candidates change the number of
`write()` calls. The response path already coalesces maximally: one
`write_all` per HEADERS frame (`h2_write_headers.S:227-232`, "header +
block can't be split") and one `write_all` per DATA frame
(`h2_write_body.S:118-123`, "one write per frame"). A small embedded asset
(all six current assets are ≤16,384 B — single DATA chunk) already sends
in exactly 2 writes: one HEADERS, one DATA. Precomputing whole frames
(candidate 4) would still be 2 writes for such a response; it does not
reduce syscall count, only the (already ≤0.15 µs) construction time ahead
of it. The syscall cost itself is a fixed per-call OS overhead this
prompt's precomputation strategy cannot touch — TCP/TLS record chunking
and `write()` overhead, not build-time-knowable response bytes.

---

## 5. Per-candidate verdict

| # | Candidate | Verdict | Why |
|---|---|---|---|
| 1 | Asset lookup index | out of scope | Own brief, `prompts/10`; independently confirmed unmeasurable |
| 2 | Precompute per-asset response headers | **not justified** | Header construction is ≤0.15 µs/conn total (§2); nothing to recover |
| 3 | Precompute HPACK encoding | **not justified** | Same function, same measurement, as #2 — HPACK isn't a separable stage here |
| 4 | Precompute whole HEADERS/DATA frames | **not justified** | Same as #2/#3 for construction; doesn't reduce write() count either (§4) |
| 5 | Encrypt directly from embedded data (skip the staging `memcpy`) | **not justified** | Only ~1.70 µs/76,739 B body (§3) — 2.3% of transfer, 0.26% of a connection, below both noise floors even at 100% elimination |

All five candidates fail the prompt's own gate: *"Do not optimize the
response path simply because an opportunity exists"* and *"An improvement
confined to a microbenchmark of header construction, with no measurable
effect on end-to-end request latency once encryption cost is accounted
for, is not a pass."* Candidate 5 is the closest to real, and it is still
roughly 5x below the transfer-scenario noise floor at a **theoretical
100%** elimination — no partial implementation of it could do better.

This is the same shape of outcome `docs/PROFILE-POST.MD` reached for
register-pressure optimization (prompts 06/07): a fresh, honest
measurement against the current (post-03/04) profile, producing a valid
"not yet" rather than a forced target.

---

## 6. Binary size

No source file was changed; binary size delta is **0 bytes**. Had any of
candidates 2–4 been implemented, the size cost would be bounded by the
embedded-asset count (currently 6 files) × a small fixed per-asset header
block plus stream-ID patch logic — cheap in absolute terms, but the
runtime benefit that would need to justify it doesn't exist per §5.

---

## 7. Recommendation

**Do not implement any part of prompts/08 at this time.** Response
construction is at the sampler's resolution floor, and the one real
signal (the body copy) is a theoretical 2.3%/0.26% ceiling against a
12%/6% noise floor — an order-of-magnitude gap, not a close call. Nothing
here regresses HTTP/1.1, HTTP/2, ranges, HEAD, or error responses, because
nothing was changed.

Per `docs/PLAN.MD`/`prompts/README.md`'s standing discipline: this
conclusion holds for the current profile. If `p256_point_mul`'s deferred
fixed-base comb (the largest remaining opportunity, 45.4% of a connection,
`docs/PROFILE-POST.MD` §10) lands and shrinks the connection total, every
percentage in this report shrinks in its denominator too — the same
"smaller pie, bigger slice" effect `docs/PROFILE-POST.MD` §5 finding 6
flagged for X25519. Re-check this prompt after that lands, not before;
re-deriving it now on an assumption would repeat the mistake `06/07`
already avoided once.

### Reproducing

```bash
make                                                        # nm/objdump need symbols
nm -n sarm | awk '$2=="T"{print $1, $3}' | grep -A1 -E \
  ' (h2_write_body|h2_write_headers|create_response|http1_write_response)$'
cd scripts/benchmarks && make bench_memcpy && ./_bench_bin/bench_memcpy
```

The rest of the evidence (`docs/PROFILE-POST.MD` §1, §3, §4, §7) is
reproduced via that document's own §9 "Reproducing" section — this report
adds only the `nm`/`bench_memcpy` steps above.
