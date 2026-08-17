# Workload Profile — where sarm's CPU time actually goes

Empirical answer to `prompts/00-workload-profile.md`. Measurement only: no
`.S` file was modified, and nothing was added to the shipped binary.

**Target:** Apple M3 Pro (6 P-cores + 6 E-cores), macOS 27.0 (26A5406e),
arm64, loopback. Results do not transfer to Cortex/Neoverse.
**Build:** `make` (local symbols kept), commit `676d517`.

---

## The one-line answer

For the workload sarm is actually written for — a browser opening a
connection and pulling six small embedded assets over TLS 1.3 + HTTP/2 —
**81% of the server's CPU time is the TLS handshake, and half of the whole
connection is one call to `p256_ecdsa_sign_with_k`.** Serving the bytes
costs 5.5%. Parsing the requests costs 5.1%.

| | µs of server CPU | share of connection |
|---|---:|---:|
| TLS 1.3 handshake | 1238.9 | 81.4% |
| — of which ECDSA CertificateVerify | 777.9 | 51.1% |
| — of which the Barrett reduction inside it | 533–576 | 35–38% |
| — of which X25519 key agreement (×2) | 62.8 | 4.1% |
| 6 requests (HPACK + H2 framing + syscalls) | 77.5 | 5.1% |
| 80,851 response bytes (AES-GCM + `write`) | 84.4 | 5.5% |
| unattributed (connection setup, teardown, plumbing) | 121.1 | 8.0% |
| **measured total, one page-load connection** | **1521.9** | **100%** |

This contradicts the ordering in `prompts/README.md`, which puts AES-GCM
throughput (prompt 03) ahead of P-256 (prompt 04) as "the largest
per-byte win". It is the largest per-byte win, but per-byte cost is 5.5%
of a connection, so the win is bounded at ~3%. See
[Recommended order](#recommended-order-for-prompts-0308).

---

## 1. Scenario results

`scripts/profile_workload.py` runs `./sarm d` as a child process and reads
its CPU time from `getrusage(RUSAGE_CHILDREN)` after it exits. The client
is `tests/h2_browser_sim.py`'s `Connection`, reused as-is, with a
completion-aware read loop added so a measurement is not dominated by the
correctness suite's timeouts.

**Wall clock is not the measurement.** The client is Python, and on the
transfer scenario its own TLS record decryption costs several times what
sarm's encryption does, so wall clock measures the client. Every number
below is server-process CPU (user + sys). Wall clock is reported by the
tool and labelled for what it is.

Each scenario is run at three workload sizes, five rounds each after a
discarded warm-up, and a least-squares fit separates the fixed cost the
scenario pays once from the marginal cost of one more unit. Reading the
marginal cost off a single size folds the handshake into it — a 30–60%
error on the per-request number at these sizes.

| Scenario | Unit | Marginal cost | Fixed | R² | Round-to-round spread |
|---|---|---:|---:|---:|---|
| handshake | one connection: handshake, one 104 B GET, close | **1238.9 µs** | 1.77 ms | 0.99999 | 0.8–1.8% |
| transfer | one 76,739 B GET on an established connection | **93.0 µs** | 5.51 ms | 0.9998 | 1.4–14.8% |
| request | one 104 B GET on an established connection | **12.92 µs** | 3.19 ms | 1.0000 | 1.5–3.0% |
| pageload | one connection: document + 5 subresources, close | **1521.9 µs** | −1.26 ms | 0.9998 | 1.4–7.5% |

Sizes: handshake/transfer/pageload at 50/100/200 units, request at
500/1000/2000. The fitted "fixed" term is process start plus, for the
single-connection scenarios, the one handshake they each pay; the
handshake scenario's 1.77 ms fixed term matches the 1.49 ms measured for
starting and stopping the server with no connections at all.

**User/sys split**, which is the fastest way to see what a scenario is:

| Scenario | user | sys |
|---|---:|---:|
| handshake | 89% | 11% |
| transfer | 56% | 44% |
| request | 22% | 78% |

The handshake is arithmetic. The request path is syscalls.

### The linear model closes

The three scenarios predict the fourth. A page-load connection is one
handshake, six requests and 80,851 bytes:

```
1238.9  +  6 × 12.92  +  80851 × 1.044 ns  =  1400.8 µs   predicted
                                              1521.9 µs   measured  (92%)
```

The 8% residual is the two-phase structure of a real page load (document
first, then subresources), which costs extra read/write round trips that
neither single-asset scenario pays.

### Per-byte cost

```
(93.02 − 12.92) µs / 76,739 B = 1.044 ns/byte = 958 MB/s
```

---

## 2. Attribution to functions

Two independent methods, as the prompt requires.

### Method A — sampled time profile (`scripts/profile_samples.py`)

**`xctrace` is not usable on this machine.** It requires a full Xcode
install; this machine has Command Line Tools only, and `xctrace` refuses
to start (`tool 'xctrace' requires Xcode`). `/usr/bin/sample` is the same
class of instrument — a periodic PC sampler over a live task — and it is
present, so it is what was used. `dtrace` is present but restricted by
SIP and needs root, so it was not attempted.

Load is driven by four concurrent client processes so the single-threaded
server stays busy; `sample` samples a blocked thread as readily as a
running one, and an idle server piles every sample onto whichever `svc`
it is parked in. Residual idle (the accept-loop block) is measured and
excluded, and it is small: 115 of 16,898 samples (0.68%) in the handshake
run, 48 of 16,940 (0.28%) in pageload, 8 of 17,154 (0.05%) in transfer,
4 of 17,004 (0.02%) in request. ~17,000 samples per scenario at 1 ms.

Two attribution corrections were needed, and both changed the answer:

- `sample` names the nearest preceding symbol *including* `.L…` labels,
  which splits one function across a dozen rows. Attribution here uses the
  bracketed absolute PC and resolves it against `nm`'s `T` symbols only.
- `src/crypto/gcm/data.S` emits the GHASH block into `.text` and all four
  gcm files `#include` it, so each copy sits *before* its file's exported
  function. Uncorrected, `aes_gcm_encrypt`'s GHASH was charged to
  `aes_gcm_decrypt`, and the transfer profile claimed 29% of server time
  went into decrypting a few hundred 26-byte `WINDOW_UPDATE` records.

### Method B — microbenchmark × call count

`scripts/benchmarks/bench_primitives.c` links the repo's own object files
and times each primitive directly, checking a correct answer first (GCM
round trip, agreeing X25519 secrets, a known SHA-256 state).

`scripts/count_calls.py` drives sarm under `lldb` with auto-continuing
breakpoints and reads the hit counts back, so call frequency is measured
rather than assumed and no instrumented binary ever exists.

The two are multiplied and compared against the `getrusage` totals from
§1 — a closed comparison that shares nothing with the sampler.

> One thing had to be worked around, and it is worth knowing:
> **`aes128_encrypt` clobbers v8–v11 without restoring them**
> (`src/crypto/aes128/encrypt.S:47`; its own header documents this).
> AAPCS64 makes the low 64 bits of v8–v15 callee-saved. Inside sarm every
> caller is assembly and nothing depends on them, but C code that keeps a
> `double` live across the call gets it silently corrupted — the first
> version of this benchmark reported GCM costs of 1e86 ns rather than
> crashing. `bench_primitives` therefore calls through an assembly
> trampoline with v0–v31 declared clobbered. x19–x28 were probed
> separately and *are* preserved by every function measured here.

---

## 3. Cost breakdown

Self time as a share of non-idle samples, Method A. "Transport/syscalls"
is `raw_read_exact` + `raw_write_all` and conflates real syscall work with
time blocked waiting for the client — read it as an upper bound.

| Cost centre | handshake | transfer | request | pageload |
|---|---:|---:|---:|---:|
| handshake asymmetric crypto (P-256, X25519) | **76.5%** | 2.3% | 1.0% | **60.2%** |
| transport / syscalls / accept loop | 22.8% | **55.3%** | **94.1%** | 36.0% |
| AES-GCM record crypto | 0.2% | **37.5%** | 2.1% | 2.9% |
| transcript / key schedule (SHA-256, HKDF) | 0.3% | 0.0% | 0.0% | 0.3% |
| H2 / HTTP framing | 0.1% | 0.6% | 1.0% | 0.2% |
| HPACK | 0.0% | 0.1% | 0.3% | 0.0% |
| TLS record framing | 0.0% | 0.2% | 0.2% | 0.1% |
| util (`memcpy`) | 0.0% | 4.1% | 1.2% | 0.3% |

### Method A vs Method B

| Scenario | Cost centre | A (sampled, wall) | B (bench × counts, CPU) | ratio |
|---|---|---:|---:|---|
| handshake | asymmetric crypto | 76.5% | 67.9% | 1.13× |
| handshake | `p256_ecdsa_sign_with_k` alone | 69.1% (855.8 µs) | 777.9 µs | 1.10× |
| handshake | everything else | 23.5% | 32.1% | 1.37× |
| transfer | AES-GCM | 37.5% (45.6% of non-blocked) | 53.5% | 1.17× |
| transfer | GHASH share *within* AES-GCM | 79.0% | 79.0% | **1.00×** |
| handshake | `p256_reduce` share *within* `p256_fe_mul` | 74.2% | 73.3% | **1.01×** |
| request | crypto | 2.1% | 5.2% | 2.5×† |
| request | syscalls + framing | 94.1% | 94.8% | 1.01× |

Both methods put the same three cost centres in the same order for every
scenario, and agree to within 1.2× on everything that matters. The two
ratios that land on 1.00× are the strongest evidence the attribution is
right: they are internal splits, so the sampler's wall-clock bias and the
benchmark's cache-warmth bias both cancel.

† The request-scenario crypto disagreement is 2.5× on a quantity that is
2–5% of a 12.9 µs number — 0.4 µs of absolute disagreement, below the
noise floor. It does not change any conclusion.

The systematic ~1.1× gap on the handshake is in the expected direction:
`bench_primitives` runs `p256_ecdsa_sign_with_k` 300 times in a row with
hot caches and trained branch predictors, while the server runs it once
per connection cold. Method B is a lower bound on the real cost.

---

## 4. Ranked function table

Share is of a **page-load connection** (1521.9 µs), which is the workload
that matters. Confidence is *high* where both methods agree within 1.2×,
*medium* where only one method resolves it, *low* where the number is at
or below the noise floor.

| # | Function | Share | Calls/conn | Calls/req | Method | Confidence |
|---|---|---:|---:|---:|---|---|
| 1 | `p256_bn_mul` | 51.5% | ~26,000 | 0 | sample self; derived count | high |
| 2 | `raw_read_exact` | ≤27.9% | 12 | 1.8 | sample self (includes blocking) | medium |
| 3 | `raw_write_all` | 7.9% | 9 | 2.0 | sample self | high |
| 4 | `crypto_random_bytes` | 2.4% | 3 | 0 | sample self; lldb count | high |
| 5 | `ghash` (inlined gcm block) | 2.2% | 36 (3 per GCM call) | 8.7 | sample self; lldb + source | high |
| 6 | `p256_reduce` | 1.6% self, 37.9% incl. | ~8,500 | 0 | sample; bench | high |
| 7 | `x25519_fe_mul` | 1.5% | — | 0 | sample self | medium |
| 8 | `x25519_fe_sqr_times` | 1.1% | — | 0 | sample self | medium |
| 9 | `p256_fe_add` / `p256_fe_sub` | 0.8% | ~11,000 | 0 | sample self; derived | medium |
| 10 | `aes128_encrypt` | 0.4% | ~200 | ~4,800/76 KB | sample self; 1 per 16 B | high |
| 11 | `memcpy` | 0.3% | — | — | sample self | medium |
| 12 | `aes_gcm_encrypt` (excl. GHASH) | 0.3% | 8 | 2.0 | sample self; lldb | high |
| 13 | `h2_stream_find` | <0.2% | 6 | 7.6 | sample self; lldb | low |
| 14 | `h2_hpack_decode_field` | <0.2% | 9 | 9.0 | sample self; lldb | low |
| 15 | `sha256` | <0.2% | 127 | 0 | sample self; lldb | low |
| 16 | `hmac_sha256` / `hkdf_expand_label` | <0.1% | 21 / 16 | 0 | lldb count; bench | low |
| — | `h2_huffman_decode` | not observed | 0* | 0* | lldb count | see caveat |
| — | `ghash` / `gf_mult_128` (exported) | **0** | 0 | 0 | lldb count; source | high |

Inclusive shares for the enclosing functions, handshake scenario, % of
non-idle samples: `p256_ecdsa_sign_with_k` 69.1%, `p256_point_mul` 65.5%,
`p256_fe_mul` 63.9%, `p256_reduce` 47.4%, `p256_point_add` 45.6%,
`p256_point_dbl` 30.8%, `x25519` 3.7%.

### Measured per-call costs

`scripts/benchmarks/bench_primitives`, minimum of 9 rounds, net of the
0.84 ns trampoline. Second column is an independent re-run.

| Function | ns/call | re-run | Δ |
|---|---:|---:|---:|
| `p256_ecdsa_sign_with_k` | 777,939 | 771,229 | −0.9% |
| `p256_point_mul` (256-bit k) | 755,082 | 751,169 | −0.5% |
| `x25519` | 31,394 | 30,089 | −4.2% |
| `aes_gcm_encrypt` 16 KiB | 10,400 | 10,573 | +1.7% |
| `ghash` 16 KiB | 8,219 | 8,420 | +2.4% |
| `aes_gcm_encrypt` 1 KiB | 736 | 750 | +1.9% |
| `sha256` (per 64 B block) | 25.2 | 25.8 | +2.4% |
| `aes_gcm_encrypt` 26 B (fixed cost) | 107.4 | 110.7 | +3.0% |
| `p256_fe_mul` | 81.1 | 83.4 | +2.8% |
| `aes_gcm_decrypt` 26 B | 66.4 | 68.5 | +3.2% |
| `aes128_key_expand` | 62.8 | 64.3 | +2.4% |
| `p256_bn_mul` 5×5 | 29.1 | 30.5 | +4.8% |
| `p256_bn_mul` 4×4 | 21.6 | 22.5 | +4.0% |
| `aes128_encrypt` (1 block) | 0.91 | 0.90 | −1.1% |

### Call counts per connection

`scripts/count_calls.py`, one page-load connection. Marginal per-request
counts are the difference between a 21-request and a 1-request run on one
connection, divided by 20.

| Function | per connection | per request | per 76,739 B asset |
|---|---:|---:|---:|
| `p256_ecdsa_sign_with_k`, `p256_point_mul`, `p256_scalar_inv` | 1 | 0 | 0 |
| `x25519` | 2 | 0 | 0 |
| `crypto_random_bytes` | 3 | 0 | 0 |
| `p256_scalar_mul` | 427 | 0 | 0 |
| `sha256` | 127 | 0 | 0 |
| `hmac_sha256` | 21 | 0 | 0 |
| `hkdf_expand_label` / `hkdf_expand` | 16 | 0 | 0 |
| `aes_gcm_encrypt` | 8 | 2.0 | 11.6 |
| `aes_gcm_decrypt` | 4 | 0.9 | 4.2 |
| `aes128_key_expand` | 12 | 2.9 | 15.8 |
| `raw_read_exact` | 12 | 1.8 | 8.4 |
| `raw_write_all` | 9 | 2.0 | 11.6 |
| `h2_hpack_decode_field` | 9 | 9.0 | 9.0 |
| `h2_stream_find` | 6 | 7.6 | 14.4 |
| `h2_process_request` / `h2_write_headers` / `h2_write_body` | 1 | 1.0 | 1.0 |

---

## 5. Findings that change what should be optimized

**1. The ECDSA signature is the workload.** One `p256_ecdsa_sign_with_k`
per connection at 778 µs is 51% of a page-load connection. Nothing else
is within an order of magnitude.

**2. Inside it, the reduction costs nearly three times the multiplication.**
`p256_fe_mul` is one 4×4 `p256_bn_mul` followed by `p256_reduce`, and
`p256_reduce` is *Barrett* reduction — `q1*mu` (5×5) and `q3*p` (5×4),
i.e. **two more `p256_bn_mul` calls** (`src/crypto/p256/sqr_mul.S:54,62`).
So every field multiply is three big multiplies, and the reduction is 73%
of it (bench: 59.4 ns of 81.1 ns; sample: 74.2% of `p256_fe_mul`'s
inclusive time — the two methods agree to 1%).

P-256's prime is a Solinas prime: `2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1` reduces
with about a dozen 256-bit adds and subtracts and no multiplication at
all. Replacing Barrett with the Solinas reduction is a change to one
file that plausibly takes `p256_fe_mul` from 81 ns to under 30 ns —
**35–38% of every connection**, and it is independent of, and larger than,
the comb-table work prompt 04 currently describes.

**3. GHASH, not the AES chain, is the AES-GCM bottleneck.**
`prompts/README.md` says the per-byte cost is dominated by
`aes_gcm_encrypt` calling `aes128_encrypt` once per 16-byte block,
"serializing the AESE dependency chain". Measured, `aes128_encrypt` costs
0.91 ns per 16-byte block — 0.057 ns/byte, **9%** of AES-GCM. GHASH is
**79%** (8,219 ns of 10,400 ns for 16 KiB; the sampled profile
independently gives 79.0%). The AESE chain is already fast because the
M3 runs it on the crypto unit; the GHASH is a software carry-less
multiply. `pmull`/`pmull2` on the M3's PMULL unit is the win here, not
multi-block AES.

**4. `aes128_key_expand` runs on every record.** Both
`aes_gcm_encrypt` and `aes_gcm_decrypt` expand the key schedule on entry
(`gcm/encrypt.S:73`, `gcm/decrypt.S:73`), 62.8 ns per call. That is 58%
of the 107 ns fixed cost of a small record, and 15.8 redundant expansions
per large asset served. The TLS key does not change within a connection;
hoisting the schedule into the connection state removes it outright.

**5. The exported `ghash` and `gf_mult_128` are dead code on the server
path.** Every GCM caller uses the `.Lgcm_ghash_run` copy that
`src/crypto/gcm/data.S` includes into its own translation unit; nothing
in `src/` calls the exported symbols (verified by `grep` and by zero lldb
breakpoint hits across all four workloads). `docs/REGISTER-PRESSURE.MD`
ranks `ghash` fourth by recoverable save/restore traffic — optimizing it
would change nothing that runs.

**6. The per-request path is syscalls, not parsing.** 12.92 µs per
request, 78% of it kernel time, 94% of samples in `raw_read_exact` /
`raw_write_all`. Per request the server makes ~1.8 reads and ~2.0 writes;
per large asset, 11.6 writes and 11.6 separate `aes_gcm_encrypt` calls
(≈6.6 KB per TLS record). HPACK and H2 framing together are under 1.5%
of any scenario.

**7. The transfer path spends as much in `write` as in crypto.**
`raw_write_all` 37.2% vs AES-GCM 37.5% of non-idle samples. Larger TLS
records (16 KiB rather than 6.6 KB) would cut both the syscall count and
the per-record fixed cost, and needs no cryptography work at all.

---

## 6. Method and its limits

### What was measured

- **Server CPU, not wall clock**, via `getrusage(RUSAGE_CHILDREN)` on a
  child `./sarm d`. This excludes the Python client entirely.
- **Marginal cost by linear fit** over three workload sizes, so the
  one-off handshake does not contaminate per-request numbers.
- **Sampled attribution** with `/usr/bin/sample` at 1 ms, four concurrent
  clients, accept-loop idle excluded.
- **Per-call cost** by direct benchmark against the repo's own objects.
- **Call frequency** by `lldb` breakpoint hit counts.

### What the numbers cannot support

- **`sample` measures wall time in the process, not CPU.** A thread
  blocked in `read()` is sampled at the same rate as one doing work.
  `raw_read_exact`'s self time is therefore an upper bound that mixes
  syscall cost with waiting, and it is why Method A's crypto shares run
  ~1.1× above Method B's. Every conclusion here is stated so that it
  survives that bias.
- **No call tree for the deepest frames.** `sample`'s unwinder roots some
  subtrees directly on the thread, so inclusive times are reliable for the
  top of a subtree and not for reconstructing every caller/callee edge.
- **No hardware counters.** No `perf`, no `llvm-mca`, no PMU access. There
  are no cycle, IPC, branch-miss or cache-miss numbers anywhere in this
  document, and none can be produced on this machine.
- **`xctrace` was unavailable**, so the prompt's first-choice tool was not
  used. `sample` is a close substitute but has coarser symbolication and
  no CPU-time filter.
- **The client is not a browser.** `tests/h2_browser_sim.py` encodes
  header values as raw literals, not Huffman, so `h2_huffman_decode`
  never ran in any measurement here. A real browser Huffman-codes header
  values and would call it roughly once per header field, ~9 times per
  request. Its cost is bounded by the HPACK cost centre, which is ≤0.3%
  of any scenario — but the count of 0 in the table above is an artifact
  of the client, not a property of the workload.
- **No core pinning.** macOS on Apple Silicon exposes no thread-affinity
  API, so the server may migrate between P- and E-cores. This is absorbed
  into the noise floor rather than eliminated; it is the main reason the
  transfer scenario is the noisiest.
- **The single-connection scenarios cannot see fork cost.** The `no_fork`
  debug path is used so one process serves everything and its rusage is
  the whole workload. Production forks per connection
  (`src/sarm/main.S:301`), which adds a per-connection cost this profile
  does not measure. It is bounded by the ~1.5 ms process create/destroy
  cost measured in the noise scenario, and would make the per-connection
  picture *more* handshake-dominated, not less.
- **Method B is a lower bound.** Benchmarked primitives run hot; the
  server runs them cold, once per connection.

### Noise floor

Stated as numbers, so later prompts know what is too small to claim.

| Quantity | Reproducibility | Absolute floor |
|---|---|---|
| Per-connection marginal (handshake) | +0.8% across two full sweeps | ±10 µs |
| Per-request marginal | +0.5% | ±0.07 µs |
| Per-page-load marginal | −2.8% | ±43 µs |
| Per-large-request marginal (transfer) | +7.4% | ±7 µs |
| Round-to-round CPU median, largest size | 0.8–1.5% | — |
| Round-to-round CPU median, smallest size | up to 14.8% | — |
| Microbenchmarked ns/call | ≤4.8%, typically ≤3% | — |
| Sampled share (17,000 samples @ 1 ms) | ±8% relative at a 1% share | shares below ~0.5% are not resolved |

**Rule for prompts 03–09: do not claim a win below 3% on the
per-connection or per-request path, or below 10% on the per-byte
(transfer) path.** Anything smaller is inside the run-to-run spread of
this harness. A change to a single function that moves the page-load
connection by less than ~45 µs cannot be distinguished from noise by
these tools.

### Reproducing

```bash
make                                              # keep local symbols
python3 scripts/profile_workload.py --rounds 5    # §1
python3 scripts/profile_samples.py handshake      # §3, and transfer/request/pageload
make -C scripts/benchmarks bench_primitives && ./scripts/benchmarks/bench_primitives
python3 scripts/count_calls.py --workload pageload --requests 1
```

`scripts/profile_samples.py` needs `nm`, which is an `xcrun` shim: do not
wrap these commands in an x86_64 `timeout`, or `nm` fails to load
`libxcrun` and the symbol table comes back empty.

---

## Recommended order for prompts 03–08

### Run first: prompt 04 (P-256), rescoped

**Addressable: ~51% of a page-load connection.** But the prompt as written
targets "precomputed comb tables" for `p256_point_mul`. The data says do
the reduction first:

1. **Replace Barrett with the P-256 Solinas reduction** in
   `src/crypto/p256/sqr_mul.S`. `p256_reduce` is 73% of `p256_fe_mul` and
   ~35% of the whole connection, and it is 73% because it does two extra
   `p256_bn_mul` calls that the special form of `p` makes unnecessary.
   One file, no algorithmic change to the curve arithmetic, and the
   constant-time property is easier to preserve than with tables.
2. **Then** comb tables for `p256_point_mul`. Still worth doing —
   double-and-add over 256 bits with no precomputation is ~8,200 field
   multiplies, because constant time means `p256_point_add` runs a full
   `p256_point_dbl` of its own every iteration
   (`src/crypto/p256_point/add.S:155`), so each of the 256 bits costs two
   doublings and one addition — but it multiplies a cost that step 1 has
   already cut by ~3×, and the constant-time table scan (every entry,
   always) is the riskiest constraint in the repo.

Either step alone clears the noise floor by more than an order of
magnitude.

### Run second: prompt 08 (precomputed response path), rescoped upward

**Addressable: ~11% of a page-load connection** (the request and byte
paths together), and the profile says the win is not in precomputing more
bytes — it is in making fewer, larger syscalls. 11.6 `write` calls and
11.6 `aes_gcm_encrypt` calls per 76 KB asset means ~6.6 KB TLS records;
16 KiB records would cut both counts by 2.5×, and `raw_write_all` alone is
7.9% of a connection. Hoisting `aes128_key_expand` out of the per-record
path (finding 4) belongs here too: 62.8 ns × 15.8 calls per large asset.

### Run third: prompt 03 (AES-GCM), retargeted

**Addressable: ~3.4% of a page-load connection** — the per-byte path is
5.5% and AES-GCM is 62% of it. Worth doing, but only third, and **not for
the reason the prompt gives**. Multi-block AES is aimed at
`aes128_encrypt`, which is 9% of AES-GCM. The target is GHASH at 79%:
`pmull`/`pmull2` instead of the software carry-less multiply in
`src/crypto/gcm/data.S`. A 4× GHASH speedup is ~2.5% of a connection —
just clear of the 3% floor at the page-load level, comfortably clear on
the transfer scenario where it is 30% of the work.

### Do not run: prompts 05, 06 and 07 (register overhead)

`prompts/README.md` already makes 06 and 07 conditional on 05 showing the
overhead is measurable. **It is not measurable with these tools, and the
ceiling is below the noise floor.** Concretely:

- The hottest function in the entire profile, `p256_bn_mul` (51% of a
  connection), is a **leaf with no stack frame and no callee-saved
  traffic**. There is nothing for this work to remove from it.
- The next two, `p256_fe_mul` and `p256_reduce`, each hold `x19`/`x20`
  live across their calls to `p256_bn_mul`. `docs/REGISTER-PRESSURE.MD`
  classifies exactly this pattern as justified and excludes it. Even if
  both frames could be removed entirely — they cannot — it is 4
  instructions × ~17,000 calls ≈ 1% of a connection.
- `docs/REGISTER-PRESSURE.MD`'s own priority list is, measured against
  this workload, cold: `h2_huffman_decode` (#1) sits behind HPACK at
  ≤0.3% of any scenario; `ghash` (#4) is **never called**; the entire
  non-crypto handshake-plumbing group, which is where
  `tls_server_handshake` (#4) lives, is 0.04% self time;
  `x25519_fe_scalar_product` and `x25519_fe_sqr_times` (#2) sit
  inside X25519's 3.7%, so removing *all* of their prologue traffic is
  ~0.3% of a connection.
- ~160 recoverable instructions repo-wide, against ~6 million cycles per
  connection.

The register-pressure investigation is careful and its static analysis
holds up — `p256_reduce` being 73% of `p256_fe_mul` was found by two
methods here that both agree with each other. What the static ranking
cannot see is that its top targets almost never execute. That is exactly
the outcome prompt 00 exists to establish, and
`prompts/README.md`'s own instruction applies: *"If it is not, say so and
stop — that is a valid outcome."*

Prompt 10 (embedded lookup) is unaffected by any of this: `lookup_embedded`
never appeared in a profile, so it should be judged on correctness, as its
brief already says.

### Summary

| Prompt | Addressable share of a connection | Verdict |
|---|---:|---|
| 04 — P-256, reduction first then comb tables | ~51% | **run first** |
| 08 — response path, retargeted at record/syscall size | ~11% | run second |
| 03 — AES-GCM, retargeted at GHASH | ~3.4% | run third |
| 05 — register overhead experiment | ~1% ceiling, below the floor | **do not run** |
| 06, 07 — register framework and transformations | conditional on 05 | **do not run** |
