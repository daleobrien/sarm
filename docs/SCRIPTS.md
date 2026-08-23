# Tooling guide

Everything in `scripts/`, `tests/` and the two shell scripts at the repo root.
Nothing here ships in the binary.

Rule of thumb for which to reach for:

| I want to… | Use |
|---|---|
| know if I broke something | `make test` |
| know where the time goes in a connection | `scripts/profile_workload.py` |
| know which function is hot | `scripts/profile_samples.py` |
| know how often a function runs | `scripts/count_calls.py` |
| know if one function got faster | `scripts/benchmarks/` |
| know if a register/ABI change is legal | `scripts/abi.py`, `scripts/regpressure.py` |
| change P-256 or GHASH arithmetic | the matching `scripts/*_derivation.py` — **first** |
| let a machine try optimisations | `scripts/arm-optimize.py` |

---

## Build scripts (these do ship their output)

| Script | Does |
|---|---|
| `embed_www.sh` | Walks `www/`, gzips text-like assets when smaller, computes SHA-256 ETags, emits `src/embedded.S`. Run by `make assets`. |
| `certs/embed_cert.sh` | Emits `src/tls/cert_data.S` from `cert.der` + the raw private scalar in `key.pem`. |
| `certs/generate.sh` | Makes a fresh self-signed ECDSA P-256 test certificate. |
| `build_err_pages.sh` | Generates `www/err/<code>.html` from `err/template.html` (`{{CODE}}`, `{{TITLE}}`, `{{MSG}}`). |

## Tests

```bash
make test                       # everything: unit + files + security + protocols
make -C tests/unit              # unit suite alone (~4,300 assertions)
./tests/test_files.sh           # asset integrity, ranges, MIME, ETag, gzip
./tests/test_security.sh        # traversal, encoding, oversize, malformed input
./tests/test_protocols.sh       # HTTP/1.1, h2c, HTTP/2-over-TLS end to end
./tests/test_keepalive.sh       # pipelining, fragmentation, keep-alive budget
./tests/test_h2_flow.sh         # HTTP/2 flow-control wait path, over h2c
./tests/test_workers.sh         # --workers parsing, accept spread, shutdown
./tests/test_leak.sh            # secret-leak probe: hostile traffic, scanned responses
./tests/test_syscalls.sh        # syscall allowlist + traced filesystem non-access
./tests/test_limits.sh          # resource limits: connections, deadline, buffers, CPU
./tests/test_multicore.sh       # concurrent multi-protocol load across workers
./tests/h2_browser_sim.py all   # frame-level browser simulator, not in `make test`
```

`tests/unit/` is C drivers linked directly against the real `.S` files — one
test directory per assembly module. Many of the crypto test files are
*generated* by the derivation scripts below and should be regenerated, not
hand-edited.

`tests/test_h2_flow.sh` (with `tests/h2_flow_checks.py`) drives raw h2c frames
at the one place in the server where a request's I/O runs inside another's:
`h2_write_body`'s flow-control wait loop, which reads and dispatches client
frames — and serves requests that complete — while a response waits for
window credit. Cleartext on purpose; over TLS the connection loop's unparsed
bytes live in the TLS stage buffer, which is what kept the buffer-sharing bug
it regresses latent there. It needs an embedded asset larger than the
65535-byte default window and says so rather than passing vacuously if there
isn't one.

`tests/test_leak.sh` (with `tests/leak_checks.py` and
`tests/hostile_workload.py`) is `docs/SECURITY.md` Step 10: it fires
deterministic malformed traffic over HTTP/1, h2c, junk TLS, a real TLS 1.3
connection and byte-at-a-time fragments, captures every byte the server sends
back, and searches it for the embedded private scalar, any 12-byte run of it,
certificate-adjacent memory, file content, and the per-connection request
markers — the last of which catches one connection seeing another's buffers.
It runs the whole workload twice, once in the production fork mode and once in
`no_fork`, and also asserts the server writes nothing to stdout or stderr,
leaves no core dump, and never dies on a signal. `--cases N` (or
`SARM_LEAK_CASES`) scales the run; the scanner tests itself first with
`leak_checks.py --self-test`.

`tests/test_syscalls.sh` (with `scripts/syscall_audit.py`,
`tests/syscall_allowlist.txt` and `tests/trace_check.py`) is Step 11. The
static half resolves every `svc` site in the built binary — every syscall
number in this tree is a compile-time immediate, so the complete set the binary
*can* make is decidable — and checks it against the allowlist; the dynamic half
traces the hostile workload under `strace` (Linux) or `dtruss` (macOS, root)
and checks what actually happened, skipping rather than passing where no tracer
exists. It also serves the workload from an empty read-only directory and
checks nothing appeared on disk. `scripts/syscall_audit.py` is usable alone,
with `--json` or `--skip-binary`. Write-up:
[docs/SECURITY.md §6](SECURITY.md).

`tests/test_limits.sh` (with `tests/limit_checks.py`) is Step 12 — the one
that asks what hostile input *costs* rather than what it does. Four campaigns
against four differently-shaped servers: `connections` (48 clients that connect
and go quiet — one forked child each, all reclaimed, and the server still
serving while they are held), `deadline` (a byte dripped just often enough to
restart `RECV_TIMEOUT`, in all three protocol shapes including the
`change_cipher_spec` flood RFC 8446 requires the server to tolerate),
`buffers` (peak resident size under oversized headers, paths, records, frames,
streams and HPACK tables, compared with peak resident size under plain traffic
over all three protocols) and `cpu` (per-connection CPU in `no_fork` mode,
which is how "rejected before expensive crypto" becomes a measurement — a
truncated key_share is ~18x cheaper than a completed handshake). Every campaign
also asserts its own non-vacuity, and `limit_checks.py --self-test` checks the
instruments before any of them run. The timeout campaigns run against a
short-deadline binary built by `make variant`; the shipped constants are
asserted separately out of `src/config.S`. Knobs: `--connections`,
`--cpu-cases`, `--deadline`, `--recv-timeout`. Write-up:
[docs/SECURITY.md §8](SECURITY.md).

`tests/test_hardening.sh` (with `tests/hardening_checks.py`) is Step 13 — the
one that inspects the *binary* rather than the behaviour. It checks that the
linked image is a PIE with no writable-and-executable segment, that 11 named
constants (the certificate, the private scalar, the crypto tables, the HPACK
static table, the frame dispatch table) sit in a read-only section while 4
named mutable globals do not, and that the loader is asked to apply no
relocations at all; on ELF it also checks `PT_GNU_STACK` and that `.rodata`
gets its own `r--` LOAD segment. Then the same claims about a running server —
`vmmap` or `/proc/pid/maps` — and the core-dump limit, both statically (the
binary really does call `setrlimit`/`prlimit64`) and dynamically (a `SIGSEGV`'d
connection child leaves no core, gated on a control that proves the machine
dumps cores at all). Two deliberately unhardened control builds show the checks
can fail: `-DSARM_NO_RODATA` puts every constant back in writable `.data`, and
on Linux an empty `LDFLAGS` gives a fixed-address image with an executable
stack. `--docker` additionally inspects the binary inside the container image;
the ELF side is parsed in Python, so that works from macOS. Write-up:
[docs/SECURITY.md §13](SECURITY.md).

`tests/test_workers.sh` (with `tests/worker_checks.py`) covers the pre-forked
accept workers — properties of *processes* rather than of functions, so they
cannot live in `tests/unit/`: which `--workers` arguments are accepted and
where the `MAX_WORKERS` clamp lands, that every worker really does take
connections off the shared listening socket, and that `SIGTERM`/`SIGINT`
leaves no worker behind, frees the port immediately, and lets in-flight
connections finish.

`tests/test_multicore.sh` (with `tests/multicore_checks.py`) is the Phase 4
stress harness: concurrent clients over HTTP/1 (single, keep-alive, pipelined,
split-write), h2c and h2+TLS with every body checked byte for byte, then a
randomised mixed workload with slow clients and long-lived HTTP/2 connections
while a probe times fresh connections. `--iterations` and `--stress-seconds`
turn it into a soak; `--workers` picks the server's worker count. It found the
`SA_NOCLDWAIT` zombie bug described in `docs/MULTICORE-BASELINE.md`.

`scripts/fuzz_soak.py` and `scripts/fuzz_minimize.py` are Step 14 — the two
halves of continuous fuzzing. The soak runner (`make fuzz-soak`, or
`SOAK_ARGS='--minutes 60 --minimize' make fuzz-soak`) runs the five seeded fuzz
suites on random seeds, one fresh process per suite per round, logging every
seed to `tests/security/findings/soak.log`; `make test` keeps its fixed seed,
so the soak widens the input space without making the committed suite
irreproducible. A campaign that crashes, hangs or breaks an invariant has
already written the failing case's bytes into `tests/security/findings/` —
the harness does that itself, because a seed-based reproducer stops meaning
anything the moment its generator changes. `fuzz_minimize.py` then shrinks such
a file by delta debugging, using the harness's replay mode (`SARM_FUZZ_TARGET`
+ `SARM_FUZZ_REPLAY`, exit code as the oracle) — it took a real 238-byte
preserved crash down to the five bytes of `docs/SECURITY.md` §11 in 49
replays — and `--keep <name>` installs the result under
`tests/security/corpus/`, where every later run of that suite replays it as a
regression test. Write-up:
[docs/SECURITY.md §12](SECURITY.md).

`tests/h2_browser_sim.py` is a dependency-free HTTP/2 client (stdlib `ssl`/`socket`
plus its own frame writer and encode-side HPACK) that mimics real browser frame
patterns — which is how three flow-control bugs `curl` and `nghttp` both hid were
found. Scenarios: `page-load`, `burst`, `no-credit`, `reload`, `late-wu`,
`settings-resize`, `all`. Useful knobs: `--paths`, `--no-indexing`, `--reloads`,
`--streams`, `--conn-window`, `-v`. It exits non-zero on any incomplete stream.

## Profiling

```bash
python3 scripts/profile_workload.py pageload handshake transfer request
python3 scripts/profile_samples.py handshake --top 30
python3 scripts/count_calls.py --workload pageload
```

- **`profile_workload.py`** — the authority on *where a connection's cost is*.
  Runs sarm as a child, drives it with `h2_browser_sim.py`'s `Connection`, and
  reads server CPU from `getrusage(RUSAGE_CHILDREN)`. Runs each scenario at three
  workload sizes and least-squares-fits marginal vs fixed cost — reading marginal
  cost off a single size folds the handshake in and misstates it by 30–60%.
  **Wall clock is not the measurement**: the Python client's own TLS decryption
  costs several times what sarm's encryption does.
- **`profile_samples.py`** — periodic PC sampler via `/usr/bin/sample`
  (`xctrace` needs a full Xcode install; this machine has CLT only), attributed to
  functions. sarm has no frame-pointer chain, so this is self-time only.
- **`count_calls.py`** — call frequency per connection/request, via `lldb` with
  auto-continuing breakpoints. Frequency, not size, is what makes a function hot,
  and the shipped binary deliberately logs nothing.

## Benchmarks

```bash
cd scripts/benchmarks
make bench_p256_fe_mul && ./_bench_bin/bench_p256_fe_mul     # prints JSON
python3 measure_noise_floor.py bench_p256_fe_mul             # writes .noise.json
./rps_bench.sh --no-build --duration 15                      # req/s, all three protocols
```

Each `bench_<fn>.c` links the function's own `.S` file — so a candidate installed
by the optimiser is picked up automatically — and prints
`{"function": …, "runtime_ns": …, "sizes": {…}}`. The paired `.noise.json` records
the round-to-round noise floor a candidate must beat; `arm-optimize.py` reads it.

`rps_bench.sh` builds `make production`, starts sarm on a scratch port, and runs
`wrk` (HTTP/1.1), `h2load --no-tls-proto=h2c` (h2c) and `h2load` over TLS against
that one instance. Use duration mode (`-D`, the default here) not `-n`:
fixed-request-count mode undercounts when more clients are configured than
requests needed.

Two caveats that used to sit here are gone as of Phase 1. sarm now speaks
HTTP/1 keep-alive, so `wrk` no longer reports socket read errors for closes it
did not expect, and the order-of-magnitude HTTP/1-to-h2c gap has closed — both
were consequences of forking per *request*, not of the HTTP/1 path being
slower per request. h2c still leads HTTP/1.1, but by roughly 3x rather than
10x — see `docs/MULTICORE-BASELINE.md` for figures at a stated concurrency.

Two caveats that remain, and matter more:

- **`--connections` above the machine's logical CPU count measures
  scheduling, not the server.** One process per connection means `-c50` on 12
  cores is 50 runnable processes; h2c falls from 282k req/s at `-c4` to 93k at
  `-c50` with no code change at all, and past the core count the metric is
  bimodal (6 P-cores + 6 E-cores), so a single run lands in one of two modes
  regardless of build. The script warns when you cross that line.
- **A single run is not a measurement.** Use `--repeat N` (median plus
  spread), interleave the builds you are comparing rather than running all of
  A then all of B, and keep an unchanged protocol in the table as a control.
  `--workers N` sets the server's worker count.

## Static analysis

```bash
python3 scripts/regpressure.py                                    # ranked report
python3 scripts/regpressure.py --callers .Lgcm_ghash_run
python3 scripts/abi.py --source src/crypto/p256/sqr_mul.S --function p256_reduce --flags
python3 scripts/validate_clobbers.py --verdict OVERSTATES
python3 scripts/syscall_audit.py                                  # svc sites vs the allowlist
```

- **`syscall_audit.py`** — the syscall allowlist checker (`docs/SECURITY.md`
  Step 11). Resolves every `svc` in the built binary to a syscall number and
  every `SCWINUM` in `src/` to a name, and checks both against
  `tests/syscall_allowlist.txt`. Its own parser, not `asmparse.py`: it reads
  the *disassembled binary*, which is where the claim has to hold —
  `--skip-binary` falls back to the source check alone, `--json` for a report.
  Run by `tests/test_syscalls.sh`.
- **`asmparse.py`** — the single AArch64 parser everything else uses: labels
  (including `.L`), macro expansion (`ldr_l`, `SCWISVC`, `gcm_rbit`, the carry51
  family), regions, call graph, platform-aware (`--linux`). It exists because
  there used to be two parsers and their divergence hid a soundness bug for a
  long time. Do not add a third.
- **`abi.py`** — the pre-compile gate: callee-saved GPRs/SIMD not restored on
  some path, `bl` without saving `x30`, SP not restored or misaligned, and
  **NZCV** — dozens of functions return status in the carry flag, so the flags are
  a live-out ABI value. The NZCV check is differential against the function being
  replaced, since only that comparison shows which flag write was intended.
- **`regpressure.py`** — read-only. Reports pressure, callee-saved traffic and
  register moves. Note the metric that matters is *not* register count: nothing in
  this repo spills. It's fixed prologue/epilogue traffic that isn't earned.
- **`validate_clobbers.py`** — checks the analyzer against the 200+ hand-written
  `// Clobbered Registers:` headers. Where they disagree, exactly one is wrong.
  This is the cheapest strong oracle in the repo; it has found real bugs in both
  directions.

## Crypto derivation scripts — read this before touching `src/crypto/`

These are not documentation of the assembly. They are its **generator and proof
harness**. Each models the exact word-and-carry sequence the assembly executes —
not the mathematical identity — so a carry bug is one the Python can also have,
and therefore one that testing can catch. Several also emit the unit tests and,
in two cases, the assembly data tables themselves.

```bash
python3 scripts/p256_reduce_derivation.py derive          # re-derive the Solinas fold table
python3 scripts/p256_reduce_derivation.py bound           # exact carry bounds (vertex search)
python3 scripts/p256_reduce_derivation.py check 200000
python3 scripts/p256_reduce_derivation.py gen-test        > tests/unit/test_p256/reduce.c

python3 scripts/p256_fe_mul_derivation.py prove           # the row bound + umulh headroom
python3 scripts/p256_fe_mul_derivation.py check 20000
python3 scripts/p256_fe_mul_derivation.py interop 40      # vs OpenSSL
python3 scripts/p256_fe_mul_derivation.py gen-test        > tests/unit/test_p256/mul_carry.c

python3 scripts/p256_comb_derivation.py prove             # the two safety proofs for add_affine
python3 scripts/p256_comb_derivation.py check 2000
python3 scripts/p256_comb_derivation.py interop 500
python3 scripts/p256_comb_derivation.py gen-table         > src/crypto/p256_point/comb_table.S
python3 scripts/p256_comb_derivation.py gen-test-madd     > tests/unit/test_p256_point/add_affine.c
python3 scripts/p256_comb_derivation.py gen-test-mulb     > tests/unit/test_p256_point/mul_base.c

python3 scripts/p256_scalar_inv_derivation.py prove       # addition chain + Montgomery bounds
python3 scripts/p256_scalar_inv_derivation.py check
python3 scripts/p256_scalar_inv_derivation.py interop
python3 scripts/p256_scalar_inv_derivation.py gen-chain     > src/crypto/p256_scalar/inv_chain.S
python3 scripts/p256_scalar_inv_derivation.py gen-test-mont > tests/unit/test_p256_scalar/mont_mul.c
python3 scripts/p256_scalar_inv_derivation.py gen-test-inv  > tests/unit/test_p256_scalar/inv.c
```

`p256_fe_mul_derivation.py` imports `p256_reduce_derivation.py`'s reference rather
than restating it, so the two cannot drift apart. The workflow — prototype in
Python, prove the bounds, cross-check against an independent library, *then*
port — is written up as the `verified-asm-crypto` skill and is not optional:
hand-deriving a change to these files and reasoning about it abstractly is how
this codebase gets a silent carry bug.

## The optimisation harness

```bash
python3 scripts/arm-optimize.py --list-functions --source src/util/memcpy.S
python3 scripts/arm-optimize.py --function memcpy --mutate-only
python3 scripts/arm-optimize.py --function memcpy --llm ollama --llm-model qwen2.5-coder:7b
python3 scripts/arm-optimize.py --function p256_reduce --strategy crypto --apply
```

`arm-optimize.py` is the CLI; the pipeline is
**propose → ABI check → build → tests → differential → benchmark → keep/reject**,
with every candidate and its evidence archived under `.arm-optimize/`. See
[OPTIMISATION.MD](OPTIMISATION.MD) for the design and the module breakdown.

The important flag is `--strategy`. It decides *what a candidate is judged
against* — a GHASH candidate is judged by AES-GCM throughput, not its own
microbenchmark. Every non-`speed` strategy **fails closed at construction**
unless its target is a measured line item in the profile table in
[HISTORY.md](HISTORY.md). That is the "never justify a target by register or
instruction count alone" rule, enforced structurally rather than by discipline.

Supporting modules: `strategy.py` (accept/score rules), `optimizer.py` (the
loop), `common.py`, `compiler.py` (build/test), `benchmark.py` (the authority on
whether a candidate is faster), `differential.py` (reference vs candidate over
random inputs), `disassembler.py` (`.asm`/`.dis`/`diff.asm` artifacts),
`mca.py` (llvm-mca, absent on this toolchain), `perf.py` (Linux only — no PMU
access on macOS), `llm.py` (Ollama HTTP or any subprocess command),
`mutations/` (rule-based `neon`/`scheduling`/`unroll` transforms),
`prompts/*.txt` (the analyst / optimizer / judge prompts).
