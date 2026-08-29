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
| change the width of a wire field | `scripts/width_guard.py` — it will tell you anyway |
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
./tests/test_rng_fail.sh        # fail-closed entropy: each of the three draws, injected
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

`tests/test_rng_fail.sh` (with `tests/rng_fail_checks.py`) is `docs/SECURITY.md`
§14 A4 — the one that makes the CSPRNG fail. `src/crypto/random.S` carries a
`-DSARM_RNG_FAIL_NTH=n` block on the `-DSARM_NO_RODATA` precedent, `make
variant` builds one server per draw, and the script checks first that the
shipped `./sarm` carries none of it. A TLS connection makes exactly three
draws: the first two abort inside `tls_build_server_hello` before a byte is
written, so the assertion is that the client saw *nothing*; the third aborts
inside `tls_certificate_verify_write` with three records already sent, so the
assertion is that exactly three arrived and the fourth — the signature — never
did. `./sarm` itself is the control, and it must complete the same handshake
and carry application data, or the four failing cases prove only that the
client cannot talk to this server. A source sweep also requires every `bl
crypto_random_bytes` in the tree to branch on carry immediately. The
measurement is `rng_fail_checks.py`, which drives the handshake over an
`ssl.MemoryBIO` pair so it can count wire bytes rather than only ask the
library whether it worked. The buffer-level half — nothing signed, nothing
derived from an unfilled scalar, no stale signature left behind — is
`tests/unit/test_rng_fail.c`, the one test binary that links a `-DSARM_RNG_FAIL`
build of `random.S` instead of the tree's own. Write-up:
[docs/SECURITY.md §4.4](SECURITY.md).

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

### Driving a server on another machine

`--target HOST:PORT` skips the build and the server start entirely and points
the load generators at a server already running somewhere else. `--only
h1,h2c,h2tls` picks which protocols run.

```bash
./rps_bench.sh --target 10.0.1.7:8080 --only h2tls --duration 20 --repeat 3
```

This is the flag that makes an honest throughput number possible. On one box
the client and the server share cores, and `h2load` costs roughly **4x** what
sarm costs per request — so a same-box figure is a floor set by the split, not
a ceiling set by sarm. `--server-cpus` is rejected under `--target`: the
server is not this script's to start, so pinning it is the other box's job.

## Renting the hardware: the EC2 scripts

Three orchestrators in `scripts/aws/`, all built on the same two libraries.

| script | what it rents | what it answers |
|---|---|---|
| `quick_test_ec2.sh` | one `c6g.metal` | *where does the time go* — PMU counters, profiles, annotation |
| `rps_two_box_ec2.sh` | a sarm box + a load box 3x its size | *how many requests per second* |
| `run_perf_suite.sh` | nothing — runs on the box | the measurement suite itself |

```bash
./scripts/aws/quick_test_ec2.sh --yes                 # profile on metal
./scripts/aws/rps_two_box_ec2.sh --yes                # pure req/s, two machines
./scripts/aws/rps_two_box_ec2.sh --sweep-only         # drain the deferred lists
```

**Why two boxes for req/s.** Every figure in `perf-results/` before this was
taken over loopback with the load generator on the same machine, so the two
competed for cores and one of them had to lose. `quick_test_ec2.sh` resolves
that by starving sarm on purpose — two cores for the server, sixty for the
client — which is exactly right for a *profile* and is not a throughput number
anybody would quote. `rps_two_box_ec2.sh` puts sarm on a `c7g.4xlarge` (16 vCPU)
and the load on a box three times its size, in one zone, in a cluster placement
group, talking over their private addresses.

**The load box is sized from the server, not fixed.** `--load-type auto` (the
default) picks the smallest type in the server's own family with at least
`--load-ratio` times its cores, so changing `--server-type` cannot silently
erode the margin the measurement depends on. Past the family's largest size the
script says so and lets the measurement decide.

```bash
./scripts/aws/rps_two_box_ec2.sh --server-type c7g.8xlarge   # 32 vCPU server
./scripts/aws/rps_two_box_ec2.sh --load-ratio 6              # more headroom
./scripts/aws/rps_two_box_ec2.sh --load-type c7gn.16xlarge   # pin it
```

**`--load-ratio` defaults to 3, and that number is measured.** The figure
quoted elsewhere in this repo — h2load costing ~4x what sarm costs per request
— is a *loopback* figure, taken where client and server contend for the same
cores and caches. It does not survive the move to two boxes. Driving a
saturated 8-core server
(`perf-results/two-box-20260829-213226`), the client's own busy cores were:

| protocol | server busy | client busy | client:server |
|---|---|---|---|
| HTTP/1.1 | 7.83/8 | 4.49/64 | 0.57x |
| HTTP/2 h2c | 7.81/8 | 9.53/64 | 1.22x |
| HTTP/2 + TLS | 7.28/8 | 10.69/64 | **1.47x** |

So the worst protocol needs ~1.5 client cores per server core, and the original
8:1 default was provisioning five times what the job used. 3:1 keeps a 2x
margin over the worst case and buys a much larger server inside the same
instance family. Every run prints the ratio it actually measured next to the
one it provisioned, so this stays evidence rather than folklore.

**Both sides are measured.** `/proc/stat` is sampled on the server *and* the
load box across each protocol's window. The server's busy cores say whether
sarm saturated; the client's say whether it had room to spare — which is the
only evidence that a number is sarm's ceiling and not the load generator's.
The verdict reports `CLIENT-BOUND` ahead of everything else when the client
peaked above 85%, because a run in that state contains no server measurement
at all. Read that line before any req/s figure.

**One zone, private addresses, checked.** The launch resolves one subnet per
zone and puts both instances in it, and the load is driven at the server's
private VPC address. After launch the script re-reads both instances'
`Placement.AvailabilityZone` and confirms the benchmark address is RFC1918,
terminating both if either is wrong. Cross-zone traffic is billed per gigabyte
in each direction and adds latency that would land in the req/s figure as if
it were the server's — a benchmark that quietly measures the network is worse
than one that stops.

### Shared pieces

Both orchestrators are thin. What they share lives in:

| path | runs on | what it is |
|---|---|---|
| `lib/common.sh` | laptop | `say`/`info`/`warn`/`die`, numeric helpers |
| `lib/pending_sg.sh` | laptop | deferred security-group and placement-group deletion |
| `lib/region.sh` | laptop | region probing: image, instance types, vCPU quota |
| `lib/pricing.sh` | laptop | spot vs on-demand, per zone and per region |
| `lib/ec2.sh` | laptop | key pair, security group, placement group, launch, ssh |
| `lib/upload.sh` | laptop | the working-tree tarball and its provenance stamp |
| `setup/packages.sh` | instance | role-based toolchain (`server`, `load`, `metal`) |
| `setup/tuning.sh` | instance | sysctl and ulimits |
| `setup/loadgen.sh` | instance | wrk (built when unpackaged), h2load |
| `setup/build_sarm.sh` | instance | sources, certs, `make production`, smoke test |
| `setup/profiling.sh` | instance | perf, FlameGraph, PMU verification |

The region and pricing libraries work on a *list* of instance types, because
the two-box run needs both of them in one zone: the zone list is the
intersection of what each type is offered in, the vCPU quota check is against
their sum, and a price is the pair's hourly rate rather than either half's.
`quick_test_ec2.sh` passes a one-element list and behaves exactly as before.

**Key pairs are per region.** An AWS key pair created in Melbourne does not
exist in Sydney, so a single hard-coded default silently degrades to a minted
ephemeral pair everywhere else — the box then works, but is unreachable from
any other terminal, which matters under `--keep`. `region_key_name()` in
`lib/ec2.sh` maps region to key (`ap-southeast-4=DaleMelbourne`,
`ap-southeast-2=DaleSydney`), pairing each with `~/.ssh/<name>.pem`. Override
with `SARM_EC2_KEYS="ap-southeast-2=DaleSydney us-west-2=DaleOregon"`;
`--key-name`/`--key-file` still win over the table.

**Starting a server over ssh: redirect the group, not the command.** ssh does
not return until nothing on the far side holds the channel's stdout/stderr.
`setsid ./sarm ... > log 2>&1 &` binds the redirections to the *inner*
command, leaving the background subshell still pointing at the ssh pipes — the
ssh then hangs forever while the server is up and serving. The redirections
belong on the `{ ...; }` group that `&` backgrounds, with `exec` so no shell
is parked behind sarm. Every sarm launch site in this repo also closes fds 3
and 4.

The instance-side split is what keeps a two-box run cheap: the load box
installs no compiler and builds no sarm, the server box installs no profiler
and no load generator, and the two provision in parallel.

`setup_ec2_metal.sh` is therefore no longer a single file you can `curl` on its
own — it needs the repo next to it. `quick_test_ec2.sh` uploads the tree for
you, which is the usual path.

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
- **`width_guard.py`** — guards the premises of `docs/SECURITY.md` §3.5's
  **width** verdicts: that no multi-octet wire field is composed in a 64-bit
  register anywhere in the 99 wire-parsing files, and that six named files
  still assemble the fields, at the widths, the verdicts were written against.
  It proves no arithmetic safe — it makes changing a field's width fail a check
  instead of silently invalidating a paragraph. `--report` prints what it sees.
  Run by `tests/test_width_guard.sh` in `make test`, with two controls that
  damage a scratch copy of the tree and require the guard to notice.
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
