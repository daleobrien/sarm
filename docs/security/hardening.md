# sarm — production hardening

Step 13 of the programme in [docs/SECURITY.md](../SECURITY.md), whose text is
two lines:

> **Enable supported binary and OS protections.**
> **Test:** inspect the final binary and verify the expected protections are
> present.

§13 of the same document lists what to look for: ASLR/PIE, non-executable
writable memory, stack canaries, RELRO, branch protection, pointer
authentication, and read-only static tables. It also says what the whole list
is worth:

> These are defence-in-depth measures. They do **not** replace fixing the
> overflow.

That is the right frame for this step. Nothing here fixes a bug — Steps 2–9
did that, and found real ones. What this step changes is what a bug would be
*worth*. Before it, every byte the server owns was writable, the Linux image
loaded at a fixed address with an executable stack, and a crash could write the
private key to disk. After it, three quarters of the server's static data is
read-only, both images are position-independent, neither can be loaded with an
executable stack, and no process in the tree can dump core.

Delivered: the `rodata` macro in `src/defs.S` and the section split across 35
files, four tables converted from pointers to offsets, the link flags in the
`Makefile`, `RLIMIT_CORE` in `src/sarm/main.S`, one new allowlist entry, and
[`tests/test_hardening.sh`](../../tests/test_hardening.sh) +
[`tests/hardening_checks.py`](../../tests/hardening_checks.py) — 10 checks on
macOS and 16 on Linux, run by `make test`.

This closes observations 1 (partly) and 2 of
[threat-model.md](threat-model.md) §9.

---

## 1. What was unprotected

Three things, all of them recorded before this step rather than discovered by
it.

**Everything was writable.** threat-model observation 2, in full: the embedded
assets, the certificate, the private scalar, the Huffman and status tables and
every response string were emitted into `.data`. `src/defs.S` had no read-only
section macro, and no file in `src/` used one. On macOS that was a single
336 KB `__DATA` segment, `rw-`, holding the key next to the request buffers.

**The Linux image had no ASLR and, worse, an executable stack.** The Linux link
was a bare `ld` with no flags at all, which produces `ET_EXEC` at a fixed
`0x400000` and — because nothing emitted a `PT_GNU_STACK` header — a binary
that aarch64 Linux loads with `READ_IMPLIES_EXEC` set. That last part is the
one worth stopping on. On arm64, a *missing* `PT_GNU_STACK` does not mean
"default"; `elf_read_implies_exec()` turns it into a personality flag that
makes every readable mapping in the process executable, stack and data
included. The file could pass any W^X check you like and the process would
still be entirely executable.

**Nothing in the server stopped a core dump.** Step 10's harness set
`ulimit -c 0` before launching the server and then checked that no core
appeared — which tests the harness, not the server. A core of this process is a
complete memory disclosure: the private scalar, the handshake secrets and every
traffic key are in it, by construction (threat-model §4). `SECURITY.md` §10
asks production to disable core dumps; nothing in the binary did.

---

## 2. The read-only split

`src/defs.S` gains one macro:

```asm
#ifdef SARM_NO_RODATA
.macro rodata
    .data
.endm
#elif defined(__linux__)
.macro rodata
    .section .rodata,"a",%progbits
.endm
#else
.macro rodata
    .section __DATA_CONST,__const
.endm
#endif
```

Thirty-five files changed `.data` to `rodata` (`src/embedded.S` and
`src/tls/cert_data.S` among them, via their generators); the two generators
(`embed_www.sh`, `certs/embed_cert.sh`) now emit it too. `.data` still means
what it always did, and the files that still use it are the ones that really do
hold mutable state:

| Still `.data` / `.bss` | Why |
|---|---|
| `src/data.S` | `file_des`, `connection_mode`, `worker_count`, and the request buffers |
| `src/tls/data.S` | `tls_state` — every key in the schedule, written per connection |
| `src/transport/data.S` | the staging and record buffers |
| `src/crypto/data.S` | the streaming SHA-256 context |
| `src/h2/data.S`, `src/hpack/**` | connection, stream, field and dynamic-table state |
| `src/parse/data.S`, `src/http1/data.S` | filename, query, authority, header buffers |
| `src/sarm/main.S` — `addr` only | the port from `argv` is written into it |
| `h2_range_buf`, `h2_cr_buf` | per-request scratch inside two otherwise-constant files |

Everything else moved: the certificate and the private scalar, the six embedded
assets with their paths, MIME types and ETags, the SHA-256 constants, the P-256
field and scalar constants and the 4 KB comb table, the HPACK static table and
Huffman code, the MIME table, the status-line table, the frame dispatch table,
every protocol string and every label the key schedule derives from.

**On Mach-O the section is `__DATA_CONST,__const`, not `__TEXT,__const`.**
`__TEXT` is `r-x`: putting data there would make it read-only by making it
*executable*, which trades one weakness for a better one. `__DATA_CONST` is a
segment dyld drops to `r--` after applying fixups (it carries `SG_READ_ONLY`),
so the result is read-only and non-executable both. Measured on the running
server with `vmmap`, which is what the harness checks:

```
__TEXT        104174000-104180000   r-x/r-x   sarm
__DATA_CONST  104180000-1041a8000   r--/rw-   sarm     ← 160 KB, read-only
```

Before and after, on the same machine:

| | before | after |
|---|---|---|
| macOS `__TEXT` (r-x) | 48 KB | 48 KB |
| macOS `__DATA_CONST` (r--) | — | 160 KB |
| macOS `__DATA` (rw-) | 336 KB | 176 KB |
| Linux `.rodata` | — | 154 KB |
| Linux `.data` | 252 KB | 100 KB |

---

## 3. Why the tables hold offsets instead of pointers

An address stored in static data is not a constant. It is a relocation: a note
asking whoever loads the image to write the real address in, once the base is
known. That has two consequences here, and the second is the interesting one.

The first is ordinary: a relocation means the loader *writes* to the page it
patches, so a section full of pointers cannot be mapped read-only from the
start. dyld handles this by writing `__DATA_CONST` and then protecting it; ELF
handles it with `RELRO` and a dynamic linker.

The second is that **the Linux build has no dynamic linker at all**. It is
`ld` over a set of freestanding objects — no libc, no interpreter, nothing that
runs before `_start`. A `-pie` link of pointer-bearing tables produces an
`ET_DYN` image with 177 `R_AARCH64_RELATIVE` relocations and nobody to apply
them: every one of those pointers would be read at runtime as an offset from
zero. Position independence and absolute addresses in static data are, for this
binary, mutually exclusive.

So the four tables that held pointers now hold differences, which the *linker*
resolves at link time and no loader ever touches:

| Table | Entries | Read by |
|---|---|---|
| `h2_frame_handlers` | 10 handler addresses | `h2_dispatch_frame` — one `add` before the `br` |
| `h2_hpack_static_table` | 61 × 2 name/value pointers | `h2_hpack_static_lookup` — two `add`s |
| `status_table` | 21 status-line pointers | `find_http_code` — one `add` |
| `embedded_files` | 6 × 4 path/content/type/etag pointers | `lookup_embedded` — one `add` per column |

Each is an offset from the table's own symbol, so the reader adds the table
base back. The cost is one `add` per pointer read, on lookups that happen once
per frame or once per request; `lookup_embedded` re-derives the base inside its
scan loop rather than holding it in a register, because `streqn` is free to
clobber the caller's scratch (this is not hypothetical — it is the one bug this
conversion introduced, and three of the eight file-integrity tests caught it
immediately).

The payoff is the same on both platforms and stronger than the ASLR it was for:

```
Linux:  177 dynamic relocations  →  0      ET_EXEC @ 0x400000  →  ET_DYN, randomised
macOS:  177 chained fixups       →  0
```

**The binary asks the loader to relocate nothing.** That is a checkable
property (`fixups` in the harness), and it means the read-only regions are
read-only from the first instruction rather than write-then-protect.

Two observed load bases from consecutive runs of the same Linux binary, which
is the whole point of the exercise:

```
ffffbe6b0000-ffffbe6b1000 r--p  /tmp/b/sarm
ffff98580000-ffff98581000 r--p  /tmp/b/sarm
```

---

## 4. The link flags

```make
Darwin: -e _main -arch arm64 -l System -syslibroot ... -pie
Linux:  -pie --no-dynamic-linker -z noexecstack -z separate-code
```

- `-pie` — the image can be placed anywhere. On arm64 macOS this is
  unconditional (ld64 ignores `-no_pie` on this architecture, which is also why
  the harness cannot build a non-PIE control there and says so instead of
  pretending); it is stated anyway so that a build that somehow was not PIE
  would be a visible change rather than a silent one.
- `--no-dynamic-linker` — no `PT_INTERP`. Nothing is asked to run before
  `_start`, which is only sound because §3 removed every relocation.
- `-z noexecstack` — emits `PT_GNU_STACK RW`, which is what stops
  `READ_IMPLIES_EXEC` (§1). This is the single most valuable flag in the list
  for this binary.
- `-z separate-code` — gives `.rodata` its own `r--` LOAD segment instead of
  sharing the `r-x` one with `.text`, so constants are not mapped executable.

The resulting Linux segment table, and the same thing seen from `/proc`:

```
LOAD  0x000000 R    (ELF headers)
LOAD  0x010000 R E  .text
LOAD  0x020000 R    .rodata
LOAD  0x04ff10 RW   .data .bss
GNU_STACK       RW
```

---

## 5. No core dumps, from inside the process

`main.S` sets `RLIMIT_CORE` to zero at startup, before the listening socket
exists:

```asm
    adr_l x9, no_core_rlimit
#ifdef __linux__
    SCWINUM SYS_prlimit64      // pid 0, RLIMIT_CORE, &new, NULL
#else
    SCWINUM SYS_setrlimit      // RLIMIT_CORE, &rlimit
#endif
```

Three decisions in that block:

**Before the socket, so it covers everything.** rlimits are inherited across
`fork()`, so one call covers every accept worker and every connection child for
the life of the server. It is also before anything a client can influence.

**Fatal on failure.** Lowering a soft limit is always permitted; a failure here
means the kernel interface is not what this code thinks it is, not that a
request went wrong, and it happens at startup where refusing to serve costs
nothing. This is the opposite of the `setitimer` decision in Step 12 — that one
deliberately serves the connection without its ceiling rather than dropping it
— and the difference is that a failed deadline costs one connection's
boundedness, while a failed core limit costs the private key on the first
crash.

**Two syscalls for one thing.** arm64 Linux has no `setrlimit`; the generic
syscall table carries `prlimit64(pid, resource, new, old)` and pid 0 means
self. `struct rlimit` is two 64-bit fields on both platforms, so
`no_core_rlimit` lays out identically either way — the same trick `rcv_timeout`
and `conn_deadline` use.

Step 11's audit caught the new syscall before this step's own test ran, exactly
as it did for `setitimer` in Step 12: both the `SCWINUM` site in `src/` and the
`svc` in the linked binary. `setrlimit` and `prlimit64` are now on
[`tests/syscall_allowlist.txt`](../../tests/syscall_allowlist.txt) and in
threat-model §6.

---

## 6. Evaluated and not adopted

The rest of `SECURITY.md` §13's list, with the reason in each case. A "no" here
is a decision, not an omission — which is the point of writing them down.

**Branch target identification (BTI).** Enforced only when the ELF carries the
`GNU_PROPERTY_AARCH64_FEATURE_1_BTI` note *and* every indirect branch target
carries a landing pad. This tree has ~200 hand-written routines reached by
`blr` and one `br` through a dispatch table; marking the binary without a
landing pad at every one of them turns a missed function into a `SIGILL` on
whatever path first reaches it — which, for a path the test suite does not
cover, means in production. Doing it properly means a `bti c` at every global
entry point, enforced by `scripts/abi.py` the way the callee-saved rules
already are, so that a new function cannot be added without one. That is a
worthwhile change and it is a change to the assembly conventions of the whole
tree, not a link flag. Not attempted here. macOS gets nothing from it either
way: BTI is enforced on arm64e, and this is arm64.

**Pointer authentication (PAC).** Same shape of argument, worse ratio.
`paciasp`/`autiasp` in every prologue and epilogue changes the stack discipline
that `scripts/abi.py` and every "Stack Usage" header in the tree describe, and
buys protection against return-address overwrites in a server that has no
attacker-writable return addresses on record — `SECURITY.md` §12
(stack-corruption testing) is the place that question belongs.

**Stack canaries.** A C compiler feature, and there is no C in the server. The
only C in the repository is test code.

**RELRO.** Protects the GOT and PLT of a dynamically linked binary. This one
has neither: no dynamic symbols, no PLT, and after §3 no relocations to
protect. The property RELRO exists to provide — "the loader's writable
scratch is read-only by the time untrusted input arrives" — is here by
construction.

**`mprotect`-ing `.data` after startup.** Tempting, and wrong: `.data` holds
`tls_state` and every buffer. There is no point in the lifetime after which it
stops being written. The useful subset of this idea is exactly what §2 did
statically.

**macOS hardened runtime / notarisation.** Deployment-signing concerns for a
distributed application bundle, not properties of a server binary; the shipped
artifact is the Linux container.

---

## 7. The private key (threat-model observation 1)

The scalar is embedded in the binary, in `src/tls/cert_data.S`, generated from
`certs/key.pem` — which is in the repository. Today that is a self-signed
`localhost` development key, so nothing is exposed, but the pattern has to be
settled before a real certificate meets it. `SECURITY.md` §9 lists four
options; here is what each would cost this server:

| Option | What it would take here | Note |
|---|---|---|
| A — hardware-backed key | A signing interface the TLS code calls instead of `p256_ecdsa_sign`, plus a syscall to reach the device | The strongest, and the largest change: it breaks the "no filesystem, no dependencies" property the syscall allowlist rests on |
| B — generate at deployment | `certs/generate.sh` + `embed_cert.sh` run in the deployment pipeline, not in the repository; the binary that ships is built with the key it will use | Fits this build exactly — the certificate is already a build input, and the build already runs `embed_cert.sh` |
| C — ephemeral / per-installation | As B, plus accepting that the certificate changes when the image is rebuilt | Fine for internal or ACME-fronted deployments; not for a pinned certificate |
| D — embedded encrypted key | A passphrase has to reach the process, which means an environment variable or a read — both of which the server deliberately cannot do | Rejected: it moves the secret rather than removing it, and costs the containment property |

Step 13 changes one thing about this and states the rest. The change: the key
is no longer in writable memory, so a write primitive can no longer replace the
key in place (a substitution attack against a server whose certificate is
pinned), and the harness checks specifically that `tls_priv_key` is inside the
read-only region. What is unchanged: an *arbitrary read* primitive still
reaches it, exactly as it reaches any in-process key, and that is what Step 10's
leak probe covers empirically.

Which of A–D applies is a deployment decision, not a build one, and this
document is not the place it gets made. Recorded here so that the next person
to point a real certificate at this server finds the analysis rather than
redoing it. Observation 1 is therefore **partly closed**: the memory question
is answered, the deployment question is documented and still open.

---

## 8. The test

[`tests/test_hardening.sh`](../../tests/test_hardening.sh), with the inspection
in [`tests/hardening_checks.py`](../../tests/hardening_checks.py). Step 13 asks
for the *binary* to be inspected, so nothing in it reads the Makefile or trusts
a flag.

**binary** — PIE; no segment writable-and-executable at current *or* maximum
protection; 11 named constants inside the read-only region, private scalar
included; 4 named mutable globals outside it; zero load-time fixups. On ELF
also `PT_GNU_STACK` and `.rodata`'s own `r--` segment. The Mach-O side shells
out to `otool`/`nm`/`dyld_info`; the ELF side parses the file directly, so a
macOS host can inspect the Linux binary the container ships without a
cross-binutils.

**process** — the same claims about a running server rather than a file:
`__DATA_CONST` mapped `r--` (`vmmap`) or the read-only segment mapped `r--p`
(`/proc/pid/maps`), no `rwx` mapping, a non-executable stack mapping, and on
Linux a core-dump limit of zero read out of `/proc/pid/limits`. A file can be
marked however it likes; what matters is what the kernel did with it.

**cores** — the static half holds anywhere: the built binary really does
contain a `setrlimit`/`prlimit64` call, read out of `scripts/syscall_audit.py
--json`. The dynamic half opens a connection, `SIGSEGV`s the forked child and
checks that no core appeared — gated on a control program that crashes under
`ulimit -c unlimited` and *does* dump, so that on a machine where nothing ever
dumps (macOS, where `/cores` is root-owned) the check is reported as skipped
rather than passed.

**controls** — two deliberately unhardened builds, because a check that has
only ever been seen to pass is not evidence:

| Control | Built with | Must fail |
|---|---|---|
| writable constants | `make variant VARIANT_CFLAGS=-DSARM_NO_RODATA` | `rodata-const`, `rodata-mutable` — and must still pass `wx` |
| unhardened link | `make variant LDFLAGS=""` (Linux) | `pie`, `noexecstack`, `rodata-segment` |

`-DSARM_NO_RODATA` exists for that one caller. arm64 macOS cannot link a
non-PIE executable, so the second control is reported as skipped there.

**container** — `--docker` (not part of `make test`) builds the image, extracts
`/sarm` and runs the same seven ELF checks against the artifact that actually
ships. That binary is `make production`, i.e. stripped of local symbols, which
is why the three tables that had no `.global` now have one: a security check
that cannot see the thing it checks in the shipped artifact is not a check.

Results:

```
── hardening                             ... ( 10 checks) ✓     # macOS host
                                             ( 16 checks) ✓     # Linux
```

The difference is not coverage of the same claims — it is that four checks
(`noexecstack`, `rodata-segment`, the core-dump limit, the crashing child) have
no macOS equivalent, and one control cannot be built there.

---

## 9. What Step 13 delivers

154–160 KB of constants moved out of writable memory on both platforms,
including the private scalar and the two tables an indirect branch goes
through. Zero load-time relocations, which is both a hardening property in
itself and the thing that made a position-independent Linux build possible at
all: `ET_EXEC` at a fixed address with an implicitly executable stack became
`ET_DYN`, randomised, with `PT_GNU_STACK RW` and a read-only `.rodata` segment
of its own. `RLIMIT_CORE` set from inside the process rather than by the
harness that launches it, with one new allowlist entry that Step 11's audit
demanded before this step's test ran. A binary-inspection harness in `make
test`, with two deliberately-unhardened controls behind it. And §6, which is
the list of protections this server does *not* have and the reason for each —
the part of a hardening step that is worth the most six months later.
