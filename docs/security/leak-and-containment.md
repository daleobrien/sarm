# sarm — secret leaks and syscall containment

Steps 10 and 11 of the programme in `docs/SECURITY.md`:

> **Step 10 — Add secret-leak tests.** Use recognisable fake secrets.
> **Test:** fuzz responses and logs never contain the secret marker.
>
> **Step 11 — Add syscall allowlist testing.** Trace a normal and malformed
> workload. **Test:** no filesystem-opening syscall succeeds.

Sections 1–7 are Step 10. Sections 8–13 are Step 11. They are written up
together because they run the same traffic: one hostile workload
(`tests/hostile_workload.py`), watched from two sides. Step 10 looks at what
came back out; Step 11 looks at what the server asked the kernel for while
producing it.

Delivered: `tests/hostile_workload.py`, `tests/leak_checks.py`,
`tests/test_leak.sh`, `scripts/syscall_audit.py`,
`tests/syscall_allowlist.txt`, `tests/trace_check.py`,
`tests/test_syscalls.sh`. Both new suites run in `make test`.

No production code changed. **No defects were found** — and, as in
`fuzzing.md`, that sentence is worth exactly as much as the negative controls
behind it, which are §7 and §12.

---

# Step 10 — the secret-leak probe

## 1. What is actually secret, and what could carry it out

`threat-model.md` §4 already answers the first half. The long-lived secret is
one 32-byte ECDSA P-256 private scalar, embedded as literal `.byte` data in
`src/tls/cert_data.S`. The per-connection secrets are the eleven fields of the
key schedule in `tls_state`. The ephemeral ones — the X25519 scalar, the ECDSA
nonce `k` — live in a stack frame and are wiped before their function returns.

The second half is what makes this testable. §4.5:

> There is no logging of any kind in the server — no `stderr` writes, no debug
> output, no error file. The only bytes that reach a client are: TLS records
> sealed from `tls_write_record_buf`, HTTP/1 headers from `header_buf` + an
> embedded body, and h2 frames from `h2_frame_buf` / `transport_writev_scratch`.

So there is exactly one channel out — the socket — and exactly one way for a
secret to reach it: an over-read that runs off the end of one buffer and into
another, or a length that says more bytes than were meant. Both produce the
same observable: bytes on the wire that were never meant to be there. That is
what the probe looks for.

---

## 2. The workload

`tests/hostile_workload.py` is a deterministic generator of hostile
connections, seeded once and reproducible byte for byte. Five campaigns, one
per protocol surface:

| campaign | what it sends |
|---|---|
| `http1` | request lines and header blocks wrong in one generated way: bad methods and versions, traversal and percent-encoded traversal, NUL and control bytes in the path, header lines past the buffer, absurd `Content-Length` and `Range`, no terminator at all, pipelined requests behind a valid one |
| `h2c` | the cleartext preface, then generated frames: unknown types, a length that disagrees with the payload, DATA on a stream that was never opened, a `WINDOW_UPDATE` of zero, HPACK blocks with a literal that claims more than follows |
| `tls_junk` | bytes shaped like TLS records but not a handshake: every content type, versions the server rejects, a length past `TLS_MAX_CIPHERTEXT`, ClientHellos truncated mid-extension |
| `tls_real` | a completed TLS 1.3 handshake through the stdlib `ssl` module with ALPN `h2`, then a valid request *and* a hostile one on separate streams inside the encrypted connection |
| `fragmented` | a valid request delivered one to three bytes at a time, sometimes cut off mid-header |

`tls_real` is the campaign that earns its keep. It is the only one that gets
past the handshake, so it is the only one that can show a leak from a
connection the server considers established — and because a valid request rides
alongside the hostile one, the bytes it captures are a **real response body off
the real response path**, not a 400 error page. The h2 encoding is
`tests/h2_browser_sim.py`'s HPACK encoder, reused rather than rewritten: a
"valid" control case that is subtly invalid tests nothing, because the server
answers it with an error either way.

Every connection sends a unique marker — `SARMLEAKCANARY000123` — in its path,
query, authority or a header. Every byte that comes back is captured: off the
socket for the plaintext campaigns, and for `tls_real` both the ciphertext and
what the TLS layer hands back after decryption.

---

## 3. The needles

`tests/leak_checks.py` knows exactly what to look for, which is what makes
this a regression test rather than an aspiration.

**The private key.** Read out of `src/tls/cert_data.S` — the file the
assembler reads, so no guessing is involved — and searched for whole, and as
every 12-byte window of itself. The window matters more than the whole: an
over-read that catches the tail of the key and stops is the realistic shape of
this bug, and a test that only looks for all 32 bytes would miss it. 12 bytes
because a false positive needs a 96-bit coincidence.

**The request markers.** The server echoes no request bytes in any response —
it serves embedded assets and fixed error pages, and the only request-derived
text in any header is the digits of a `Content-Range`. So a marker coming back
*at all* is a finding, and a marker coming back **on a different connection**
is the specific finding Step 10 exists for: one client reading another's
buffers.

**The key's neighbours.** An over-read into the region around the key usually
catches its neighbours too. Those bytes — the tail of the certificate DER — are
public, but their appearance in a response body is still a disclosure of memory
the server never meant to send, and it is a strictly easier thing to hit than
the key itself. Same window search.

**File content.** PEM armour, `/etc/passwd`'s first field, the ELF and Mach-O
magic numbers. The server makes no file-opening syscall at all (Step 11, below)
so these cannot appear today; they are here because a future change that added
one would surface as a leak long before anyone thought to re-run the syscall
audit.

---

## 4. Two modes, because they have different exposure

The workload runs twice.

**`fork`** is the production shape: every connection is served by a fresh
child, so the `.bss` a child dirties dies with the child and one client cannot
see another's buffers even if the server wanted it to.

**`no_fork`** (`./sarm PORT d`) is the debug and profiling mode, where one
process serves connection after connection over the *same* globals. It is the
only configuration in which a cross-connection leak is possible at all, which
makes it the one the canary is really pointed at. It is not a production mode,
and this test is the reason to keep knowing that.

---

## 5. Three checks about the process, not the responses

`tests/test_leak.sh` adds what a response scan cannot see.

**Nothing on stdout or stderr, ever.** The absence of logging is a security
property, not an oversight — a log line is the cheapest way for a secret to
escape a process. Both descriptors are captured for the whole run and any byte
on either fails it.

**No core dump.** A crash dump is a complete memory disclosure including the
key (`SECURITY.md` §10). The run sets `ulimit -c 0` and then checks that
nothing appeared in the working directory or in `/cores` regardless.

**No death by signal.** The server must still be alive at the end, and must not
have terminated on anything but the `SIGTERM` the harness sends. A crashed
worker is a memory-safety finding whatever the scan says.

---

## 6. Results

```
── secret leak                           ... ( 30 checks) ✓
```

150 hostile connections per mode by default, sized for `make test`;
`--cases N` or `SARM_LEAK_CASES=N` scales it, and the seed is fixed so a
regression is a regression rather than a coincidence. A default run captures
and scans about 35 KB of response bytes across 300 connections. The soak run
by hand for this write-up was `--cases 1500`: 3000 connections over the two
modes, 1402 answered per mode, **707,308 bytes captured and scanned**, 30
checks, nothing found.

Nothing leaked. Specifically: the private scalar never appeared, no 12-byte run
of it appeared, no certificate-adjacent memory appeared outside a handshake, no
marker was ever echoed — not to its own connection and not to any other — and
neither descriptor received a byte.

---

## 7. Verified by sabotage

A leak detector that cannot detect a leak passes exactly like a server that
does not leak, and the two are indistinguishable in the output. Four controls
separate them, three of them permanent parts of the suite:

**The scanner self-test** (`leak_checks.py --self-test`, run first by
`test_leak.sh`). Synthetic responses carrying each needle — the whole key, a
12-byte run of it, certificate-adjacent bytes, PEM armour, its own marker,
another connection's marker — must each be caught, and a clean response must
produce nothing at all. A scanner that fires on everything is as useless as one
that fires on nothing, so both directions are checked.

**The live capture-path check.** Every run counts how many responses carried
`Server: sarm`, a string the server really does send, and fails if the answer
is zero. This is the difference between "nothing was there" and "nothing was
looked at" — the same vacuity idea the fuzz harness applies to its outcome
buckets.

**The empty-run check.** A run in which the server returned no bytes at all
fails before any scan is reported — and so does a run in which no TLS
connection completed, or in which the certificate the server served is not the
one in `src/tls/cert_data.S`. The needles are read out of that file; if the
running binary was built from different key material, every "the key never
appeared" line below it would be about the wrong key.

**An end-to-end planted needle**, run by hand during development: with
`Server: sarm` substituted into the needle list, a 10-connection run reported 5
hits. The whole pipeline — generate, capture, scan, report — sees what is
actually on the wire.

---

# Step 11 — the syscall allowlist

## 8. A stronger claim than tracing can make

Step 11 as written is a tracing exercise: run the server under a syscall
tracer, drive traffic, assert no `open`. That is worth doing and §11 does it.
But it only ever proves something about the workload that ran.

`sarm` supports a much stronger statement, and `scripts/syscall_audit.py`
checks it:

> The binary contains no code path that can issue a file-opening syscall,
> because it contains no `svc` site whose syscall number is one.

That is decidable here for three reasons, all of them properties this project
already has. Every syscall goes through the `SCWINUM`/`SCWISVC` macro pair in
`src/defs.S`, which materialises the number as an **immediate** into x16
(macOS) or x8 (Linux) — so the number is a compile-time constant at every call
site. There is no libc, so no third-party code makes syscalls on the server's
behalf. And the binary is statically linked against nothing, so no loader
brings any in later.

The audit therefore reads the *set of syscalls the binary can make* straight
out of the disassembly, and compares it with `tests/syscall_allowlist.txt`.

---

## 9. The three static checks

**source** — every `SCWINUM SYS_x` site in `src/` must name an allowlisted
syscall. Deliberately platform-blind: it takes the union of the macOS and Linux
call sites, so a syscall added under the `#ifdef` arm you are not currently
building still has to be justified. 44 sites, 21 distinct syscalls.

**binary** — every `svc` in the built binary must resolve to a number, and that
number, mapped through the `.equ SYS_x` table in `src/defs.S` for the platform
being audited, must be allowlisted. 36 `svc` sites on macOS, 17 distinct
syscalls; 15 on Linux (the two platforms differ where one has `fork`/`accept`
and the other `clone`/`accept4`, and in the entropy call).

An `svc` whose number the audit **cannot** resolve is itself a failure. The
resolver is a linear scan that remembers the last immediate written to the
number register — exactly as strong as the property being checked. If a number
ever arrives at an `svc` by a route a linear scan cannot see, the site resolves
to nothing and the audit fails rather than guessing, because at that moment the
claim in §8 has stopped being true and needs re-arguing.

**forbidden** — no syscall from an explicitly named set (`open`, `openat`,
`execve`, `unlink`, `rename`, `mkdir`, `getdents64`, `chroot`, `ptrace`, …)
appears in either. Redundant with the allowlist, deliberately: it is the
assertion Step 11 is actually about and it should fail by name.

The syscall numbers come from `src/defs.S` itself, split at the top-level
`#ifdef __linux__`/`#else` boundary, so the two platforms' numbering — 93 is
`exit` on Linux and nothing on macOS — can never be confused.

---

## 10. The traced workload

The dynamic half is Step 11 as literally described. `tests/test_syscalls.sh`
starts the server under `strace -f` in an **empty directory** (so a code path
that tried to open something by relative name would fail visibly rather than
quietly finding the repo's own files), runs the same hostile workload Step 10
uses, and then asks three questions of the trace:

* does any filesystem-opening syscall appear? (The `execve` of the server
  binary by the tracer is filtered — it happens before a single instruction of
  `sarm` has run. An `execve` of anything else stays a finding.)
* is every syscall that does appear on the allowlist? `tests/trace_check.py`
  folds only genuine aliases — `clone3`→`clone`, `vfork`→`fork`,
  `rt_sigreturn`→`sigreturn`. `recvfrom` is *not* folded into `read`: the
  server calls `read(2)` on its socket, so the socket-specific variant turning
  up would mean something changed.
* did the workload reach the server at all? A trace missing `read` or `write`
  means the first two questions were answered by an empty file.

A representative Linux run (Alpine arm64, 30 connections):

```
close 60 · read 54 · write 47 · setsockopt 21 · accept4 21 · exit 20
clone 20 · getrandom 12 · writev 9 · rt_sigaction 2 · socket 1
listen 1 · bind 1
```

Thirteen syscalls, all allowlisted, no `open`, no `openat`, no `mmap`.

**Platform coverage.** `strace` on Linux; `dtruss` on macOS needs root and a
SIP configuration that permits dtrace, so where neither is available the
dynamic check reports as **skipped**, not passed — a check that cannot run has
not run. The static audit runs everywhere and covers the same ground for every
possible workload rather than for one.

---

## 11. Filesystem non-access (§15)

`SECURITY.md` §15 asks for the same property from the outside, and it is
checkable without a tracer: start the server in an empty, read-only directory,
serve the whole hostile workload out of it, and check that it worked and that
nothing appeared on disk. Both assertions run on every platform. The first is
the interesting one — a server that needed to open anything at runtime could
not answer a request from there at all.

The entropy path is included by construction rather than by exception:
`src/crypto/random.S` calls `getentropy`/`getrandom` and holds no descriptor,
so there is no `/dev/urandom` fallback to audit. That is visible in the audit
output as the only crypto-tree syscall, and in the trace above as
`getrandom 12` — three per TLS connection, exactly as `threat-model.md` §4.4
describes.

---

## 12. Verified by sabotage

The audit's failure mode is a parser that finds nothing: no `svc` sites, or
none it can resolve, reports a clean binary for a server that opens whatever it
likes. So `test_syscalls.sh` builds a **negative control** on every run — a
four-instruction object file that calls `open` (macOS) or `openat` (Linux) —
and requires the audit to reject it, by name, for calling a forbidden syscall.
It is compiled to an object file rather than an executable so it works on a
toolchain with an assembler but no libc, which is the container this project
builds in.

Two further deliberate-failure runs were done by hand: pointing the audit at a
two-entry allowlist produced 49 findings naming every syscall the binary makes,
and pointing it at the control binary produced all three findings — not
allowlisted, forbidden, and present in the binary but absent from `src/`.

---

## 13. Carried forward

* The allowlist is a threat-model document, not a config file. Adding a line to
  `tests/syscall_allowlist.txt` is a change to what the server is permitted to
  do, and `threat-model.md` §6 changes with it. The audit prints any entry
  nothing calls, so the list cannot quietly drift wider than the binary.
* `sysctlbyname` is on the list and is startup-only, reached solely by
  `--workers auto`. It is the one allowlisted call that is not needed to serve
  a request, and it is the obvious candidate if the list is ever tightened
  further.
* The Linux side could be hardened from an *audit* into an *enforcement* with a
  seccomp filter built from this same list — `SECURITY.md` §14 suggests it and
  nothing here blocks it. The list is already in a form a generator could read.
* Step 10's probe cannot see the per-connection key schedule directly: it knows
  the private key's bytes, but the traffic secrets are derived inside the server
  and never leave it, so the check for them is indirect (a marker or
  certificate-adjacent leak from the same buffers). The in-process route to
  checking them directly is the one `tests/security/test_fuzz_tls_handshake.c`
  already uses — poison the fields, run the driver, assert what survived — and
  is the natural next increment if that ever needs to be tighter.
