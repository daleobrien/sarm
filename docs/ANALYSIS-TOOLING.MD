# Analysis Tooling — Correctness Report

Prompt `prompts/01-analysis-tooling-correctness.md`. This fixed the analysis
tooling itself (no `.S` code changed for that part — see below), then used
the fixed tooling to correct every stale `// Clobbered Registers:` header it
found. That second pass touched 87 `.S` files, comment lines only: no
instruction was added, removed, or reordered.

## What changed

| File | Status |
|---|---|
| `scripts/asmparse.py` | **new** — the single parser: labels, macros, regions, call graph |
| `scripts/abi.py` | rewritten on top of `asmparse`; NZCV modelled; two soundness bugs fixed |
| `scripts/regpressure.py` | rewritten on top of `asmparse`; region-aware, call-site aware |
| `scripts/validate_clobbers.py` | **new** — checks the analyzer against the hand-written headers |
| `scripts/optimizer.py` | one line: passes the original function so the NZCV check is differential |

`make -C tests/unit test` — **3423 tests, all pass.**

---

## Defect 1 — local labels are invisible

`abi.py:129` discarded every line beginning with `.` before testing for a
label, so all 393 `.L…` labels were dropped. `regpressure.py` carried a
corrected copy of the parser, and that divergence is how the bug survived.

Both now import one parser from `asmparse.py`. `abi.py` owns no parser at all.

**Effect.** Before, `regpressure.py` reported `Loop 0` for every function in
the repo. Now **81 of 173 regions** contain a detected loop:

| Region | Back edges | Peak in loop |
|---|---|---|
| `raw_read_exact` | 2 | 4 |
| `parse_path` | 3 | 11 |
| `h2_huffman_decode` | 3 | 14 |
| `.Lgcm_ghash_run` | 2 | 5 |
| `p256_bn_mul` | 4 | 15 |

## Defect 2 — macros are never expanded

`abi.py` now expands macros before parsing, platform-aware, defaulting to the
host (`--linux` forces the other branch: Linux puts the syscall number in x8,
macOS in x16).

Expansion was also widened beyond `defs.S`. Subsystems define their own
macros — `gcm_rbit` in `crypto/gcm/data.S`, the `carry51` family across
`crypto/x25519/*.S` — and those expand to real arithmetic. Leaving them as
opaque one-line "instructions" hid the same class of writes.

**Effect.** `raw_read_exact` now reports **x19, x20 and x21 all justified** —
live across the `svc` that `SCWISVC` expands to. Under the old model the
syscall was invisible, all three looked removable, and applying that would
have miscompiled it. Same for `h2_verify_preface`, `crypto_random_bytes` and
`raw_write_all`.

Expansion also finds writes documentation missed: `verify_http_version`
writes x2 via `adr_l x2, host_str`, which its header does not list.

## Defect 3 — NZCV is not modelled

NZCV is now tracked as a value: a def/use table (`FLAG_DEFS` / `FLAG_USES`),
backward liveness, and forward reaching-definitions. `bl`, `blr` and `svc`
are flag *writers* — AAPCS64 does not preserve the condition flags across a
call.

**55 regions** use the carry-flag return ABI, and all 55 report NZCV live at
their exit. That is more than the 36 the old tooling counted, for three
reasons: local-label regions are now visible; doc headers are located by the
name they declare rather than by adjacency, so functions whose header is
separated from their label (`itoa`, the whole x25519 chain) are no longer
missed; and four regions exit by tail call rather than `ret` (`write_all` is
nothing but `b transport_write`), so an exit is any `ret` *or* any branch that
leaves the region. 55 matches the 55 source files the brief says the
convention spans.

The check is differential. A single-function analysis cannot know which
flag write is the intended status; a comparison against the function being
replaced can. `check_function(candidate, original=...)` compares, for every
flag reader, the set of writes that reach it. `optimizer.py` now passes the
original.

Validated against `p256_reduce`, the densest ADDS/ADCS/SUBS/SBCS sequence in
the repo (91 instructions, **23 flag writers and 27 flag readers**):

```
$ # break one link in the carry chain: adcs x15, x5, x15  ->  add x15, x5, x15
[ERROR] NZCV dependency changed: the condition flags read by 'adcs x17 x6 xzr'
        come from a different instruction than in the original
        (now also reached by adcs x14 x4 x14, no longer reached by adcs x15 x5 x15)
        -- a flag-clobbering instruction was moved or inserted into a live flag range
```

Also caught, on `raw_read_exact`: an `adds` hoisted between `cmn xzr, xzr` and
the `ret`, and a flag-clobbering instruction sunk between a `cmp` and its
`b.eq`. A harmless reordering of two `mov`s stays silent.

---

## Four further soundness bugs found while fixing the above

**A load is not always a restore.** `effect()` treated every load of a
callee-saved register as a restore, whatever address it read. So
`aes128_encrypt`'s `ld1 {v5.16b, v6.16b, v7.16b, v8.16b}, [x1], #64` — loading
round keys from the caller's key schedule into **v8-v11, which are
callee-saved** — read as a restore, and the checker answered "safe" to a
question whose real answer is "this violates AAPCS64". A load now only counts
as a restore when its address is SP- or x29-relative.

**Unreachable is not clean.** The dataflow seeded every block with a valid
`State()`. With loops finally visible, every loop header joined a real
predecessor state against a fictitious `sp_net = 0`, and the
sp-disagreement sentinel is sticky — so every loop in the repo would have
reported "could not verify SP restoration". Unreachable blocks are now `None`
and contribute nothing to a join. This bug was latent only because defect 1
meant there were no loops to hit it.

**Writeback detection in `regpressure.py` never fired.** `_writeback_regs`
matched a trailing `],` on the operand string to catch post-indexed
addressing (`[x27], #16`), but operands arrive already comma-split — the
comma that pattern needed is consumed by the split before the regex ever
runs. A post-indexed base register was silently missing from the write set,
which makes a pointer that is genuinely advanced in a loop look
loop-invariant. Fixed by matching a bare `[xN]` operand that isn't the last
one in the (already-split) list, which is exactly the shape a post-index
form takes once split.

**`svc` is not `bl`.** The same function credited every call-like
instruction — `bl`, `blr`, *and* `svc` — with writing x30, because it tested
"did this instruction write to any caller-saved-for-calls register" rather
than checking the instruction itself. A bare syscall never touches the link
register; only `bl`/`blr` do. Fixed to check the mnemonic directly.

## Real ABI violations in `src/` (reported, not fixed — no `.S` edits)

Running the corrected checker over all 173 regions leaves **7 errors in 2
functions** (one per `ret`):

1. **`aes128_encrypt`** (`src/crypto/aes128/encrypt.S:41`) writes **v8, v9,
   v10, v11** and never restores them. v8-v15 are callee-saved. This
   propagates: `aes_gcm_encrypt`, `aes_gcm_decrypt`, `tls_record_encrypt`,
   `tls_record_decrypt` and the rest of the chain up to `transport_write`
   inherit the same v8-v11 clobber. The headers now say so (see the
   validation section below) — the header fixes make the leak accurately
   *documented*, not fixed; the code still violates AAPCS64.
2. **`h2_verify_preface`** (`src/h2/h2_verify_preface.S:32`) writes **x21**
   (`mov x21, #0`) but saves only x29/x30 and x19/x20.

Both are latent today — no caller happens to hold a live value there — but
either would bite any transformation that starts using those registers.

The remaining 14 findings are warnings, and all are correct conservatism:
eight noreturn/tail-call functions that `bl` without saving x30, two functions
(`reply_status`, `http1_write_response`) that skip their own prologue on one
path so SP genuinely differs between paths, and four notes on two private
regions that write a callee-saved register by design.

That last case is checked **in caller context**: `hex_to_val` returns a flag in
x20 and `.Lh2wh_append_str` uses x23, neither restoring it. For a non-`.global`
region the checker verifies every caller preserves the register before
downgrading the error to a note — and if a caller does not, it stays an error.

---

## Local-label regions

The analysis unit is now a **region**: any label reached by `bl`, `.global` or
not. 173 regions, **15 reachable only through a local `.L` label**.

Regions nest. `hex_to_val` sits in the middle of `decode_url`'s body, so
`decode_url` extends past it — its epilogue is *below* `hex_to_val` in the
file. And they can fall through: `p256_fe_sqr` is `mov x2, x1` running
straight on into `p256_fe_mul`. Both are handled generally; no name is
special-cased.

### `.Lgcm_ghash_run` — the real GHASH implementation

```
.Lgcm_ghash_run  (src/crypto/gcm/data.S)
  kind                    : private region (local label)
  call sites in src/      : 3  (aes_gcm_decrypt, aes_gcm_encrypt, ghash)
  instructions            : 40        loops (back edges) : 2
  peak live GPRs          : 5  (in loops: 5)
  callee-saved used       : x27, x28      justified: x27      unjustified: none
  save/restore insns      : 2         stack frame: 32 bytes
  call sites out          : 2  (.Lgcm_gf_mul)
  clobbers (transitive)   : x9-x12, v0-v7, v20
  preserved               : x30
```

x27 (data pointer) and x28 (byte count) are its **input contract**, set up by
its callers; it reads them without saving them. Registers a region merely
reads are excluded from the "unjustified" opportunity set — there is no
prologue there to recover, and reporting one would point a transformation at
code that does not exist.

`--callers .Lgcm_ghash_run` prints it alongside `aes_gcm_encrypt` and
`aes_gcm_decrypt` (peak 18 GPRs each, x19-x28 all justified, v16-v21 held
across the call).

### `ghash` does not shadow it

```
ghash  (src/crypto/gcm/ghash.S)
  call sites in src/ : 0
  opportunity        : NONE -- no call site anywhere in src/ -- not on any
                       hot path this server executes
```

19 exported symbols have no in-tree caller, and 7 of those also never have
their address taken. `ghash` is one of the 7; AES-GCM reaches
`.Lgcm_ghash_run` directly. Ranking now uses call sites, so `ghash` cannot be
reported as the hot GHASH implementation, and `.Lgcm_ghash_run` is neither
unreachable nor unanalysable for lacking a `.global`.

"No `bl` to it" is not the same as dead, though, and the checker says so: the
nine h2 frame handlers are reached through a `.quad` jump table in
`h2_dispatch_frame.S`. A symbol whose address is taken anywhere counts as
reachable, so those handlers are not suppressed from the ranking.

### `p256_reduce` and `p256_fe_mul`

| | `p256_reduce` | `p256_fe_mul` | `p256_bn_mul` |
|---|---|---|---|
| kind | file-local (`bl` target) | `.global` | `.global` |
| call sites in `src/` | 1 (`p256_fe_mul`) | 5 | 4 |
| instructions | 91 | 18 | 44 |
| loops | 0 | 0 | 4 |
| peak live GPRs | 17 | 6 | 15 |
| callee-saved used → justified | x19, x20 → both | x19, x20 → x19 only | none |
| NZCV writers / readers | 23 / 27 | 2 / 0 | 8 / 7 |
| clobbers (transitive) | x0-x17 | x0-x17 | x5-x17 |
| documented header | x0-x17 ✓ | x0-x17 ✓ | x5-x17 ✓ (was x0-x17, x0-x4 read-only) |

`p256_reduce` was previously invisible: it is file-local and sits *above* the
first `.global` in its file, and the old `.global`-to-`.global` split never
produced it. Both of its `bl p256_bn_mul` calls resolve, and `p256_bn_mul` is
correctly a hot leaf with no frame (0 callee-saved registers, no stack).

One live finding: **`p256_fe_mul` preserves x20 for nothing.** It sets
`mov x20, x2` and consumes it in `mov x3, x20` *before* `bl p256_bn_mul`, so
x20 is never live across a call — the `stp`/`ldp` pair is pure overhead.

Note on the acceptance criteria: `p256_reduce` is **not** one of the
carry-ABI functions. It documents `out[0..3] = T mod p` and returns its result
in memory; NZCV is not part of its contract, so it correctly reports flags
*not* live at `ret`. Its carry chains are dense and fully tracked internally,
which is what makes it the stress test the brief wanted.

---

## Validation against the 207 clobber headers

`scripts/validate_clobbers.py`. Of the 207 `// Clobbered Registers:` headers,
**57 document macros** (`carry51`, `gcm_rbit`, `mime_entry` …), not functions.
The remaining **150 function headers** are checked.

Headers do not follow one convention — some list what the function itself
writes, some the full cost to a caller — so each is scored against both a
direct and a transitive clobber set and judged on the closer one (106 direct,
44 transitive). Documented return registers are not counted as undocumented
clobbers.

The first run, against the headers as they stood, found:

| Verdict | Count |
|---|---|
| AGREE | 58 |
| OVERSTATES (header names a register never written) | 57 |
| BOTH | 20 |
| UNDERSTATES (header omits a register that *is* written) | 13 |
| UNPARSED (`"see transport_write"`) | 2 |

### Triage: the split

**Analyzer bugs found: 2** — both listed above (load-is-not-restore,
unreachable-is-not-clean). Both were found *by* this comparison and are fixed;
every disagreement remaining after that fix was traced to documentation.

**Stale or incomplete documentation: 90 headers**, all rewritten to the
analyzer's output. Three systematic patterns:

- *OVERSTATES (57), mostly input registers.* The headers listed argument
  registers as clobbered even when the function only read them:
  `aes128_encrypt` listed `x0,x1,x2` (all read-only), `p256_bn_mul` listed
  `x0-x17` where x0-x4 are inputs. Harmless to a caller, but now trimmed —
  `p256_bn_mul` reads `x5-x17`. `x18` appeared in several headers and is
  never touched by anything; removed throughout.
- *UNDERSTATES (13), the direction that can hurt.* The v8-v11 leak from
  `aes128_encrypt` propagates through the whole call chain — `aes_gcm_encrypt`,
  `aes_gcm_decrypt`, `tls_record_encrypt`, `tls_record_decrypt`,
  `tls_server_handshake`, `application_read`, `application_write`,
  `transport_read` and `transport_write` all now list `v0-v11` instead of
  `v0-v7`. Headers that omitted **x16**, the macOS syscall-number register
  written by `SCWINUM`, now include it (`child`, `_main`, `h2_send_settings`,
  `transport_read`). `child` and `_main` now list x30 alongside their `bl`.
  `verify_http_version` now lists x2. `tls_finished_verify_data` now lists
  x9-x11.
- *NZCV annotations.* 4 headers claimed NZCV for functions with **zero** flag
  writers (`x25519_fe_add`, `x25519_fe_sqr`, `x25519_fe_sub`,
  `x25519_fe_tobytes`) — their `carry51` macros use only `lsr`/`add`/`and`.
  The annotation is now gone from all four. 89 functions write flags without
  the annotation, which is the majority convention rather than a defect and
  is left alone.

### After the fix

Re-running `validate_clobbers.py` against the corrected headers:

| Verdict | Count |
|---|---|
| AGREE | **146** |
| OVERSTATES | 2 |
| BOTH | 0 |
| UNDERSTATES | 0 |
| UNPARSED | 2 |
| NZCV claimed but never written | 0 |

The 2 remaining OVERSTATES are not stale documentation, they're deliberate
conservatism: `parse_request`'s header promises `x19-x28` preserved as one
uniform claim across every path, even though `x28` happens not to be written
on any path through the current body. `transport_write`'s header is an
explicit superset spanning two call paths ("raw_write_all only touches
x0-x2/x9/x25/x26; the TLS path additionally uses everything
tls_app_data_write clobbers"), wider than either path alone. The 2 UNPARSED
headers (`h2_read_exact`, `write_all`) point at `transport_read` /
`transport_write` by name (`"see transport_write"`) rather than listing
registers, which the checker correctly declines to score rather than
guessing.

**Deliberate asymmetry.** `regpressure` models `svc` as destroying the whole
caller-saved set, because that is what the kernel is permitted to do and
liveness must assume it. The headers describe what the syscall path actually
writes. Folding the permitted-clobber model into this comparison would make
every syscall function disagree for a reason about conservatism rather than
accuracy, so the comparison uses architectural writes only. The conservative
model still governs the `justified` analysis, where it is what matters.

---

## Aggregate, before and after

```
                                            before      after
regions analysed                            165         173  (+15 local-label)
regions containing a loop                   0           81
peak GPR pressure (max / median)            25 / 6      24 / 6
total save/restore instructions             589         613
functions preserving callee-saved GPRs      76          85
  ...with a register never live across a call  35        36
regions using the carry-flag return ABI     36          55  (all 55 live at exit)
exported symbols with no in-tree caller     n/a         19
  ...and whose address is never taken       n/a          7
```

## Commands

```bash
python3 scripts/regpressure.py                       # ranked report
python3 scripts/regpressure.py --callers .Lgcm_ghash_run
python3 scripts/abi.py --source src/crypto/p256/sqr_mul.S --function p256_reduce --flags
python3 scripts/validate_clobbers.py --verdict OVERSTATES
```
