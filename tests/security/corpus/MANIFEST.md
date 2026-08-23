# tests/security/corpus — the preserved inputs

Every `.bin` file under this directory is an input that once made a routine in
`src/` do something it should not. They are replayed, from bytes, at the start
of every run of the suite they belong to — so `make test` runs them — and a
failure is reported as a **corpus REGRESSION** naming the file.

This is the third arrow of `docs/SECURITY.md` Step 14:

```text
corpus input  →  minimal reproducer  →  unit/regression test  →  fix
```

The layout is `corpus/<suite>/<campaign>/<name>.bin`, where `<suite>` is what
the binary passes to `fuzz_suite()` (`tls_record`, `tls_handshake`, `http`,
`frag_socket`, `frag_http`) and `<campaign>` is a campaign name from that
suite's target table. A campaign with no byte-level replay entry has no
directory here: its inputs are not one flat string a peer controls, so bytes
alone would not reproduce them.

**Bytes, not seeds.** Every finding below was originally recorded as a
`SARM_FUZZ_SEED`/`SARM_FUZZ_CASE` pair, and none of those pairs still
reproduces: replaying seed 25423240288893562, case 83 today gives a 238-byte
flight, not the five bytes that crashed. The generators moved, as generators
do. That is the whole argument for this directory — a reproducer that depends
on a generator has the lifetime of that generator, and one that is bytes does
not.

## Adding one

```bash
scripts/fuzz_minimize.py tests/security/_obj/test_fuzz_http path \
    tests/security/findings/http-path-seed…-case…-crash.bin --keep my-finding
```

then add a row below saying what it is. A file nobody can explain is a file
nobody dares delete.

## What is here

### `tls_handshake/flight`

The five-byte pre-authentication crash — `docs/SECURITY.md` §11. A
handshake record whose fragment is shorter than the 4-byte handshake header;
`tls_server_handshake` subtracted the header from the fragment length
unsigned, and `tls_transcript_add` was asked to hash 2^64 − 4 bytes. Reachable
by any peer that can open a TCP connection, as the first thing it says.

| file | bytes | what it is |
|---|---|---|
| `hs-fragment-under-header-len0.bin` | `16 03 01 00 00` | the original crash: fragment length 0 |
| `hs-fragment-under-header-len1.bin` | + 1 byte | fragment length 1 |
| `hs-fragment-under-header-len2.bin` | + 2 bytes | fragment length 2 |
| `hs-fragment-under-header-len3.bin` | + 3 bytes | fragment length 3 — the last length that underflows |
| `hs-fragment-header-exact-len4.bin` | + 4 bytes | the first length that does **not**: a clean rejection, so a "fix" that rejects everything is not a fix |

Fix: `src/tls/server/handshake.S`, the `cmp x2, #TLS_HS_HEADER_LEN` /
`b.lo .Lhs_fail_generic` immediately after the content-type test.

Verified by removing that check and re-running: all four underflow entries
report SIGSEGV, and the length-4 entry stays clean.

### `http/path`

Three reads past the length argument in `parse_path` —
`docs/SECURITY.md` §11 — and one entry per instruction of the fix, plus
the input the fuzzer originally found.

| file | bytes | what it covers |
|---|---|---|
| `parse-path-overread-step8-original.bin` | `GET /foo/b]dA%^W?l` | the input Step 8 found, kept because it is the one a human can point at |
| `parse-path-overread-trailing-slash.bin` | `GET /aaaaaaaaaaaa/` | `Lchar_found`: the byte after a `/` that is the last byte of the header |
| `parse-path-overread-16-byte-window.bin` | `GET /aaaaaaaaaaa` (16 bytes) | the `" /"` search window: 17 bytes wide, guarded by a 16-byte precondition |
| `parse-path-overread-filename-copy-loop.bin` | `AAAAAAAAAAAAAAA /` (17 bytes) | the filename copy loop's own bound |

Fix: `src/parse/parse_path.S` — two `b.hi` became `b.hs`, and the minimum
length became 17.

Verified by reverting each of the three instructions on its own, which is a
sharper question than reverting all three:

| reverted | 16-byte-window | trailing-slash | step8-original | filename-copy-loop |
|---|---|---|---|---|
| the 17-byte window (`cmp x22, #17` → `#16`) | **faults** | clean | clean | clean |
| `Lchar_found`'s `b.hs` → `b.hi` | clean | **faults** | **faults** | clean |
| the copy loop's `b.hs` → `b.hi` | clean | clean | clean | **faults** |
| all three | **faults** | **faults** | **faults** | **faults** |
| none (as shipped) | clean | clean | clean | clean |

The fourth entry exists because of that table. The three inputs Step 8 recorded
cover only two of the three instructions: `GET /foo/b]dA%^W?l` reaches
`Lchar_found`, not the copy loop, and with only the copy loop's `b.hs` reverted
every entry stayed green. So the copy loop was re-fuzzed with just that one
instruction put back — the `path` campaign found a case in 22 162 tries, the
harness preserved its 17 bytes, and `fuzz_minimize.py` turned them into
`AAAAAAAAAAAAAAA /`. That is Step 14's pipeline run end to end for a defect
that was already fixed, in order to prove the corpus can see it.
