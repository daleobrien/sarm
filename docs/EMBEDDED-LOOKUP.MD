# Embedded-file lookup — evidence and decision, prompts/10

Empirical answer to `prompts/10-embedded-lookup.md`. **Target:** Apple M3
Pro, macOS 27.0, arm64 (commit `d8dcd89`, before this prompt's changes).

---

## The one-line answer

**Linear scan, cleaned up, is the sole surviving mechanism.** The
FNV-1a hash side table, its build-script generation, and the unused
`fnv1a_64` primitive that computed it are deleted. `lookup_embedded` costs
**~7 ns/call** measured against the real six-entry table (worst case ~9 ns,
a full-scan miss ~4.7 ns) — about 0.001% of the ~657 µs a connection costs
per `docs/PROFILE-POST.MD`, consistent with that report's independent
finding of **0 self-time samples across 56,935 busy samples, all four
scenarios combined**. There is nothing here for a hash table or binary
search to win.

---

## 1. What existed before this prompt

Three pieces of a hash-based lookup existed and none was wired up:

1. `embed_www.sh` computed an FNV-1a 64-bit hash per path at build time.
2. `src/util/fnv1a_64.S` implemented the hash, unit-tested, zero call
   sites anywhere in `src/`.
3. `embedded_hash_table` in the generated `src/embedded.S` — a
   `(hash, index)` array sorted by hash, 96 bytes total for 6 entries.

`lookup_embedded` itself ran a linear scan (its header comment called it a
"DEBUG fallback") with several independent inefficiencies: two unjustified
callee-saved registers (x21, x24 — confirmed by `regpressure.py` before this
change), two branches to the immediately following instruction, an
`index * 80` recomputed every loop iteration instead of an advancing
pointer, and no unit-test coverage of its own (`test_file.c` covered
`check_path_traversal`, `check_path_safety`, `get_filetype`, but not
`lookup_embedded`).

## 2. Benchmark

`scripts/benchmarks/bench_lookup_embedded.c` links the real generated
table (`src/embedded.S`, from `embed_www.sh`) and times the cleaned-up
`lookup_embedded` against every real asset path (one per table position,
so scan depth varies) plus a realistic miss. Best-of-7, 2,000,000
iterations per path:

```
$ ./scripts/benchmarks/_bench_bin/bench_lookup_embedded
{"function":"lookup_embedded","sizes":{"hit_pos0":6.30,"hit_pos1":7.15,
"hit_pos2":8.01,"hit_pos3":8.17,"hit_pos4":8.17,"hit_pos5":5.94,
"miss":4.72},"runtime_ns":6.92}
```

Three runs agreed within ~0.5 ns per path. Position-0/5 are cheaper because
they're also the shortest paths (`streqn`'s cost scales with path length,
not just scan depth); the miss is cheapest because no path length in the
table matches the query, so `streqn` is never called.

**~7 ns against a ~657,210 ns connection (`docs/PROFILE-POST.MD` §1) is
~0.001%.** At `embedded_count = 6`, the entire hash table is two cache
lines and binary search's ~2.6 average comparisons vs. linear scan's ~3
is not a real difference once branch mispredictions are considered — and
neither is reachable from noise this far below the floor. This is the
outcome `prompts/README.md`'s own instruction anticipates: *"If it is not
[worth it], say so and stop — that is a valid outcome."*

## 3. Decision: delete the unused mechanism

Per the prompt's explicit permission ("deleting the unused mechanism ...
is a legitimate outcome"):

- `embedded_hash_table` / `embedded_hash_count` generation removed from
  `embed_www.sh`.
- The hash field removed from the per-file table entry (was `+0` of an
  80-byte entry; entries are now 72 bytes with no hash field —
  `embedded_entry_size` updated to match).
- `src/util/fnv1a_64.S` and `tests/unit/test_fnv1a_64.c` deleted (their
  only purpose was this mechanism; zero other call sites existed).
- The unused sentinel table entry (`.8byte 0 // sentinel`) also removed —
  it was never read; `lookup_embedded` bounds its scan by `embedded_count`,
  not by scanning for a terminator.
- `lookup_embedded.S`'s header comment, `embed_www.sh`'s comments, and
  `tests/unit/stubs.S` / `stubs_response.S` (the unit-test fixture tables)
  all updated to describe the 72-byte, hash-free layout.

`bl streqn` inside the scan loop was deliberately **kept**, not
hand-rolled into an inline compare: `streqn` is length-matches-first, so it
runs at most once per lookup for this table (paths mostly have distinct
lengths); the measured cost above already includes it; and reusing the one
already-tested string-compare primitive on a security boundary
(`check_path_safety.S`/`check_path_traversal.S` sit downstream of this
function) is safer than adding new comparison logic to chase an
unmeasurable win.

## 4. What was fixed regardless of the algorithm decision

Independent of the linear-scan-vs-hash question (all four are in
`lookup_embedded.S`):

- Register save/restore: x21/x24 removed (unjustified — confirmed by
  `regpressure.py`, which now reports `opportunity: NONE`). Stack frame
  shrank from 64 to 48 bytes.
- The `// Clobbered Registers:` header corrected to the true set;
  `validate_clobbers.py` reports `AGREE`.
- Both branches to the immediately following instruction removed.
- The scan now advances an entry pointer by `entry_size` instead of
  recomputing `index * entry_size` every iteration.

## 5. Test coverage added

`tests/unit/test_file.c` gained direct `lookup_embedded` coverage (none
existed before): a found case asserting all seven return values, and five
not-found cases — an unrelated path, an empty path, a path of the same
length as the real entry but different bytes (exercises the
length-matches-but-`streqn`-rejects branch), and two same-prefix
different-length paths (shorter and longer, exercising the length-mismatch
branch that never calls `streqn`). All pass, alongside the existing 3,706
unit tests, `tests/test_files.sh`, `tests/test_security.sh`,
`tests/test_protocols.sh`, and `tests/h2_browser_sim.py`.
