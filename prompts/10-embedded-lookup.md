# 10 — Resolve the embedded-file lookup

**Explicitly low priority.** A small, self-contained task with an unusually
clear brief — a complete lookup mechanism was built end to end and never
connected — but the repository currently has only a very small number of
embedded assets, so the objective is to **determine whether lookup
optimization has a measurable effect on the real request workload before
introducing a more complicated lookup algorithm**, not to assume the more
sophisticated mechanism is worth finishing.

## Context

`lookup_embedded` (`src/file/lookup_embedded.S`) resolves a request path to an
embedded asset. It runs **once per request**.

Its own header comment says:

> The table is sorted lexicographically by path, so binary search gives
> O(log n) lookup instead of linear scan. **Currently uses a DEBUG linear-scan
> fallback to verify entry layout.**

That is accurate — but it understates the situation. Three separate pieces of a
hash-based lookup exist and **none of them is used**:

1. **`embed_www.sh` computes an FNV-1a 64-bit hash per path** at build time and
   stores it at offset +0 of every 80-byte table entry. The script's own
   comment reads "Stage 4: FNV-1a hash-based lookup table for O(log n) file
   resolution", and it explicitly notes the hash "matches fnv1a_64 in
   src/util/fnv1a_64.S".
2. **`src/util/fnv1a_64.S` exists and is unit-tested**
   (`tests/unit/test_fnv1a_64.c`) — and has **zero call sites** anywhere in
   `src/`.
3. **A dedicated side table exists**: `embedded_hash_table` in the generated
   `src/embedded.S` is a packed array of `(hash, index)` pairs, 16 bytes each,
   **sorted ascending by hash**, exported as a global alongside
   `embedded_hash_count`. **Nothing references it.**

Meanwhile `lookup_embedded` walks the main 80-byte-stride table linearly,
comparing lengths and calling `bl streqn` on every length match.

Scale matters here and cuts against over-engineering: **`embedded_count` is 6.**
The whole hash table is 96 bytes — two cache lines.

## Objective

Decide, on evidence, what this function should do; implement it; and make the
code, the comments and the build script agree. Leaving a third mechanism
half-built is not an acceptable outcome.

## The honest framing

At n = 6, binary search over linear scan is close to meaningless — ~2.6
comparisons versus an average of 3 — and binary search's unpredictable branches
may well make it *slower*. The documented "O(log n) instead of linear scan"
rationale does not obviously hold at this size, and a larger asset set is not
in prospect for this server.

**So the performance win here may be negligible, and that is a legitimate
finding.** Prompt 00's profile decides whether the request path matters at all
next to the handshake. If it does not, the deliverable is the cleanup and the
corrected documentation, and you should say so plainly rather than manufacture
a justification for the more complex option.

That said, the current implementation has real inefficiencies that cost nothing
to fix, listed below.

## Defects found by reading the source

Verify each before acting; all are in `src/file/lookup_embedded.S`.

- **x21 and x24 are saved and restored but never written.** The prologue does
  `stp x21, x22, [sp, #32]` and `stp x23, x24, [sp, #48]`, but the body uses
  only x19, x20, x22, x23. This matches `scripts/regpressure.py`, which
  independently flags x21 and x24 as unjustified — a useful confirmation that
  the analyzer works.
- **The clobber header is wrong.** It documents `x19-x24` as clobbered; x21 and
  x24 are not. Exactly the drift prompt 01's `validate_clobbers.py` exists to
  catch.
- **`Lle_found_from_linear: b Lle_found`** branches to the immediately
  following instruction.
- **`b Lle_epilogue` in `Lle_not_found`** also branches to the next
  instruction.
- **`mul x6, x23, x9` recomputes `index * 80` every iteration** instead of
  advancing a pointer by 80.
- **`bl streqn` is a function call inside the scan loop**, invoked for every
  length match.

## Method

Benchmark `lookup_embedded` with:

- the current six-entry workload;
- representative request paths;
- repeated requests;
- realistic HTTP/2 request workloads.

Measure its contribution to total request latency before deciding anything
about the algorithm.

### First fix obvious inefficiencies

Where safe, and independent of the hash/binary-search decision below, fix the
low-risk defects listed above:

1. Remove unjustified save/restore registers (x21, x24).
2. Remove branches to the immediately following instruction.
3. Maintain an advancing table pointer instead of recalculating `index * 80`.
4. Avoid the unnecessary `bl streqn` call inside the lookup loop where a
   cheaper comparison suffices.

These are low-risk transformations and should be considered independently of
whether the lookup algorithm itself changes.

### Hash/binary-search decision

**Do not automatically connect the existing FNV-1a hash table.** At six
entries, the extra data and hashing work may cost more than the scan it
replaces.

Compare, using the real asset set:

1. **Linear scan, cleaned up.** Fix the defects above. Likely competitive at
   n = 6 and the simplest thing that works.
2. **Linear scan over the packed hash table.** Hash the request path once with
   `fnv1a_64`, then scan `embedded_hash_table`'s 96 contiguous bytes comparing
   64-bit integers — no string comparison, no call, two cache lines, no
   data-dependent branching.
3. **Binary search over `embedded_hash_table`.** The documented intent.
   Evaluate it, but expect branch mispredictions to erase the theoretical
   advantage at n = 6.

**If the difference is below the noise floor, keep the simplest
implementation. That is a successful outcome.**

If measurement says the linear scan wins outright, **deleting the unused
mechanism** — `embedded_hash_table`, the hash field, and the unused
`fnv1a_64` call site — is a legitimate outcome — it shrinks the binary and
removes a misleading half-built path. Do not keep dead infrastructure "in
case".

Whichever you choose, exactly one mechanism should survive, and the comments
in both `lookup_embedded.S` and `embed_www.sh` must describe it accurately.

## Security constraint — read this before implementing option 2 or 3

**A hash match is not a match.** FNV-1a is not collision resistant, and the
request path is attacker-controlled. If the lookup returns an entry on hash
equality alone, a crafted path that collides with `index.html` serves the wrong
file — a correctness bug and a security bug.

Any hash-based path **must confirm with a full length-and-bytes comparison**
(`streqn`) before returning the entry. The hash is a filter that avoids most
string comparisons, never a substitute for one. Budget for that confirming
compare when estimating the win — it means the fast path is one integer scan
plus one string compare, not one integer scan.

Related: this function sits behind the path-traversal defences in
`src/file/check_path_safety.S` and `check_path_traversal.S`. Do not weaken the
ordering or assumptions those rely on.

## Testing

- `tests/unit/test_file.c` — direct coverage of `lookup_embedded`.
- `tests/test_files.sh` — every embedded asset must serve correctly.
- `tests/test_security.sh` — path traversal and malformed paths. **Mandatory**;
  this function is on the security boundary.
- Add a **negative test**: a path that is not in the table must return
  carry-set (not found) — including paths sharing a prefix with a real asset
  and paths of the same length as a real asset.
- If you implement a hash path, add a test that **forces the collision branch**:
  construct or inject two entries with equal hashes and assert the confirming
  string compare rejects the wrong one. An untested collision path is an
  untested security control.

## Acceptance criteria

- One lookup mechanism remains; the other artifacts are either used or removed.
- `lookup_embedded.S`'s header comment and `embed_www.sh`'s comments both
  describe what the code actually does. No "DEBUG fallback" note survives.
- The `// Clobbered Registers:` header lists the true set.
- All tests pass, security suite included, plus the new negative and collision
  tests.
- A measurement, or an explicit statement that the difference is below the
  noise floor from prompt 02 and the choice was made on simplicity and safety
  instead. Either is acceptable; silence is not.
- The final implementation matches every embedded asset correctly, returns
  not-found correctly, and preserves path semantics.
- **If lookup represents less than a meaningful fraction of request latency,
  document that result and stop** — do not add algorithmic complexity to
  chase a win the profile does not support.

## Constraints

- Invariants in `prompts/README.md` apply — in particular the carry-flag return
  convention, which this function uses (`cmn xzr, xzr` = found,
  `cmp xzr, xzr` = not found). Do not let a flag-setting instruction move
  between those and the `ret`.
- Keep the function's ABI and its seven return values unchanged; callers depend
  on them.
- If the build script changes, regeneration must stay reproducible —
  `src/embedded.S` is generated, never hand-edited.
