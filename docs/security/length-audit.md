# sarm — length-arithmetic audit

Step 5 of the programme in `docs/SECURITY.md`:

> **Step 5 — Audit all length arithmetic.** Introduce explicit checked-add and
> checked-range patterns. **Test:** integer-overflow corpus is rejected.

`docs/security/threat-model.md` §3 inventories *which* lengths an attacker
controls and what bound constrains each. This document is the next question:
for every one of those lengths, is the arithmetic that carries it to a memory
access actually safe, and how do we know? It ends with four code changes and
two new test suites.

---

## 1. Method

A **site** is any instruction where a wire-derived value takes part in
arithmetic whose result reaches an address, a length, or a bound comparison.
Sums of two such values, and sums of one with a pointer, are the cases that
matter; a lone `ldrb` of a length field is not a site until something is done
with it.

Each site gets one of three verdicts.

| Verdict | Meaning |
|---|---|
| **width** | The sum cannot wrap because every operand is a 8/16/24-bit wire field held in a 64-bit register, and the result is compared against an end pointer before use. Sound, but the soundness lives outside the instruction. |
| **checked** | The sum carries its own overflow check (`ckadd` / `ckrange`). Sound locally. |
| **fixed** | Was neither. Listed in §3. |

The distinction between **width** and **checked** is the whole point of the
step. `docs/SECURITY.md` §3 asks for the `adds`/`b.cs` idiom on "all externally
derived arithmetic". Applying it to all ~120 sites would be churn: the width
argument is genuinely valid for most of them, and an unreachable branch on
every field read costs both instructions and reading time. What the width
argument is bad at is *staying* valid. It depends on facts several functions
away — that this length came from two octets, that this cursor started inside
the buffer — and nothing in the source says so. So the rule adopted here is:

> Use the checked idiom wherever the operand's width is not visible at the
> instruction, and wherever a value crosses a function boundary before being
> used as a length.

That is precisely the set §3.5 of the threat model flagged, and it is where all
four findings turned out to live.

---

## 2. The idioms

`src/defs.S` gains three macros, next to the existing `cb`:

```asm
ckadd  d, a, b, l          // d = a + b, branch to l on unsigned wrap
ckrange d, base, len, end, l  // d = base + len; branch on wrap OR past end
ckfits base, len, end, l   // the same as a predicate, discarding the sum
```

`ckrange` is the important one. "Does this field fit?" is two questions —
does `base + len` wrap, and is it past `end` — and asking only the second is
what makes a comparison against a pre-computed end pointer meaningless the
moment `len` stops being width-limited.

---

## 3. Findings

Four sites failed the audit. All four are fixed, and each has cases in the
Step 5 corpus (§5) that fail without the fix.

### 3.1 `h2_hpack_decode_int` — the 32-bit bound tested one bit

`src/hpack/h2_hpack_decode_int.S`. RFC 7541 §5.1 integers are bounded to 32
bits, and the decoder enforced that with:

```asm
add  x2, x2, x7                  // value += chunk
tbnz x2, #32, .Lhpack_int_error  // value overflowed 32 bits
```

A continuation octet at shift 28 contributes up to `0x7f << 28`, a little over
2^35. The accumulator can therefore leave the 32-bit range with **bit 32
clear** — `0x7f 80 80 80 80 20` decodes to 2^33 + 127 and was accepted.
48 of the 128 possible final octets escape this way: every one whose bit 4 is
clear, giving accepted values up to 29,796,335,743.

Not exploitable today — every consumer of the value (string length, table
index, dynamic size update) rejects a number that large for its own reasons —
but the routine's header promises a 32-bit bound and did not deliver one, and
"the caller happens to catch it" is not a bound. Now:

```asm
lsr  x3, x2, #32
cbnz x3, .Lhpack_int_error
```

### 3.2 `h2_hpack_decode_int` — continuation octets read past the block

Same file. The read loop was bounded only by the shift counter, so a prefix of
all ones at the tail of a header block made the decoder read up to five octets
past it before the shift bound fired. The decoder now takes the block end as
an argument and checks every octet against it before reading.

### 3.3 `h2_hpack_decode_string` — the length was checked after the read

`src/hpack/h2_hpack_decode_string.S`. This is the serious one.

`h2_hpack_decode_block` does verify that every representation fits inside the
block — but it can only do so *after* `h2_hpack_decode_field` has returned, and
by then two things have already happened on the paths that matter:

* **Huffman strings.** `h2_huffman_decode` is handed a byte count and expands
  until its 4096-byte output area fills. A 5-octet HEADERS payload declaring a
  4 GB Huffman string sent it walking off the end of `h2_frame_buf` —
  roughly 2.5 KB of adjacent memory, decoded into a header value. In a tree
  where key material sits in the same `.bss` neighbourhood as the record
  buffers (threat-model.md §9.3), an over-read that becomes a header value is
  the disclosure shape `docs/SECURITY.md` §3 warns about, even though the
  connection then dies with `COMPRESSION_ERROR` and never sends it.

* **Literal strings on the incremental-indexing path.**
  `h2_hpack_decode_field` hands the decoded name and value straight to
  `h2_hpack_dyn_insert`, which `memcpy`s both into the dynamic-table arena. A
  name length larger than the block was therefore copied out of adjacent
  memory first and rejected second.

The end of the block is now threaded down through
`decode_block` → `decode_field` → `decode_string` → `decode_int` /
`h2_huffman_decode`, and every length is checked with `ckrange` before a byte
is touched. `h2_hpack_decode_block`'s signature is unchanged, so
`h2_handle_headers` is untouched.

### 3.4 Two preconditions enforced by documentation only

Both were recorded by the Step 3 bounds suite as threat-model.md §9.9 and
pointed here.

* `hkdf_expand` assembles `[T(i-1)] || info || counter` in a 640-byte stack
  buffer, so its header requires `infolen <= 607`. Past that it overruns the
  frame — over the saved registers and the return address. The Step 3 suite
  trapped on the guard page at 1023. It now checks `infolen` and `okmlen`
  (`<= 8160`, the limit of the one-octet counter) and returns carry set with
  the output untouched.

* `hkdf_expand_label` builds an HkdfLabel in a 520-byte buffer, sized exactly
  for `label_len <= 249` and `context_len <= 255`. Past that it overruns — and
  the length octet it writes, `add w7, w21, #6` followed by `strb`, truncates
  on the way, so the peer would be handed a label nobody sent. Both are now
  checked, and the function propagates `hkdf_expand`'s carry.

* `x25519_fe_sqr_times` runs a do-while, so `count == 0` wraps to 2^64
  iterations and never returns. It now returns a copy of the input, which is
  what `a^(2^0)` means, and the copy reads all five limbs before writing any so
  it is safe to alias the way the rest of the field arithmetic is.

None of the three is reachable today: every caller passes a compile-time
constant. They are here because "no caller derives this from the wire" is a
property of the whole tree that a reader has to re-verify call site by call
site, and because the failure mode when it stops being true is a smashed frame
or a hang rather than a wrong answer.

The fifteen `hkdf_expand_label` call sites in the TLS key schedule are
deliberately **not** rewired to check the new carry flag. Each passes constant
lengths, so the flag cannot be set there, and threading an error return through
the key schedule for an unreachable condition is a large change to the most
delicate code in the tree in exchange for nothing. The flag exists so the
precondition is enforced at the point it belongs to and so the corpus can
assert it.

---

## 4. The audit

### 4.1 TLS record layer — **width**

`src/tls/record/parse.S`. The fragment length is two octets, bounded to
`2^14` or `2^14 + 256` by content type *before* it is added to anything, and
`add x7, x6, #TLS_RECORD_HEADER_LEN` then compared against the buffer end. A
16-bit value plus 5 in a 64-bit register; no reachable wrap.

### 4.2 ClientHello — **width**

`src/tls/handshake/client_hello.S` is a strict-bounds recursive-descent walk
with `x9` = cursor, `x10` = body end, `x13` = extensions end. Every field
computes `cursor + field_len` and compares it against the applicable end before
reading. Audited site by site:

| Field | Sum | Why it cannot wrap |
|---|---|---|
| `legacy_session_id` | `x9 + x14` | `x14` is one octet, rejected above 32 first |
| `cipher_suites` | `x9 + x14` | two octets; also required even and `>= 2` |
| `legacy_compression_methods` | `x9 + x14` | one octet |
| extensions block | `x9 + x14` | two octets, then required to *exactly* equal `x10` |
| per-extension | `x9 + x15` | two octets, compared against `x13` |
| `supported_versions` list | `w0 + 1` | one octet, in a w-register — 32-bit, so 255 + 1 cannot wrap |
| `supported_groups` / `key_share` / ALPN / SNI list | `w0 + 2` | two octets in a w-register: 65535 + 2 = 65537, which cannot equal the 16-bit `w15` it is compared against, so an over-long list is rejected rather than wrapped |
| key_share entry | `x8 + x6`, `x0 - x2` | entry length is `4 + key_len`, both bounded, compared against the remaining count before the cursor moves |
| ALPN name | `x4 + 1` | one octet |
| SNI hostname | `x5 + 3` | two octets |

The `w`-register cases are the ones worth naming: they are safe *because* the
arithmetic is 32-bit and the fields are 16-bit, which is the width argument in
its purest form and also its most fragile — a later change to `x`-registers
would not alter behaviour, and a later change of a field to 32 bits would.

### 4.3 HTTP/2 frame loop — **width**

`src/h2/h2_connection_loop.S`. The 24-bit payload length is validated by
`h2_validate_frame` against `H2C_MAX_RX_FRAME_SIZE` (2^14 by default, 2^24-1
absolute) before it is used. The loop then keeps `x21` (bytes buffered),
`x22` (offset) and `x23` (payload length) as *separate* cursors rather than
summing header and payload, and every step is a comparison
(`cmp x21, x23 / b.hs`) rather than an addition, so the `header + payload` sum
§3.5 of the threat model asked about does not exist in the form it feared.
`sub x2, x23, x21` is guarded by the `b.hs` above it, so it cannot go negative.

`h2_handle_headers` / `h2_handle_data` pad handling: pad length is one octet,
compared against the remaining payload with `b.hi` before the subtraction.
**width**.

### 4.4 HPACK — **fixed**, then **checked**

Covered in §3.1–§3.3. After the fix, the decode path is:

```
h2_hpack_decode_block(ptr, len)
    ckadd end = ptr + len
    -> h2_hpack_decode_field(ptr, end)
         -> h2_hpack_decode_int(ptr, N, end)      every octet < end
         -> h2_hpack_decode_string(ptr, end)
              ckrange data + len <= end           before the read
              -> h2_huffman_decode(data, len)     bound already established
```

`h2_hpack_dyn_insert`'s `name_len + value_len + 32` is now **width** rather
than unexamined: both operands are bounded by the block, which is bounded by
the frame size, so the sum is at most ~2^15 — but it reads as a bare `add`, so
it is the one place a future change to the string decoder would silently
un-bound. Noted rather than converted, because converting it would put a
`b.cs` on the path of every header field for a condition three orders of
magnitude away.

### 4.5 Record staging triples — **width**, and safe for a subtler reason

`src/transport/transport_read.S`. §3.2 of the threat model flagged the
`stage_len` / `stage_pos` pairs, where the bug shape is a stale `pos > len`
rather than an oversized field. The drain path is:

```asm
subs x22, x9, x10        // staged - consumed
b.gt .Ltr_plain_drain
```

`subs` and `b.gt` — signed. A stale `pos > len` makes `x22` negative, which
fails `b.gt` and falls into the branch that performs a fresh `read()` and
resets both counters. The state repairs itself rather than copying a negative
count reinterpreted as 2^64. That is correct, and it is correct because the
comparison is signed, which nothing at the instruction says. Recorded here so
that a future change from `b.gt` to `b.ne` is recognisable as the bug it would
be.

### 4.6 HTTP/1 request path — **width**

| Site | Verdict | Note |
|---|---|---|
| `child.S` read loop | width | bounded by `BUF_SIZE`; a full buffer without `\r\n\r\n` is a 431 |
| `parse_path.S` | width | 4096 cap → 414 before any copy |
| `decode_url.S` | width | in-place, output never longer than input; `%00` and truncated escapes rejected |
| `parse_range.S` | width | at most 18 digits reach `atoi_n`, so the value is `< 10^18`; `-1` is the sentinel and is unreachable from 18 digits |
| `atoi_n.S` | checked already | rejects 19+ digits outright (`cmp x1, #19 / b.hs`), which is the register-overflow guard in the form the tree already had |
| `http1_write_response.S` | width | header assembly accumulates into `x14` and compares against `header_buf_size` before each `memcpy`, using the existing `cb hi` idiom; every component is a bounded constant or an `itoa` of a bounded value |
| pipelined leftover shift | width | `request_total_len - request_header_len`, both produced by the same parse |

`parse_range` rejects `end < start`, so `h2_resolve_range` and its HTTP/1 twin
never produce an inverted window, and the `end - start + 1` content length
downstream cannot go negative. That rejection is load-bearing and now has a
line in this document saying so.

---

## 5. The corpus

Two new suites, in `tests/security/`, both built on
`overflow_common.h`. Every input is placed **flush against a guard page**, so
each case asserts two things at once: the routine returned its error, and it
did so without reading a byte outside the input it was given. A parser that
reads past the end and then complains is reported as `OUT OF BOUNDS` regardless
of what it would eventually have returned — which matters here, because three
of the four findings were exactly that shape.

| Suite | Cases | Covers |
|---|---|---|
| `test_overflow_hpack.c` | 36 | the 32-bit integer bound at every prefix width, the 48-value escape class, over-long encodings, truncated continuation runs, literal and Huffman lengths past the block, oversized dynamic-table inserts, out-of-range table indices and size updates, and every truncation of a valid two-field block |
| `test_overflow_crypto.c` | 30 | `hkdf_expand`'s info and output limits (including declared lengths of 2^32 and 2^64-1 against a 16-byte buffer), `hkdf_expand_label`'s label and context limits, and `x25519_fe_sqr_times` with a zero count |

Both suites pair every rejection case with the largest value that must still be
**accepted**. A check that rejects 608 and also rejects 607 has not made the
routine safer, and only the second half of the pair notices.

### Verified by sabotage

Each fix was reverted in turn and the corpus re-run.

| Sabotage | Result |
|---|---|
| `lsr x3, x2, #32 / cbnz` → `tbnz x2, #32` | 8 failures — every "above bit 32" case accepted |
| remove the per-octet end check in `decode_int` | 3 failures, all `OUT OF BOUNDS` |
| remove `ckrange` from `decode_string` | 9 failures, 6 of them `OUT OF BOUNDS` |
| remove `hkdf_expand`'s infolen check | 10 failures, 8 of them `OUT OF BOUNDS` |
| remove `hkdf_expand_label`'s label check | 3 failures, 2 of them `OUT OF BOUNDS` |
| remove `x25519_fe_sqr_times`'s zero guard | 2 failures, both `DID NOT TERMINATE within 10 seconds` |

The `OUT OF BOUNDS` rows are the ones that matter: they are the MMU, not the
test, reporting that the pre-Step-5 code really did read past the buffer it was
given.

---

## 6. Carried forward

1. **`h2_huffman_decode` still trusts its length argument.** It is now
   unreachable with a bad one — `h2_hpack_decode_string` is its only caller and
   checks first — but the routine itself has no bound of its own, so it is one
   new caller away from being the same defect again. A second `end` argument
   would close it. → Step 8, when the HTTP/2 fuzzer gives it a harness.
2. **`h2_hpack_dyn_insert`'s entry-size sum reads as unbounded** (§4.4).
   Safe by width today, and the width comes from a bound established two
   functions away.
3. **The width argument is not machine-checkable.** Every **width** verdict in
   §4 is a human reading two functions and concluding the operands are narrow.
   Steps 6–8 fuzz those paths, which is the empirical half of the same
   question, but nothing in the build re-derives §4 when a field changes size.
4. **`h2_resolve_range` accepts `start > end` if it is ever reached with one.**
   `parse_range` and `h2_parse_range` both reject inverted ranges, so it never
   is; the resolver itself has no such check and would produce a window whose
   length underflows. → Step 8.
