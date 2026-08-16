# 08 — Precompute more of the response at build time

**Workload-specific.** This exploits what makes `sarm` unusual: it serves a
small, fixed, known-at-build-time set of files.

## Context

`sarm` already precomputes aggressively — `embed_www.sh` embeds the assets and
pre-compresses them, `certs/embed_cert.sh` embeds the certificate. The response
path has not received the same treatment.

Two concrete findings in the current code:

### Response headers are rebuilt per request

`src/h2/h2_write_headers.S` constructs headers at runtime: multiple `bl itoa`
calls to render integers as decimal strings, interleaved with `memcpy` appends
(lines 84–198). For a fixed set of files whose sizes, content types and
encodings are known at build time, most of that output is **the same bytes
every time**.

### The asset lookup is not using its own index

`src/file/lookup_embedded.S` documents a sorted table for binary search but
notes it "currently uses a DEBUG linear-scan fallback". A whole FNV-1a hash
lookup mechanism exists unused alongside it. This has its own brief —
`prompts/10-embedded-lookup.md`.

## Objective

Move per-request work to build time wherever the result is fixed, reducing the
response path toward: match path → copy precomputed bytes → encrypt → write.

## Candidate work, in rough value order

Let prompt 00's profile decide what is actually worth doing — the request path
may be small next to the handshake.

1. **The asset lookup is covered by its own brief** — see
   `prompts/10-embedded-lookup.md`. It is independent of the rest of this
   prompt and can run separately.
2. **Precompute per-asset response headers.** For each embedded file, generate
   at build time: content-length as a string, content-type, content-encoding,
   and any other fixed header bytes. Extend `embed_www.sh` to emit them
   alongside the file data. Removes the `itoa` calls and most appends.
3. **Precompute the HPACK encoding.** HTTP/2 responses carry HPACK-encoded
   headers. For fixed header sets the encoded bytes are fixed — encode them at
   build time and emit the byte sequence. Removes per-response HPACK encoding
   entirely for the common case.
4. **Precompute whole frames.** Go further: emit the complete HEADERS frame
   (and the DATA frame header) per asset, so serving a request becomes a copy
   of a precomputed block plus the body. Note the frame header carries a
   stream ID that varies per request — patch just those bytes rather than
   rebuilding the frame.
5. **Reduce copies on the send path.** Trace how response bytes travel from the
   embedded table to the socket. If they are copied into a staging buffer and
   then again during record encryption, consider encrypting directly from the
   embedded data into the output buffer. Watch for aliasing and for the
   in-place constraints of AES-GCM.

## Constraints

- **Correctness of protocol behaviour is not negotiable.** Precomputed headers
  must still be correct for conditional requests, range requests
  (`h2_resolve_range`, `parse_range`), HEAD requests, and error responses.
  Anything varying per request (stream ID, ranges, dates if present) must stay
  dynamic — identify these before precomputing anything.
- **Do not break the dynamic path.** Precomputation is a fast path; the general
  path must still work for anything not precomputed.
- **Build-time generation must be reproducible** and driven from the same
  source as the assets. Extending `embed_www.sh` is preferred over adding a
  second generator that can drift out of sync.
- **Binary size.** Precomputed frames add read-only data. Report the delta —
  for a small self-contained server this is a real trade.
- **HPACK dynamic table interactions.** If the encoder uses the dynamic table,
  precomputed encodings must remain valid regardless of connection state.
  Static-table-only encodings are safe; dynamic-table references are not. Check
  `src/hpack/dynamic_table/` before precomputing anything that could reference
  it.

## Testing

- `tests/test_files.sh` — asset serving, including every embedded file.
- `tests/test_protocols.sh` and `tests/h2_browser_sim.py` — real HTTP/2
  conversations, including HPACK decoding by an independent implementation.
- `tests/test_security.sh` — path traversal and malformed request handling must
  be unaffected.
- Range and HEAD requests specifically, since those are the cases most likely
  to be broken by a precomputed-header fast path.
- Byte-compare responses before and after for every embedded asset. They should
  be identical apart from anything legitimately per-request.

## Acceptance criteria

- Every embedded asset serves byte-identical responses to the current
  implementation, except for legitimately varying fields.
- Measured reduction in per-request CPU time beyond prompt 02's noise floor,
  or an explicit finding that the request path is too small to matter for this
  workload — which is a valid and useful result.
- Binary size delta reported.
