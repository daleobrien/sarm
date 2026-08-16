# HTTP/2 diagnosis — requests not loading in Safari

Investigated from a WebKit HAR of a page load against `https://localhost:8080/`,
in which `/`, `/assets/index-pzx_VsSR.css` and `/logo.png` completed while
`/assets/index-Q2Xld2VX.js` (77 KB gzipped) never did.

Reproduced with a raw HTTP/2 client that mimics browser frame patterns, added
as [`tests/h2_browser_sim.py`](tests/h2_browser_sim.py). `curl` and `nghttp`
both hide these bugs — they grant multi-megabyte flow-control windows up front
and do not reuse a connection hard enough to wrap the stream table.

```bash
./sarm 8443 d & ./tests/h2_browser_sim.py all
```

## 1. `SETTINGS_INITIAL_WINDOW_SIZE` is never applied to already-open streams

**Scenario:** `settings-resize` — **Confirmed — fixed**

RFC 9113 §6.9.2 requires that when the peer changes
`SETTINGS_INITIAL_WINDOW_SIZE` mid-connection, the send window of *every
already-open stream* is adjusted by the difference. The new value is not just
for streams opened later.

`src/h2/h2_handle_settings.S:98` (`.Lh2_st_initial_window_size`) stores the
value into `H2C_SETTINGS_INITIAL_WINDOW_SIZE` and nothing else. The only reader
is `src/h2/h2_stream_create.S:74`, at stream-creation time. A stream already in
flight keeps whatever window it was created with — the 65535 default.

The scenario stalls at exactly 65535 bytes, with no GOAWAY and no error of any
kind; the connection simply sits until the 10 s `RECV_TIMEOUT` (`src/config.S:24`)
closes it:

```
requesting the large asset on the default 65535 stream window
65535 bytes in before the window ran out
raising SETTINGS_INITIAL_WINDOW_SIZE to 1048576
  stream   1  /assets/index-Q2Xld2VX.js        65535 bytes  STALLED
```

**This matches the HAR's signature.** Everything under 64 KB completes; the
77 KB JS never finishes; the browser has no protocol error to report. It also
explains the two connections in the HAR — the 10 s idle timeout drops the first
one, and Safari opens a second.

Caveat on confidence: a HAR records HTTP semantics, not frames, so it cannot be
proved from the HAR alone that Safari sends a mid-connection SETTINGS. This is
the only mechanism found that produces exactly this signature, and the code path
violates §6.9.2 regardless.

**Fix.** `.Lh2_st_initial_window_size` now walks `h2_streams` and shifts every
non-CLOSED entry's `H2S_WINDOW` by the difference between the old value and the
new one, failing the connection with FLOW_CONTROL_ERROR if that would push a
window past 2^31-1. A reduction can legally drive a window negative, so
`h2_write_body` clamps a negative stream window to zero credit instead of
reading it as a huge unsigned number.

## 2. A `WINDOW_UPDATE` for a recently-closed stream kills the connection

**Scenarios:** `reload`, `late-wu` — **Confirmed — fixed**

This is the "won't stream more than a few pages" bug from commit `19a6c11`. A
browser reuses one connection across navigations, so stream ids climb without
bound. `reload` dies on page 6, exactly as the stream count crosses the
32-entry table:

```
page 5 (streams up to 59): ok
GOAWAY last_stream=71 error=1 (PROTOCOL_ERROR)
page 6 (streams up to 71): FAILED
connection died after 6 page load(s)
```

Two things combine:

- **`src/h2/h2_stream_create.S:49`** — the free-slot scan never breaks early, so
  `x6` keeps being overwritten and ends up holding the *last* free slot. The
  table therefore fills backwards, from slot 31 down to slot 0.
- **`src/h2/h2_stream_create.S:67`** — recycling takes the *first* CLOSED slot,
  scanning from slot 0. After a backwards fill, that is the **most recently
  completed** stream. So the 33rd stream evicts the stream that just finished —
  precisely the one whose `WINDOW_UPDATE` is still in flight.

`src/h2/h2_handle_window_update.S:65` then cannot find the entry, treats the id
as a never-opened idle stream, and returns `PROTOCOL_ERROR`, which
`h2_connection_loop` answers with GOAWAY and a close.

RFC 9113 §5.1 requires a `WINDOW_UPDATE` arriving for a stream in the *closed*
state to be ignored — the peer may well have had it in flight when we sent
END_STREAM. Only a genuinely idle stream is a `PROTOCOL_ERROR`.
`H2C_LAST_STREAM_ID` already holds what is needed to tell the two apart: an id
at or below the high-water mark is closed, not idle.

**Fix.** Three changes. `h2_stream_create` keeps the *lowest* free slot rather
than the last one seen, so the table fills forwards and slot order tracks age.
Recycling then picks the CLOSED entry with the *smallest stream id* — the oldest
finished stream — rather than the first one in table order. And
`h2_handle_window_update` no longer treats "absent from the table" as "idle": an
id at or below `H2C_LAST_STREAM_ID` is a stream that has been recycled away, so
the update is ignored per §5.1; only an id above the mark is a PROTOCOL_ERROR.

`late-wu` isolates the mechanism — after 40 streams, a late update for stream 1
is fine (its slot, at the top of the table, has not been reused), while one for
stream 77 or 79 kills the connection:

```
opened and completed 40 streams (ids 1..79)
now sending late WINDOW_UPDATEs for closed streams [77, 79, 1]
GOAWAY last_stream=79 error=1 (PROTOCOL_ERROR)
```

**HPACK ruled out.** The dynamic table wraps at about the same point in the
page load, so it was a plausible alternative. `reload --no-indexing` keeps the
server's dynamic table empty and fails identically, on the same page.

## Smaller issues noted, not chased

- **`src/h2/h2_write_body.S:145`** — the flow-control wait loop reads frames
  into `buf`, which is also the connection loop's buffer, clobbering any
  unconsumed bytes the loop still holds in `x21`/`x22`. Latent over TLS
  (`src/sarm/main.S:346` enters the loop with `n = 0`, so leftovers live in the
  TLS stage buffer instead), but live for cleartext h2c, where `src/sarm/child.S`
  passes its buffered bytes through.
- **`src/h2/h2_handle_settings.S`** — settings were stored with `str w7` into
  8-byte fields. Harmless for most, but `H2C_SETTINGS_MAX_HEADER_LIST_SIZE` is
  initialised to a full 64-bit `-1` in `h2_connection_loop`, so a client's value
  left a stale `0xFFFFFFFF` in the upper half. Fixed at the same time — every
  setting now stores the zero-extended 64-bit value.

## About the simulator

`tests/h2_browser_sim.py` is dependency-free — stdlib `ssl`/`socket` plus its
own frame writer and encode-side HPACK. Scenarios: `page-load`, `burst`,
`no-credit`, `reload`, `late-wu`, `settings-resize`, or `all`.

Knobs that mattered for bisecting: `--paths` (drop the large asset to remove the
flow-control stall and its recursion), `--no-indexing` (keep the server's HPACK
dynamic table empty), `--reloads`, `--streams`, `--conn-window`, `-v`.

It exits non-zero on any incomplete stream. With the fixes in place every
scenario passes, including `reload --reloads 40` (streams up to 479) and
`late-wu --streams 200`. It is still not wired into `make test`, which would
need start/stop logic for a server on its own port the way the shell suites
have.
