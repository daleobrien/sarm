# HTTP/1 keep-alive: the close rule

sarm serves only GET, HEAD and OPTIONS, never reads a request body, and
already emits a correct `Content-Length` on every response. That makes
response framing — normally the hard part of keep-alive — already right.
The one thing keep-alive needs and sarm does not have is a way to know
where a request body would begin, since a body left unread in the socket
would be misparsed as the start of the next request line.

## The rule

**Respond and close** — do not keep the connection alive — when any of:

- the method is not GET, HEAD or OPTIONS (including the 501 and 418 paths);
- the request carries `Content-Length` or `Transfer-Encoding`;
- the request is HTTP/1.0 without `Connection: keep-alive`;
- the request carries `Connection: close`;
- the response is an error that means the parser lost sync (400, 408, 413,
  431, 500);
- the per-connection request budget is exhausted (Plan.md Step 6).

**Keep alive** otherwise.

## Where it lives

`http1_should_keep_alive` (`src/http1/keep_alive.S`) implements everything
above except the request-budget clause, which belongs to the connection loop
built in Step 6, not to this predicate. It is a pure function: given the raw
request buffer, the request length, the parsed method, and the response
status about to be sent, it returns a keep-alive/close boolean. It touches no
per-connection state and calls nothing that does.

With one exception, found by the Step 8 fuzzing
(`docs/security/fuzzing.md` §17, `threat-model.md` observation 17): the three
`get_header_field` lookups below can *not return at all*. That routine answers
a header name which is a strict prefix of the one being searched for —
`Content-Lengths:` while looking for `Content-Length` — by branching to
`reply_status(400)`, and this predicate is called from the middle of
`http1_write_response`. Such a request therefore gets a 400 in place of
whatever was being encoded. The client still sees exactly one response, since
the decision is made before the `writev`, and the 400's own encode does not
escape again **because the status check runs before the header lookups** —
400 is in the close list, so the second call returns without reaching
`get_header_field`. That ordering is not cosmetic: swap the two blocks and the
same request loops forever.

Two of the conditions only need to *detect*, never parse:

- **Content-Length / Transfer-Encoding** — their presence is checked with
  `get_header_field`; sarm never reads the value, because it never reads a
  request body regardless of what the value says.
- **HTTP version** — only whether the request line ends in `HTTP/1.0` is
  checked, by comparing the last 8 bytes of the request line. Anything else
  (including a missing or malformed version token) is treated as HTTP/1.1,
  matching the version sarm already answers with unconditionally.

`Connection` is the one header whose value is inspected: `close` and
`keep-alive` are matched case-insensitively, and the byte immediately
following the match must be a token boundary (`\r`, space, tab, `;` or `,`)
so a header like `Connection: keep-alived` is not mistaken for `keep-alive`.
Anything else in `Connection` — absent, unrecognized, or a bare boundary
mismatch — is treated as absent.

## The request budget

`HTTP1_KEEPALIVE_BUDGET` (`src/config.S`, default 100) bounds how many
requests one connection may serve before sarm sends `Connection: close` and
ends it — see "The ceiling" in `Plan.md`: keep-alive trades fork cost for
process occupancy, and this is the knob that bounds the trade. `child.S`
initializes the per-connection `request_budget` global to this value and
decrements it each time a request header is found; `http1_write_response`
ANDs `request_budget > 0` into `http1_should_keep_alive`'s result before
picking the `Connection:` header, so budget exhaustion is indistinguishable
from any other close reason as far as the wire is concerned.

## Status: shipped (Steps 2-6)

`http1_should_keep_alive` (unit-tested in isolation,
`tests/unit/test_keep_alive.c`) and `http1_reset_request` (unit-tested in
isolation, `tests/unit/test_reset_request.c`) are both wired into the
request path:

- `http1_write_response` calls the predicate, ANDs in the request budget,
  stores the combined result in `keep_alive_decision`, and picks
  `Connection: keep-alive` or `close` accordingly.
- Every HTTP/1 response path (`get`, `head`, `reply_status`) tail-branches
  to `http1_keepalive_continue` (`src/sarm/child.S`) instead of always
  going to `child_end`. On close, behavior is unchanged from before this
  work. On keep-alive, it calls `http1_reset_request`, shifts any leftover
  pipelined bytes in `buf` to the front (using `request_header_len` and the
  new `request_total_len` global), and resumes the connection at
  `Lcheck_leftover` — the same entry point a fresh connection uses. That
  entry point checks for an already-complete next request in the leftover
  bytes *before* blocking in `read()`, so a pipelined second request is
  served without waiting on the network.

Storing the decision in `keep_alive_decision` rather than recomputing it in
the trampoline is deliberate: the header the client receives and the
loop-or-close behavior that follows are the same read of the same value, so
they cannot disagree.

Verified with `tests/test_keepalive.sh` (part of `make test`): pipelined
and split-write requests produce byte-for-byte identical output; the
request budget closes exactly the connection's 100th request; and
concurrent connections each issuing several sequential requests all
complete correctly. Measured results are in `docs/MULTICORE-BASELINE.md`
("Phase 1, Step 6") — HTTP/1 moved from 16 433 to ~167 822 req/s, a 10.2×
improvement, landing in the same regime as HTTP/2.

Outstanding for this phase: Step 7 onward (Phase 2, syscall reduction) and
Phase 4/5 (validation, documentation) per `Plan.md`.
