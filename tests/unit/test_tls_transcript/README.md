# TLS Handshake Transcript Test Suite

Unit tests for the TLS 1.3 handshake transcript (RFC 8446 §4.4.1), split
to mirror `src/tls/transcript/*.S` — 39 tests total, one self-contained
binary per module (same pattern as `test_tls_record/`).

## Files

- **common.h** — Shared asm entry points, handshake-type constants, the
  `SHA256_CTX_*` layout contract, an independent C reference SHA-256
  (FIPS 180-4, same one `test_sha256.c` uses), transcript helpers
  (`HsMsg`, `build_wire`, `check_transcript`), and the known-answer
  vectors (`KAT_*`, computed with `python3 hashlib`)
- **init.c** — Tests + `main()` for `tls_transcript_init`: the
  `tls_transcript_ctx` layout contract, that init seeds the FIPS IV and
  zeroes the counters, and that a second init discards a previous
  transcript
- **add.c** — Tests + `main()` for `tls_transcript_add`: known TLS
  transcript sequences against externally computed SHA-256 values
  and that message ordering changes the hash
- **hash.c** — Tests + `main()` for `tls_transcript_hash`: every length
  0..300 at the SHA-256 padding boundaries cross-checked against the
  independent C reference, and the snapshot semantics (repeatable,
  non-destructive to the running transcript)

Each `.c` file is a standalone test binary: test functions are `static`
and `main()` calls them and finishes with `test_summary()`, so each
module gets its own line in `make test` output.

## Test Coverage

All 39 tests originally in `test_tls_transcript.c` were verified
byte-for-byte identical against the split files (same function bodies,
same helpers/vectors) before that file was removed.

| Suite | Tests | Coverage |
|-------|-------|----------|
| tls_transcript_init | 12 | `tls_transcript_ctx` layout, FIPS IV seeding, re-init discards prior state |
| tls_transcript_add | 9 | KAT vectors (header synthesis, uint24 length, multi-message handshake), ordering sensitivity |
| tls_transcript_hash | 18 | Boundary-length cross-checks (14 single + 1 multi-message) vs. C reference, snapshot repeatability/non-destructiveness |
| **Total** | **39** | Full RFC 8446 §4.4.1 compliance |

## Build Integration

`tests/unit/Makefile` has one pattern rule that builds any
`test_tls_transcript_<name>` binary from `test_tls_transcript/<name>.c`:

```makefile
$(OBJ_DIR)/test_tls_transcript_%: test_tls_transcript/%.c $(TLS_TRANSCRIPT_COMMON) $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@
```

## Running Tests

```bash
make -C tests/unit test                    # build and run every suite
./tests/unit/_obj/test_tls_transcript_add   # run one suite directly
```

Exit code 0 = all tests passed; nonzero = failures.
