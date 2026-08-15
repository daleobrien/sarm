# TLS Record Layer Test Suite

Unit tests for the TLS 1.3 record layer (RFC 8446 §5), split to mirror
`src/tls/record/*.S` — 773 tests total, one self-contained binary per
module (same pattern as the `test_h2_*` suites).

## Files

- **common.h** — Shared constants, asm entry points, RFC 8448 test vectors, and helper functions (`rec_parse`, `rec_write`, `rec_encrypt`, `rec_decrypt`, `build_raw_record`, `fill_ascending`)
- **parse.c** — Tests + `main()` for `tls_record_parse` (RFC parsing with bounds checking)
- **write.c** — Tests + `main()` for `tls_record_write` (plaintext record generation)
- **nonce.c** — Tests + `main()` for `tls_record_nonce` (per-record nonce construction)
- **encrypt.c** — Tests + `main()` for `tls_record_encrypt` (AES-128-GCM sealing)
- **decrypt.c** — Tests + `main()` for `tls_record_decrypt` (AEAD opening, roundtrips, error paths, padding removal)
- **seq.c** — Tests + `main()` for `tls_record_next_client_seq` / `tls_record_next_server_seq` (sequence counters)

Each `.c` file is a standalone test binary: test functions are `static`
and `main()` calls them and finishes with `test_summary()`, so each
module gets its own line in `make test` output.

## Test Coverage

All 773 tests originally in `test_tls_record.c` were verified byte-for-byte
identical against the split files (same `ASSERT_EQ` count, same test
bodies) before that file was removed:

| Suite | Tests | Coverage |
|-------|-------|----------|
| tls_record_parse | 45 | RFC 8448 records, type/version/length validation, bounds checking |
| tls_record_write | 22 | Plaintext record generation, header encoding, error cases |
| tls_record_nonce | 7 | Nonce construction (IV XOR sequence), edge cases |
| tls_record_encrypt | 7 | RFC 8448 vectors, key/seq/content type combinations |
| tls_record_decrypt | 680 | RFC 8448 vectors, roundtrips, error paths, tag verification, padding |
| tls_record_seq | 12 | Sequence counter independence and increment |
| **Total** | **773** | Full RFC 8446 §5 compliance |

## Build Integration

`tests/unit/Makefile` has one pattern rule that builds any
`test_tls_record_<name>` binary from `test_tls_record/<name>.c`:

```makefile
$(OBJ_DIR)/test_tls_record_%: test_tls_record/%.c $(TLS_RECORD_COMMON) $(HARNESS) $(tls_objs) $(crypto_objs) $(util_objs) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $< $(tls_objs) $(crypto_objs) $(util_objs) $(LDFLAGS) -o $@
```

## Running Tests

```bash
make -C tests/unit test                      # build and run every suite
./tests/unit/_obj/test_tls_record_decrypt     # run one suite directly
```

Exit code 0 = all tests passed; nonzero = failures.
