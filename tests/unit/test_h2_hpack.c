// Unit tests for src/hpack/ — Stage 7: minimal HPACK.
// The RFC 7541 Appendix A static table (7.1), integer decoding §5.1
// (7.2), plain-string decoding §5.2 (7.3), indexed header fields §6.1
// (7.4), literal header fields §6.2.2/§6.2.3 (7.5), Huffman decoding
// (Appendix B), and the real bounded dynamic table (7.6, hpack/dynamic_table/):
// insertion, FIFO eviction, resize, and the combined static+dynamic
// index space via h2_hpack_table_lookup.

#include "test_h2_common.h"

static void test_h2_hpack_static_table(void) {
	TEST_SUITE("h2_hpack_static_lookup — RFC 7541 Appendix A (7.1)");

	ASSERT_EQ("h2_hpack_field_t layout matches H2_HPACK_FIELD_SIZE",
	          H2_HPACK_FIELD_SIZE, (int64_t)sizeof(h2_hpack_field_t));

	const uint8_t *name, *value;
	int64_t name_len, value_len, carry;

	// index 2: :method = GET — the canonical indexed request header
	name = h2_hpack_static_lookup_wrapper(2, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 2 → :method GET", carry, name, name_len, value, value_len,
	            ":method", "GET");

	// index 5: :path = /index.html
	name = h2_hpack_static_lookup_wrapper(5, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 5 → :path /index.html", carry, name, name_len,
	            value, value_len, ":path", "/index.html");

	// index 1: :authority, empty value
	name = h2_hpack_static_lookup_wrapper(1, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 1 → :authority (empty)", carry, name, name_len,
	            value, value_len, ":authority", "");

	// index 16: accept-encoding = gzip, deflate
	name = h2_hpack_static_lookup_wrapper(16, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 16 → accept-encoding gzip, deflate", carry, name,
	            name_len, value, value_len, "accept-encoding", "gzip, deflate");

	// index 31: content-type, empty value
	name = h2_hpack_static_lookup_wrapper(31, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 31 → content-type (empty)", carry, name, name_len,
	            value, value_len, "content-type", "");

	// the last entry of the table
	name = h2_hpack_static_lookup_wrapper(61, &name_len, &value, &value_len,
	                                      &carry);
	check_field("index 61 → www-authenticate (empty)", carry, name, name_len,
	            value, value_len, "www-authenticate", "");

	// index 0 and indices past the static table are decoding errors
	const uint8_t *v;
	int64_t rc = (int64_t)(uintptr_t)h2_hpack_static_lookup_wrapper(
	    0, &name_len, &v, &value_len, &carry);
	check_field_error("index 0 rejected", (const uint8_t *)rc, carry);
	rc = (int64_t)(uintptr_t)h2_hpack_static_lookup_wrapper(
	    62, &name_len, &v, &value_len, &carry);
	check_field_error("index 62 rejected (static table only — h2_hpack_table_lookup handles the dynamic range)",
	                  (const uint8_t *)rc, carry);
}

static void test_h2_hpack_int(void) {
	TEST_SUITE("h2_hpack_decode_int — RFC 7541 §5.1 (7.2)");

	// the Stage 7 required values, all with a 7-bit prefix. The
	// continuation octets carry 7 bits each, least significant group
	// first (§5.1); a prefix of all ones always means "more octets
	// follow", so 2^N - 1 itself needs one more octet.
	check_int("0 decodes",   (const uint8_t *)"\x00", 7, 0, 1);
	check_int("1 decodes",   (const uint8_t *)"\x01", 7, 1, 1);
	check_int("10 decodes",  (const uint8_t *)"\x0a", 7, 10, 1);
	check_int("127 decodes", (const uint8_t *)"\x7f\x00", 7, 127, 2);
	check_int("128 decodes", (const uint8_t *)"\x7f\x01", 7, 128, 2);
	check_int("255 decodes", (const uint8_t *)"\x7f\x80\x01", 7, 255, 3);
	check_int("4096 decodes", (const uint8_t *)"\x7f\x81\x1f", 7, 4096, 3);

	// other prefix widths: the 4-bit literal index (15, 16, 30), the
	// 5-bit size update (31, 32) and the 6-bit incremental index (63, 64)
	check_int("N=4: 15",   (const uint8_t *)"\x0f\x00", 4, 15, 2);
	check_int("N=4: 16",   (const uint8_t *)"\x0f\x01", 4, 16, 2);
	check_int("N=4: 30",   (const uint8_t *)"\x0f\x0f", 4, 30, 2);
	check_int("N=5: 31",   (const uint8_t *)"\x1f\x00", 5, 31, 2);
	check_int("N=5: 32",   (const uint8_t *)"\x1f\x01", 5, 32, 2);
	check_int("N=6: 63",   (const uint8_t *)"\x3f\x00", 6, 63, 2);
	check_int("N=6: 64",   (const uint8_t *)"\x3f\x01", 6, 64, 2);

	// encode → decode round trips across prefix widths, including the
	// 32-bit ceiling, so the encoder and decoder agree on §5.1
	static const uint32_t values[] = {
		0, 1, 10, 62, 63, 64, 126, 127, 128, 255, 256, 1024, 4096,
		65535, 0xffffffffu,
	};
	static const int prefixes[] = { 4, 5, 6, 7 };
	uint8_t enc[8];
	for (unsigned vi = 0; vi < sizeof(values) / sizeof(values[0]); vi++) {
		for (unsigned pi = 0; pi < sizeof(prefixes) / sizeof(prefixes[0]); pi++) {
			int n = put_hpack_int(enc, values[vi], prefixes[pi]);
			int64_t consumed, carry;
			int64_t got = h2_hpack_decode_int_wrapper(enc, prefixes[pi],
			                                          &consumed, &carry);
			if (carry != 0) {
				_FAIL("roundtrip value %u prefix %d — decode failed",
				      (unsigned)values[vi], prefixes[pi]);
			} else if (got != (int64_t)values[vi]) {
				_FAIL("roundtrip value %u prefix %d — got %lld",
				      (unsigned)values[vi], prefixes[pi], (long long)got);
			} else if (consumed != n) {
				_FAIL("roundtrip value %u prefix %d — consumed %lld != %d",
				      (unsigned)values[vi], prefixes[pi],
				      (long long)consumed, n);
			} else {
				_PASS("roundtrip");
			}
		}
	}

	// a value that cannot fit in 32 bits is a decoding error — and the
	// decoder must stop reading, not walk off into memory
	int64_t consumed, carry;
	static const uint8_t overflow[] = { 0x7f, 0xff, 0xff, 0xff, 0xff,
	                                    0xff, 0xff, 0xff, 0xff, 0x01 };
	int64_t rc = h2_hpack_decode_int_wrapper(overflow, 7, &consumed, &carry);
	ASSERT_EQ("32-bit overflow rejected", H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
}

static void test_h2_hpack_string(void) {
	TEST_SUITE("h2_hpack_decode_string — RFC 7541 §5.2 (7.3)");

	int64_t len, consumed, carry;
	const uint8_t *s;

	// the Stage 7 required strings
	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x03" "GET",
	                                   &len, &consumed, &carry);
	check_string("\"GET\" decodes", carry, s, len, "GET", consumed, 4);

	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x0b" "/index.html",
	                                   &len, &consumed, &carry);
	check_string("\"/index.html\" decodes", carry, s, len, "/index.html",
	             consumed, 12);

	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x09" "text/html",
	                                   &len, &consumed, &carry);
	check_string("\"text/html\" decodes", carry, s, len, "text/html",
	             consumed, 10);

	// empty string
	s = h2_hpack_decode_string_wrapper((const uint8_t *)"\x00",
	                                   &len, &consumed, &carry);
	check_string("empty string decodes", carry, s, len, "", consumed, 1);

	// multi-octet lengths: 130 = 127 + 3, 1000 = 127 + 105 + 6*128
	uint8_t s130[133];
	s130[0] = 0x7f; s130[1] = 0x03;
	for (int i = 0; i < 130; i++) s130[2 + i] = (uint8_t)('a' + (i % 26));
	s = h2_hpack_decode_string_wrapper(s130, &len, &consumed, &carry);
	ASSERT_EQ("130-byte length decodes", 130, len);
	ASSERT_EQ("130-byte string consumed", 132, consumed);
	ASSERT_EQ("130-byte string carry clear", 0, carry);
	ASSERT_TRUE("130-byte string data matches",
	            memcmp(s, s130 + 2, 130) == 0);

	uint8_t s1000[1003];
	s1000[0] = 0x7f; s1000[1] = 0xe9; s1000[2] = 0x06;
	for (int i = 0; i < 1000; i++) s1000[3 + i] = (uint8_t)('a' + (i % 26));
	s = h2_hpack_decode_string_wrapper(s1000, &len, &consumed, &carry);
	ASSERT_EQ("1000-byte length decodes", 1000, len);
	ASSERT_EQ("1000-byte string consumed", 1003, consumed);
	ASSERT_EQ("1000-byte string carry clear", 0, carry);
	ASSERT_TRUE("1000-byte string data matches",
	            memcmp(s, s1000 + 3, 1000) == 0);

	// Huffman-coded strings (§5.2) decode through h2_huffman_decode —
	// "www.example.com" is the canonical RFC 7541 Appendix C.4.1 vector
	static const uint8_t h1[] = { 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
	                              0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
	s = h2_hpack_decode_string_wrapper(h1, &len, &consumed, &carry);
	check_string("Huffman \"www.example.com\" decodes", carry, s, len,
	             "www.example.com", consumed, (int64_t)sizeof(h1));
}

static void test_h2_huffman(void) {
	TEST_SUITE("h2_huffman_decode — RFC 7541 Appendix B Huffman code");

	int64_t len, consumed, carry;
	const uint8_t *s;

	// The routine's own input bound (docs/SECURITY.md §3.5,
	// carried-forward item 1). h2_hpack_decode_string checks this too,
	// but h2_huffman_decode no longer depends on it having done so:
	// called directly with an end short of the encoded run, it must
	// refuse before reading a byte rather than expand off the end.
	static const uint8_t hb[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
	                              0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
	s = h2_huffman_decode_bounded(hb, (int64_t)sizeof(hb),
	                              hb + sizeof(hb) - 1, &len, &consumed, &carry);
	ASSERT_TRUE("encoded run one past the end is refused", carry == 1);
	s = h2_huffman_decode_bounded(hb, (int64_t)sizeof(hb), hb,
	                              &len, &consumed, &carry);
	ASSERT_TRUE("zero-length block with a non-zero run is refused", carry == 1);
	// The wrapping case (len = INT64_MAX) is deliberately *not* here:
	// without the bound it still reports carry set, having filled its
	// output area from ~2.5 KB of adjacent memory first, so this suite
	// cannot tell a refusal from the defect. It is in
	// tests/security/test_overflow_hpack.c, where the block ends at a
	// guard page and the difference is a fault.
	// ...and the exactly-fitting bound is still accepted
	s = h2_huffman_decode_bounded(hb, (int64_t)sizeof(hb), hb + sizeof(hb),
	                              &len, &consumed, &carry);
	check_string("a run that exactly fills the block is accepted", carry, s,
	             len, "www.example.com", consumed, (int64_t)sizeof(hb));

	// RFC 7541 Appendix C.4.1 — the canonical Huffman test vector
	static const uint8_t auth[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
	                                0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
	s = h2_huffman_decode_wrapper(auth, (int64_t)sizeof(auth), &len, &consumed,
	                              &carry);
	check_string("www.example.com", carry, s, len, "www.example.com", consumed,
	             (int64_t)sizeof(auth));

	// C.4.2 — no-cache
	static const uint8_t nc[] = { 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
	s = h2_huffman_decode_wrapper(nc, (int64_t)sizeof(nc), &len, &consumed,
	                              &carry);
	check_string("no-cache", carry, s, len, "no-cache", consumed,
	             (int64_t)sizeof(nc));

	// C.6.1 — private, 302
	static const uint8_t priv[] = { 0xae, 0xc3, 0x77, 0x1a, 0x4b };
	s = h2_huffman_decode_wrapper(priv, (int64_t)sizeof(priv), &len, &consumed,
	                              &carry);
	check_string("private", carry, s, len, "private", consumed,
	             (int64_t)sizeof(priv));

	static const uint8_t s302[] = { 0x64, 0x02 };
	s = h2_huffman_decode_wrapper(s302, (int64_t)sizeof(s302), &len, &consumed,
	                              &carry);
	check_string("302", carry, s, len, "302", consumed, (int64_t)sizeof(s302));

	// curl/8.7.1 — the user-agent captured from a real curl request
	static const uint8_t ua[] = { 0x25, 0xb6, 0x50, 0xc3, 0xcb, 0xba, 0xb8, 0x7f };
	s = h2_huffman_decode_wrapper(ua, (int64_t)sizeof(ua), &len, &consumed,
	                              &carry);
	check_string("curl/8.7.1", carry, s, len, "curl/8.7.1", consumed,
	             (int64_t)sizeof(ua));

	// 127.0.0.1:8100 — the :authority captured from a real curl request
	static const uint8_t ah[] = { 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70, 0xdc,
	                              0x78, 0x20, 0x07 };
	s = h2_huffman_decode_wrapper(ah, (int64_t)sizeof(ah), &len, &consumed,
	                              &carry);
	check_string("127.0.0.1:8100", carry, s, len, "127.0.0.1:8100", consumed,
	             (int64_t)sizeof(ah));

	// an empty Huffman string (encoded length 0)
	s = h2_huffman_decode_wrapper((const uint8_t *)"", 0, &len, &consumed,
	                              &carry);
	check_string("empty string", carry, s, len, "", consumed, 0);

	// two Huffman strings back-to-back (the header-block scenario): the
	// second decode appends after the first in h2_hpack_str_buf
	const uint8_t *first = h2_huffman_decode_wrapper(auth, (int64_t)sizeof(auth),
	                                                &len, &consumed, &carry);
	check_string("authority then", carry, s, len, "www.example.com", consumed,
	             (int64_t)sizeof(auth));
	s = h2_huffman_decode_wrapper(ua, (int64_t)sizeof(ua), &len, &consumed,
	                              &carry);
	check_string("then user-agent", carry, s, len, "curl/8.7.1", consumed,
	             (int64_t)sizeof(ua));
	// the first string is still intact at its original position
	ASSERT_TRUE("first string intact",
	            memcmp(first, "www.example.com", 15) == 0);

	// invalid padding — the leftover bits must be all ones (§5.2): after
	// "302" (16 bits, exact) an extra 0x00 byte leaves 000 padding
	static const uint8_t badpad[] = { 0x64, 0x02, 0x00 };
	s = h2_huffman_decode_wrapper(badpad, (int64_t)sizeof(badpad), &len,
	                              &consumed, &carry);
	ASSERT_EQ("bad padding rejected", 1, carry);
	ASSERT_EQ("bad padding error", H2_ERR_COMPRESSION_ERROR,
	          (int64_t)(uintptr_t)s);

	// the EOS symbol inside a string is a decoding error (§5.2)
	static const uint8_t eos[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	s = h2_huffman_decode_wrapper(eos, (int64_t)sizeof(eos), &len, &consumed,
	                              &carry);
	ASSERT_EQ("EOS symbol rejected", 1, carry);
}

static void test_h2_hpack_indexed(void) {
	TEST_SUITE("h2_hpack_decode_field — indexed (6.1 / 7.4)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	// 0x82 → index 2 → :method: GET — the canonical encoded request header
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x82", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x82 → :method GET", carry, name, name_len, value, value_len,
	            ":method", "GET");
	ASSERT_EQ("next advances one byte", 1, next - (const uint8_t *)"\x82");

	// 0x81 → index 1 → :authority with an empty value
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x81", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x81 → :authority (empty)", carry, name, name_len, value,
	            value_len, ":authority", "");

	// 0x87 → index 7 → :scheme: https
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x87", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field("0x87 → :scheme https", carry, name, name_len, value, value_len,
	            ":scheme", "https");

	// multi-octet index: 0xbf 0x07 → 127 + 7 = 134, beyond the static table
	static const uint8_t big_idx[] = { 0xbf, 0x07 };
	next = h2_hpack_decode_field_wrapper(big_idx, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("index 134 rejected", next, carry);

	// index 0 is never valid (§6.1)
	next = h2_hpack_decode_field_wrapper((const uint8_t *)"\x80", &name,
	                                     &name_len, &value, &value_len,
	                                     &carry);
	check_field_error("index 0 rejected", next, carry);
}

static void test_h2_hpack_literal(void) {
	TEST_SUITE("h2_hpack_decode_field — literal (6.2.2/6.2.3 / 7.5)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	// literal without indexing, indexed name: 0x04 + "/index.html" → :path
	static const uint8_t w1[] = { 0x04, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w1, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("0x04 + \"/index.html\" → :path", carry, name, name_len,
	            value, value_len, ":path", "/index.html");
	ASSERT_EQ("next at block end", 13, next - w1);

	// never indexed, indexed name: 0x14 → the same field
	static const uint8_t w2[] = { 0x14, 0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w2, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("0x14 + \"/index.html\" → :path (never indexed)", carry, name,
	            name_len, value, value_len, ":path", "/index.html");

	// literal without indexing, new name: the name string follows the 0x00
	static const uint8_t w3[] = { 0x00, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w3, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("new name :path, value /index.html", carry, name, name_len,
	            value, value_len, ":path", "/index.html");
	ASSERT_EQ("next at block end", 19, next - w3);

	// never indexed, new name: 0x10 → the same field
	static const uint8_t w4[] = { 0x10, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x0b, '/', 'i', 'n', 'd', 'e', 'x', '.',
	                              'h', 't', 'm', 'l' };
	next = h2_hpack_decode_field_wrapper(w4, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("new name :path (never indexed)", carry, name, name_len,
	            value, value_len, ":path", "/index.html");

	// an empty value string
	static const uint8_t w5[] = { 0x04, 0x00 };
	next = h2_hpack_decode_field_wrapper(w5, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field(":path with an empty value", carry, name, name_len, value,
	            value_len, ":path", "");
	ASSERT_EQ("next at block end", 2, next - w5);

	// a multi-octet name index: 0x0f 0x01 → index 16 (accept-encoding),
	// value "gzip, deflate" — exercises the multi-octet prefix path
	static const uint8_t w7[] = { 0x0f, 0x01, 0x0d, 'g', 'z', 'i', 'p', ',', ' ',
	                              'd', 'e', 'f', 'l', 'a', 't', 'e' };
	next = h2_hpack_decode_field_wrapper(w7, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("index 16 (accept-encoding) via 2-octet index", carry, name,
	            name_len, value, value_len, "accept-encoding", "gzip, deflate");
	ASSERT_EQ("next at block end", 16, next - w7);

	// a literal name index beyond the static table (62) → decoding error
	static const uint8_t w6[] = { 0x0f, 0x2f, 0x01, 'x' };
	next = h2_hpack_decode_field_wrapper(w6, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("name index 62 rejected", next, carry);
}

static void test_h2_hpack_dynamic_table(void) {
	TEST_SUITE("h2_hpack_decode_field — dynamic table (RFC 7541 §2.3.2, 7.6)");

	const uint8_t *next, *name, *value;
	int64_t name_len, value_len, carry;

	h2_hpack_dyn_reset_wrapper();

	// literal with incremental indexing (§6.2.1) is decoded AND stored —
	// our decoder now has a real bounded table, matching what a
	// compliant client's encoder assumes before it has even processed
	// our SETTINGS (curl encodes user-agent this way)
	static const uint8_t w1[] = { 0x41, 0x05, 'h', 'e', 'l', 'l', 'o' };
	next = h2_hpack_decode_field_wrapper(w1, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("incremental indexing (indexed name) decoded", carry, name,
	            name_len, value, value_len, ":authority", "hello");
	ASSERT_EQ("next at block end", 7, next - w1);

	// the entry just inserted is index 62 (newest, 1-based from the
	// dynamic table's own start)
	name = h2_hpack_table_lookup_wrapper(62, &name_len, &value, &value_len,
	                                     &carry);
	check_field("index 62 resolves the entry just inserted", carry, name,
	            name_len, value, value_len, ":authority", "hello");

	// incremental indexing with a new name — inserted as the newest entry
	static const uint8_t w2[] = { 0x40, 0x05, ':', 'p', 'a', 't', 'h',
	                              0x01, 'x' };
	next = h2_hpack_decode_field_wrapper(w2, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("incremental indexing (new name) decoded", carry, name,
	            name_len, value, value_len, ":path", "x");
	ASSERT_EQ("next at block end", 9, next - w2);

	// now index 62 is the newest (:path/x), 63 is the older (:authority/hello)
	name = h2_hpack_table_lookup_wrapper(62, &name_len, &value, &value_len,
	                                     &carry);
	check_field("index 62 is now :path/x (newest)", carry, name, name_len,
	            value, value_len, ":path", "x");
	name = h2_hpack_table_lookup_wrapper(63, &name_len, &value, &value_len,
	                                     &carry);
	check_field("index 63 is :authority/hello (pushed back)", carry, name,
	            name_len, value, value_len, ":authority", "hello");
	name = h2_hpack_table_lookup_wrapper(64, &name_len, &value, &value_len,
	                                     &carry);
	check_field_error("index 64 out of range — only 2 entries", name, carry);

	// a dynamic table size update of 0 is accepted as a no-op (§6.3) and
	// empties the table (§4.4)
	static const uint8_t w3[] = { 0x20, 0x82 };
	next = h2_hpack_decode_field_wrapper(w3, &name, &name_len, &value,
	                                     &value_len, &carry);
	ASSERT_EQ("size update 0 accepted", 0, carry);
	ASSERT_EQ("not a field — name is 0", 0, (int64_t)(uintptr_t)name);
	ASSERT_EQ("next skips the update", 1, next - w3);
	name = h2_hpack_table_lookup_wrapper(62, &name_len, &value, &value_len,
	                                     &carry);
	check_field_error("size update to 0 emptied the table", name, carry);

	// a size update restoring 4096 (our advertised maximum) is accepted —
	// insert again to confirm the table works after being resized back up
	static const uint8_t w5[] = { 0x3f, 0xe1, 0x1f }; // 31 + 97 + 31*128 = 4096
	next = h2_hpack_decode_field_wrapper(w5, &name, &name_len, &value,
	                                     &value_len, &carry);
	ASSERT_EQ("size update 4096 accepted (equals our max)", 0, carry);
	static const uint8_t w6[] = { 0x41, 0x03, 'f', 'o', 'o' };
	next = h2_hpack_decode_field_wrapper(w6, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field("insert after restoring the table works", carry, name,
	            name_len, value, value_len, ":authority", "foo");

	// a size update above our advertised maximum (4097 > 4096) is rejected
	static const uint8_t w7[] = { 0x3f, 0xe2, 0x1f }; // 31 + 98 + 31*128 = 4097
	next = h2_hpack_decode_field_wrapper(w7, &name, &name_len, &value,
	                                     &value_len, &carry);
	check_field_error("size update 4097 rejected — exceeds our max", next, carry);

	// an oversized entry (bigger than the whole table) empties it rather
	// than being stored (§4.4) — not an error
	h2_hpack_dyn_reset_wrapper();
	uint8_t huge_value[4100];
	for (int i = 0; i < 4100; i++) huge_value[i] = 'a';
	h2_hpack_dyn_insert_wrapper((const uint8_t *)"x", 1, huge_value, 4100);
	name = h2_hpack_table_lookup_wrapper(62, &name_len, &value, &value_len,
	                                     &carry);
	check_field_error("oversized entry not stored — table stays empty", name,
	                  carry);

	// eviction: fill the table near capacity, then insert one more and
	// confirm the oldest entry is gone while the newest survives
	h2_hpack_dyn_reset_wrapper();
	uint8_t fill_value[100];
	for (int i = 0; i < 100; i++) fill_value[i] = 'v';
	// each entry costs 1(name) + 100(value) + 32 = 133 bytes; ~30 entries
	// fill the 4096-byte table close to capacity
	for (int i = 0; i < 30; i++) {
		h2_hpack_dyn_insert_wrapper((const uint8_t *)"n", 1, fill_value, 100);
	}
	// one more entry evicts the oldest ones to make room
	h2_hpack_dyn_insert_wrapper((const uint8_t *)"z", 1, fill_value, 100);
	name = h2_hpack_table_lookup_wrapper(62, &name_len, &value, &value_len,
	                                     &carry);
	int value_ok = (value_len == 100);
	if (value_ok)
		for (int i = 0; i < 100; i++)
			if (value[i] != fill_value[i]) value_ok = 0;
	if (carry != 0 || name_len != 1 || name[0] != 'z' || !value_ok)
		_FAIL("newest entry ('z') still resolves after eviction");
	else
		_PASS("newest entry ('z') still resolves after eviction");
}

static void test_h2_hpack_block(void) {
	TEST_SUITE("h2_hpack_decode_block — whole header block");

	int64_t carry;
	h2_hpack_field_t *f = h2_hpack_fields_addr();

	// a request-like block: :method GET, :scheme https, :path /index.html,
	// :authority example.com (literal without indexing, indexed name)
	static const uint8_t block[] = {
		0x82, 0x87, 0x85,
		0x01, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
	};
	reset_fields();
	ASSERT_EQ("4 fields decoded", 4,
	          h2_hpack_decode_block_wrapper(block, sizeof(block), &carry));
	ASSERT_EQ("carry clear", 0, carry);
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme https", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "https");
	check_field("field 2 :path /index.html", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":path", "/index.html");
	check_field("field 3 :authority example.com", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":authority", "example.com");

	// a size update is skipped and does not count as a field
	static const uint8_t block2[] = { 0x20, 0x82 };
	reset_fields();
	ASSERT_EQ("size update skipped — 1 field", 1,
	          h2_hpack_decode_block_wrapper(block2, sizeof(block2), &carry));
	ASSERT_EQ("carry clear", 0, carry);
	check_field("after size update, :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");

	// an empty block decodes to zero fields
	reset_fields();
	ASSERT_EQ("empty block → 0 fields", 0,
	          h2_hpack_decode_block_wrapper((const uint8_t *)"", 0, &carry));
	ASSERT_EQ("carry clear", 0, carry);

	// a truncated block — the value string overruns the block end
	static const uint8_t block3[] = { 0x01, 0x0a, 'e', 'x' }; // claims 10, has 2
	reset_fields();
	int64_t rc = h2_hpack_decode_block_wrapper(block3, sizeof(block3), &carry);
	ASSERT_EQ("truncated block rejected", H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
	ASSERT_EQ("no field stored for the truncated block", 0, f[0].name_len);

	// a size update followed by an incremental-indexing literal decodes:
	// the entry is never stored (the dynamic table max size is 0), so the
	// block is accepted and the field is added to the output
	static const uint8_t block4[] = { 0x20, 0x41, 0x05, 'h', 'e', 'l', 'l', 'o' };
	reset_fields();
	rc = h2_hpack_decode_block_wrapper(block4, sizeof(block4), &carry);
	ASSERT_EQ("incremental indexing in block accepted — 1 field", 1, rc);
	ASSERT_EQ("carry clear", 0, carry);
	check_field("size update + incremental :authority hello", 0,
	            f[0].name, f[0].name_len, f[0].value, f[0].value_len,
	            ":authority", "hello");

	// more than H2_HPACK_MAX_FIELDS (32) — the fixed output area is full
	uint8_t many[33];
	memset(many, 0x82, sizeof(many)); // :method GET × 33
	reset_fields();
	rc = h2_hpack_decode_block_wrapper(many, sizeof(many), &carry);
	ASSERT_EQ("33-field block rejected (decode area full)",
	          H2_ERR_COMPRESSION_ERROR, rc);
	ASSERT_EQ("carry set", 1, carry);
}

static void test_h2_hpack_block_curl(void) {
	TEST_SUITE("h2_hpack_decode_block — curl's real request block");

	static const uint8_t block[] = {
		0x82, 0x86, 0x41, 0x8a, 0x08, 0x9d, 0x5c, 0x0b, 0x81, 0x70,
		0xdc, 0x78, 0x20, 0x07, 0x84, 0x7a, 0x88, 0x25, 0xb6, 0x50,
		0xc3, 0xcb, 0xba, 0xb8, 0x7f, 0x53, 0x03, 0x2a, 0x2f, 0x2a,
	};
	reset_fields();
	int64_t carry;
	int64_t count = h2_hpack_decode_block_wrapper(block, (int64_t)sizeof(block),
	                                              &carry);
	ASSERT_EQ("block decodes", 0, carry);
	ASSERT_EQ("6 fields decoded", 6, count);

	h2_hpack_field_t *f = h2_hpack_fields_addr();
	check_field("field 0 :method GET", 0, f[0].name, f[0].name_len,
	            f[0].value, f[0].value_len, ":method", "GET");
	check_field("field 1 :scheme http", 0, f[1].name, f[1].name_len,
	            f[1].value, f[1].value_len, ":scheme", "http");
	check_field("field 2 :authority (Huffman)", 0, f[2].name, f[2].name_len,
	            f[2].value, f[2].value_len, ":authority", "127.0.0.1:8100");
	check_field("field 3 :path /", 0, f[3].name, f[3].name_len,
	            f[3].value, f[3].value_len, ":path", "/");
	check_field("field 4 user-agent (Huffman)", 0, f[4].name, f[4].name_len,
	            f[4].value, f[4].value_len, "user-agent", "curl/8.7.1");
	check_field("field 5 accept", 0, f[5].name, f[5].name_len,
	            f[5].value, f[5].value_len, "accept", "*/*");
}

int main(void) {
	test_h2_hpack_static_table();
	test_h2_hpack_int();
	test_h2_hpack_string();
	test_h2_huffman();
	test_h2_hpack_indexed();
	test_h2_hpack_literal();
	test_h2_hpack_dynamic_table();
	test_h2_hpack_block();
	test_h2_hpack_block_curl();
	test_summary();
	return 0;
}
