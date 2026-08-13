// Unit tests for src/util/ assembly functions
// Tests: check_path_traversal, check_path_safety, get_filetype

#include "test_harness.h"

// ── extern assembly functions ──────────────────────────────────────

extern int64_t check_path_traversal(const char *path, int64_t len) __asm__("check_path_traversal");
extern int64_t check_path_safety(const char *path, int64_t len) __asm__("check_path_safety");

// get_filetype(filename=x0, len=x1) → (ct=x0, ct_len=x1)
static inline void get_filetype_wrapper(
	const char *filename, int64_t len,
	const char **out_ct, int64_t *out_ct_len)
{
	const char *ct; int64_t ct_len;
	asm volatile(
		"mov x0, %2\n"
		"mov x1, %3\n"
		"bl get_filetype\n"
		"mov %0, x0\n"
		"mov %1, x1\n"
		: "=r"(ct), "=r"(ct_len)
		: "r"(filename), "r"(len)
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
		  "x19", "x20", "x21", "x22", "x23",
		  "memory"
	);
	*out_ct = ct;
	*out_ct_len = ct_len;
}

// ── tests: check_path_traversal ────────────────────────────────────

static void test_check_path_traversal(void) {
	TEST_SUITE("check_path_traversal");

	ASSERT_EQ("safe: www/index.html",   1, check_path_traversal("www/index.html", 14));
	ASSERT_EQ("safe: index.html",       1, check_path_traversal("index.html", 10));
	ASSERT_EQ("safe: a/b/c",            1, check_path_traversal("a/b/c", 5));
	ASSERT_EQ("safe: single dot",       1, check_path_traversal("foo/./bar", 9));
	ASSERT_EQ("safe: triple dot",       1, check_path_traversal("foo/.../bar", 10));
	ASSERT_EQ("safe: dots in filename", 1, check_path_traversal("hehe..txt", 9));
	ASSERT_EQ("safe: empty",            1, check_path_traversal("", 0));
	ASSERT_EQ("safe: just slash",       1, check_path_traversal("www/", 4));
	ASSERT_EQ("safe: root",             1, check_path_traversal("/", 1));

	ASSERT_EQ("unsafe: ../etc/passwd",     0, check_path_traversal("../etc/passwd", 13));
	ASSERT_EQ("unsafe: /../etc/passwd",    0, check_path_traversal("/../etc/passwd", 14));
	ASSERT_EQ("unsafe: foo/../bar",        0, check_path_traversal("foo/../bar", 10));
	ASSERT_EQ("unsafe: just ..",           0, check_path_traversal("..", 2));
	ASSERT_EQ("unsafe: /..",               0, check_path_traversal("www/..", 6));
	ASSERT_EQ("unsafe: deep ..",           0, check_path_traversal("a/b/../../c", 11));
}

// ── tests: check_path_safety ───────────────────────────────────────

static void test_check_path_safety(void) {
	TEST_SUITE("check_path_safety");

	ASSERT_EQ("safe: index.html",      1, check_path_safety("index.html", 10));
	ASSERT_EQ("safe: path/with/slash", 1, check_path_safety("path/with/slash", 15));
	ASSERT_EQ("safe: with spaces",     1, check_path_safety("hello world.html", 16));
	ASSERT_EQ("safe: query string",    1, check_path_safety("file?q=1", 8));
	ASSERT_EQ("safe: empty",           1, check_path_safety("", 0));
	ASSERT_EQ("safe: tilde",           1, check_path_safety("~user", 5));

	ASSERT_EQ("unsafe: NUL byte",      0, check_path_safety("\x00file", 5));
	ASSERT_EQ("unsafe: tab",           0, check_path_safety("\tfile", 5));
	ASSERT_EQ("unsafe: newline",       0, check_path_safety("\nfile", 5));
	ASSERT_EQ("unsafe: DEL (0x7F)",    0, check_path_safety("\x7F" "file", 5));
	ASSERT_EQ("unsafe: high byte",     0, check_path_safety("\xFF" "file", 5));
	ASSERT_EQ("unsafe: UTF-8 é",       0, check_path_safety("caf\xC3\xA9", 5));
}

// ── tests: get_filetype ────────────────────────────────────────────

static void test_get_filetype(void) {
	TEST_SUITE("get_filetype");

	const char *ct; int64_t ct_len; char buf[100];

	get_filetype_wrapper("index.html", 10, &ct, &ct_len);
	ASSERT_NOT_NULL("html not null", ct);
	ASSERT_TRUE("html content-type found", ct_len > 0);
	if (ct && ct_len > 0) {
		memcpy(buf, ct, (size_t)ct_len); buf[ct_len] = 0;
		ASSERT_STR_EQ("html → text/html", "text/html; charset=utf-8", ct, ct_len);
	}

	get_filetype_wrapper("style.css", 9, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("css → text/css", "text/css; charset=utf-8", ct, ct_len);

	get_filetype_wrapper("image.png", 9, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("png → image/png", "image/png", ct, ct_len);

	get_filetype_wrapper("script.js", 9, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("js → text/javascript", "text/javascript; charset=utf-8", ct, ct_len);

	get_filetype_wrapper("data.json", 9, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("json → application/json", "application/json", ct, ct_len);

	get_filetype_wrapper("photo.jpg", 9, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("jpg → image/jpeg", "image/jpeg", ct, ct_len);

	get_filetype_wrapper("photo.jpeg", 10, &ct, &ct_len);
	ASSERT_TRUE("jpeg found", ct_len > 0);

	get_filetype_wrapper("video.mp4", 9, &ct, &ct_len);
	ASSERT_TRUE("mp4 found", ct_len > 0);

	get_filetype_wrapper("noextension", 11, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("no ext → text/plain", "text/plain; charset=utf-8", ct, ct_len);

	get_filetype_wrapper("file.", 5, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("file. → text/plain", "text/plain; charset=utf-8", ct, ct_len);

	get_filetype_wrapper("file.xyzzy", 10, &ct, &ct_len);
	if (ct && ct_len > 0)
		ASSERT_STR_EQ("xyzzy → text/plain", "text/plain; charset=utf-8", ct, ct_len);
}

// ── main ───────────────────────────────────────────────────────────

int main(void) {
	test_check_path_traversal();
	test_check_path_safety();
	test_get_filetype();
	test_summary();
	return 0;
}
