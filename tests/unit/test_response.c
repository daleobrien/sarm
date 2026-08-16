// Unit tests for Stage 2 — the protocol-neutral response representation.
//
// Handlers fill a `response` struct (resolve resource → create response)
// and the HTTP/1 encoder (http1_write_response) turns it into wire bytes.
// These tests encode responses through that common representation and
// compare the exact HTTP/1.1 wire output (status line + headers + body).
//
// Coverage — statuses through the response struct:
//   200  — direct response struct → http1_write_response
//   206  — direct response struct with a range → http1_write_response
//   403, 404, 416 — via reply_status → create_response →
//         http1_write_response (the same path the server uses; with no
//         embedded error pages, which matches the current build)
//   HEAD-style (200, headers only) — Content-Length reflects the full
//         resource while no body bytes are sent
//
// Output is captured through a pipe: the test sets the clientfd global to
// the pipe's write end, calls the encoder, then compares what it wrote.
// This file is part of sarm.
// Copyright (C) 2026 imtomt
// SPDX-License-Identifier: GPL-3.0-only

#include "test_harness.h"

#define LITLEN(s) ((int64_t)(sizeof(s) - 1))

// ── the response struct, mirroring the RESP_* offsets in defs.S ─────
typedef struct {
    int64_t status;            // RESP_STATUS
    const char *content_type;  // RESP_CONTENT_TYPE
    int64_t content_type_len;  // RESP_CONTENT_TYPE_LEN
    int64_t content_length;    // RESP_CONTENT_LENGTH
    const char *body;          // RESP_BODY
    int64_t body_length;       // RESP_BODY_LENGTH
    int64_t range_start;       // RESP_RANGE_START (-1 = no range)
    int64_t range_end;         // RESP_RANGE_END   (-1 = no range)
} response_t;

// ── globals from data.S ─────────────────────────────────────────────
// The HTTP/1 encoder writes to clientfd and consults resource_type /
// embedded_gzip / embedded_etag for the Content-Encoding/ETag headers.
extern int64_t clientfd          __asm__("clientfd");
extern int64_t resource_type     __asm__("resource_type");
extern int64_t embedded_gzip     __asm__("embedded_gzip");
extern int64_t embedded_etag     __asm__("embedded_etag");
extern int64_t embedded_etag_len __asm__("embedded_etag_len");

// ── libc declarations (harness skips <unistd.h>) ────────────────────
extern int pipe(int *fds);
extern long read(int fd, void *buf, unsigned long n);
extern int close(int fd);

// ── assembly wrappers ───────────────────────────────────────────────

// http1_write_response(resp=x0) → carry flag (1 = header too big)
static inline int64_t http1_write_response_wrapper(const response_t *resp) {
    int64_t carry;
    asm volatile(
        "cmp xzr, xzr\n"
        "mov x0, %1\n"
        "bl http1_write_response\n"
        "cset %0, cs\n"
        : "=r"(carry)
        : "r"(resp)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17",
          "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "memory");
    return carry;
}

// reply_status(status=x0, flag=x1). The server always calls it with
// flag=0, which tail-branches to child_end (which exits the process in
// the real server). A unit test can't exit, so we use flag=1, which
// makes reply_status restore its frame and return — the response bytes
// written to the client are identical either way.
static inline void reply_status_wrapper(int64_t status, int64_t flag) {
    asm volatile(
        "mov x0, %0\n"
        "mov x1, %1\n"
        "bl reply_status\n"
        :
        : "r"(status), "r"(flag)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17",
          "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "memory");
}

// ── test plumbing ───────────────────────────────────────────────────

static int g_fds[2];

// fresh pipe + deterministic encoder state (no gzip/ETag extras)
static void test_setup(void) {
    if (pipe(g_fds) != 0) {
        printf("  ✗ pipe() failed\n");
        exit(2);
    }
    clientfd = g_fds[1];
    resource_type = 0;        // RES_NONE — no Content-Encoding/ETag
    embedded_gzip = 0;
    embedded_etag = 0;
    embedded_etag_len = 0;
}

// read everything the encoder wrote to the pipe (write end closed first,
// so EOF terminates the read — a wrong expected length can't hang)
static long read_pipe(char *buf, long cap) {
    long got = 0;
    close(g_fds[1]);
    while (got < cap) {
        long n = read(g_fds[0], buf + got, (unsigned long)(cap - got));
        if (n <= 0) break;
        got += n;
    }
    close(g_fds[0]);
    return got;
}

// ── tests: 200 ──────────────────────────────────────────────────────

static void test_response_200(void) {
    TEST_SUITE("http1_write_response — 200 OK");

    static const char body[] = "hello world";
    static const char ct[] = "text/plain; charset=utf-8";

    test_setup();
    response_t resp = {
        .status = 200,
        .content_type = ct,
        .content_type_len = LITLEN(ct),
        .content_length = LITLEN(body),
        .body = body,
        .body_length = LITLEN(body),
        .range_start = -1,
        .range_end = -1,
    };

    int64_t carry = http1_write_response_wrapper(&resp);
    ASSERT_EQ("carry clear", 0, carry);

    static const char expected[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 11\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Connection: close\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Allow: GET, HEAD, OPTIONS\r\n"
        "Accept-Ranges: bytes\r\n"
        "Server: sarm\r\n"
        "\r\n"
        "hello world";

    char buf[512];
    long n = read_pipe(buf, (long)sizeof(buf));
    ASSERT_EQ("bytes on the wire", (long)sizeof(expected) - 1, n);
    ASSERT_TRUE("wire bytes match",
                n == (long)sizeof(expected) - 1 &&
                memcmp(buf, expected, (unsigned long)n) == 0);
}

// ── tests: 206 ──────────────────────────────────────────────────────

static void test_response_206(void) {
    TEST_SUITE("http1_write_response — 206 Partial Content");

    static const char body[] = "hello world";   // total resource
    static const char ct[] = "text/plain; charset=utf-8";

    test_setup();
    response_t resp = {
        .status = 206,
        .content_type = ct,
        .content_type_len = LITLEN(ct),
        .content_length = LITLEN(body),          // total length
        .body = body + 2,                         // bytes 2..6 → "llo w"
        .body_length = 5,
        .range_start = 2,
        .range_end = 6,
    };

    int64_t carry = http1_write_response_wrapper(&resp);
    ASSERT_EQ("carry clear", 0, carry);

    static const char expected[] =
        "HTTP/1.1 206 Partial Content\r\n"
        "Content-Length: 5\r\n"
        "Content-Range: bytes 2-6/11\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Connection: close\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Allow: GET, HEAD, OPTIONS\r\n"
        "Accept-Ranges: bytes\r\n"
        "Server: sarm\r\n"
        "\r\n"
        "llo w";

    char buf[512];
    long n = read_pipe(buf, (long)sizeof(buf));
    ASSERT_EQ("bytes on the wire", (long)sizeof(expected) - 1, n);
    ASSERT_TRUE("wire bytes match",
                n == (long)sizeof(expected) - 1 &&
                memcmp(buf, expected, (unsigned long)n) == 0);
}

// ── tests: HEAD-style (200, headers only) ───────────────────────────
// Content-Length reflects the full resource while no body is sent.

static void test_response_head(void) {
    TEST_SUITE("http1_write_response — HEAD (headers only)");

    static const char body[] = "hello world";
    static const char ct[] = "text/plain; charset=utf-8";

    test_setup();
    response_t resp = {
        .status = 200,
        .content_type = ct,
        .content_type_len = LITLEN(ct),
        .content_length = LITLEN(body),   // what GET would send
        .body = body,
        .body_length = 0,                 // headers only
        .range_start = -1,
        .range_end = -1,
    };

    int64_t carry = http1_write_response_wrapper(&resp);
    ASSERT_EQ("carry clear", 0, carry);

    static const char expected[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 11\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Connection: close\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Allow: GET, HEAD, OPTIONS\r\n"
        "Accept-Ranges: bytes\r\n"
        "Server: sarm\r\n"
        "\r\n";

    char buf[512];
    long n = read_pipe(buf, (long)sizeof(buf));
    ASSERT_EQ("bytes on the wire", (long)sizeof(expected) - 1, n);
    ASSERT_TRUE("wire bytes match",
                n == (long)sizeof(expected) - 1 &&
                memcmp(buf, expected, (unsigned long)n) == 0);
}

// ── tests: 403 / 404 / 416 via reply_status ─────────────────────────
// reply_status → create_response → http1_write_response, exactly the
// path the server takes for error statuses. With no embedded error pages
// (current build), these are header-only responses with Content-Length: 0.

static void test_reply_status_error(int64_t status,
                                    const char *expected_status_line,
                                    int64_t expected_line_len,
                                    const char *what) {
    test_setup();
    reply_status_wrapper(status, 1);

    char expected[512];
    long expected_len = 0;
    {
        // "HTTP/1.1 <line>\r\nContent-Length: 0" + shared tail
        static const char cl[] = "\r\nContent-Length: 0";
        static const char tail[] =
            "\r\nConnection: close\r\n"
            "X-Frame-Options: DENY\r\n"
            "Referrer-Policy: no-referrer\r\n"
            "Allow: GET, HEAD, OPTIONS\r\n"
            "Accept-Ranges: bytes\r\n"
            "Server: sarm\r\n"
            "\r\n";

        memcpy(expected, expected_status_line, (unsigned long)expected_line_len);
        expected_len = expected_line_len;
        memcpy(expected + expected_len, cl, (unsigned long)LITLEN(cl));
        expected_len += LITLEN(cl);
        memcpy(expected + expected_len, tail, (unsigned long)LITLEN(tail));
        expected_len += LITLEN(tail);
    }

    char buf[512];
    long n = read_pipe(buf, (long)sizeof(buf));
    ASSERT_EQ(what, expected_len, n);
    ASSERT_TRUE("wire bytes match",
                n == expected_len && memcmp(buf, expected, (unsigned long)n) == 0);
}

static void test_response_errors(void) {
    TEST_SUITE("reply_status → create_response → http1_write_response");

    test_reply_status_error(403, "HTTP/1.1 403 Forbidden",
                            LITLEN("HTTP/1.1 403 Forbidden"), "403 wire bytes");
    test_reply_status_error(404, "HTTP/1.1 404 Not Found",
                            LITLEN("HTTP/1.1 404 Not Found"), "404 wire bytes");
    test_reply_status_error(416, "HTTP/1.1 416 Range Not Satisfiable",
                            LITLEN("HTTP/1.1 416 Range Not Satisfiable"),
                            "416 wire bytes");
}

// ── main ────────────────────────────────────────────────────────────

int main(void) {
    test_response_200();
    test_response_206();
    test_response_head();
    test_response_errors();
    test_summary();
    return 0;
}
