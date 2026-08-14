![](docs/ymawky.png)

# *ymawky* -- web server in ARM assembly
This is *ymawky* (yuh maw kee), a web server written entirely in ARM64 assembly. ymawky is a syscall-only, no libc, single-process (connection-per-loop, no fork) web server written by hand for macOS and Linux (both in-tree, split by `#ifdef __linux__`).

## Building
Requires Xcode Command Line Tools. Install with `xcode-select --install`.
ymawky only runs on apple silicon (arm64).

Run `make` to build.

Ensure there is a `www/` directory next to the source tree — it's the document root that gets embedded into the binary at build time.
`GET` with an empty filename (`GET /`) will search for `www/index.html`, so you might want to make sure there's an `index.html` as well.

*ymawky* serves static error pages when a client's request results in an error, eg 404. The pages live in `www/err/(code).html` and are embedded at build time.
See [Configuration](#configuration) to modify the default file and docroot.

## Running
- `./ymawky` to start running the web server on `127.0.0.1:8080`.
- `./ymawky [port]` to start running the web server on `127.0.0.1:[port]`
- `./ymawky [any-letter]` is accepted as a legacy "debug" flag, but has no effect anymore — ymawky no longer forks, so there is nothing to disable. (Kept so old invocations don't break.)

Unfortunately, while custom ports are supported, custom addresses are not — the listen address is fixed per platform: `127.0.0.1` on macOS, `0.0.0.0` on Linux. This is solely because I haven't implemented it -- but if you'd like to consider this a safety feature, then I guess it could be intentional.

To see ymawky in action, start running ymawky with `./ymawky [port]`. Then open your web browser of choice (or use curl), and visit `127.0.0.1:8080/` or `127.0.0.1:8080/pretty/index.html`. Bask in the warmth of assembly.

## What can it do?
ymawky is a static-file web server — every file under `www/` is embedded into the binary at build time, so content is served with no filesystem access and no heap allocation. It speaks both HTTP/1.1 and HTTP/2 (RFC 9113).
- Supported HTTP methods:
    - GET
    - HEAD
    - OPTIONS
    - (`BREW` is answered 418, because a teapot)
- HTTP/2 support (RFC 9113): connection preface, frames, streams, flow control, HPACK (static-table), GOAWAY/RST_STREAM error handling
- Basic protection from slowloris-like Denial of Service attacks
- Decodes % hex encoding, eg, `%20` decodes to a space in filenames, and `%61` decodes to `a`
- Smart path traversal detection and prevention. Blocks `..` as a complete path segment, while not disallowing multiple periods when they're part of a filename:
  - `GET /../../../etc/passwd` -> rejected: `400 Bad Request` over HTTP/1, `403 Forbidden` over HTTP/2
  - `GET /ohwell...txt` -> passes the path checks (404 if the file isn't embedded)
  - `GET /hehe..txt` -> passes the path checks (404 if the file isn't embedded)
- Automatically prepends `www/` to requested files. `GET /index.html` will retrieve `www/index.html`
- Empty `GET /` requests default to `GET www/index.html`
- All content is embedded at build time (`embed_www.sh` → `src/embedded.S`); requests are served entirely from the embedded table
- Automatic `Content-Encoding: gzip` for text-like assets (gzipped at build time when it shrinks the file) and precomputed SHA-256 `ETag` headers
- MIME type detection, giving `Content-Type` in the response header with the corresponding MIME type
- Accepts `Range: bytes=` ranges in GET requests, supporting full ranges `bytes=X-N`, suffix ranges `bytes=-N`, and open-ended ranges `bytes=X-`. Video scrubbing is well supported
- Basic HTTP version parsing. Requests need to specify `HTTP/1.1` or `HTTP/1.0`, and if requesting `HTTP/1.1`, a `Host:` field needs to be present in the header
- Serves custom HTML pages for error codes, such as 404, or 500. The pages live in `www/err/` and are embedded at build time (`build_err_pages.sh` generates them)

## "Safety"
This is a web server written entirely by-hand in ARM64 assembly as a fun project. It's probably got a lot of vulnerabilities I'm unaware of. However, I did do my best to make it safer. Here are some safety precautions ymawky takes.
- No filesystem access at request time: all content (including error pages) is embedded into the binary at build time, so there are no file reads, symlinks, or uploads to attack
- Confined to `www/`. Any path requested gets `www/` prepended to it and must match an embedded entry exactly
- Reject any paths that include path traversal -- `/../..` -- at parse time (400 over HTTP/1, 403 over HTTP/2)
- Reject any requests that do not contain a path within 16 bytes
- Reject paths >= 4096 bytes (414 URI Too Long)
- Reject paths containing non-ASCII/control bytes, and `%00` NULL bytes
- Must receive data within 10 seconds (`RECV_TIMEOUT`, configurable). If it's slower, the connection closes with a `408 Request Timed Out`. This is to prevent slowloris-like attacks.

## What happened to CGI / PUT / DELETE?
Earlier versions of ymawky supported CGI scripts, PUT uploads, DELETE, and directory listing. Those features have been **removed** — ymawky is a read-only static-file server again (everything embedded at build time). The old implementations can still be found in the git history.

## HTTP Status Codes
ymawky's current handlers can reply with the following status codes:
- `200 OK`, `204 No Content`, `206 Partial Content`
- `400 Bad Request`, `403 Forbidden`, `404 Not Found`
- `408 Request Timeout`, `414 URI Too Long`, `416 Range Not Satisfiable`
- `418 I'm a teapot`, `431 Request Header Fields Too Large`
- `500 Internal Server Error`, `501 Not Implemented`, `505 HTTP Version Not Supported`

(The status-line lookup table in `src/http1/find_http_code.S` also still holds `201`/`409`/`411`/`413`/`502`/`503`/`507` from the removed PUT/CGI/process-limit features — no current handler produces them.)

Custom HTML pages will be served alongside the error codes (400+). These HTML files live in `www/err/(code).html` and are embedded into the binary at build time. You can use `build_err_pages.sh` to create a page for each code, with different text at your leisure. Edit the source code of `build_err_pages.sh` to modify the text per-page, and modify `err/template.html` to modify the base template. In `err/template.html`:
- `{{CODE}}`  - HTTP Code: eg, 404
- `{{TITLE}}` - Title text: eg, "Not Found"
- `{{MSG}}`   - Custom message: eg, "the rats ate this page"

## MIME Types
MIME types are detected by analyzing the file extension. The following MIME types are recognized.

Web-related files:
- `.html`  -> `text/html; charset=utf-8`
- `.htm`   -> `text/html; charset=utf-8`
- `.css`   -> `text/css; charset=utf-8`
- `.csv`   -> `text/csv; charset=utf-8`
- `.xml`   -> `text/xml; charset=utf-8`
- `.js`    -> `text/javascript; charset=utf-8`
- `.json`  -> `application/json`
- `.wasm`  -> `application/wasm`
- `.mjs`   -> `text/javascript; charset=utf-8`
- `.map`   -> `application/json`

Image files:
- `.png`   -> `image/png`
- `.jpg`   -> `image/jpeg`
- `.jpeg`  -> `image/jpeg`
- `.gif`   -> `image/gif`
- `.svg`   -> `image/svg+xml`
- `.ico`   -> `image/x-icon`
- `.webp`  -> `image/webp`
- `.avif`  -> `image/avif`
- `.bmp`   -> `image/bmp`
- `.tiff`  -> `image/tiff`
- `.apng`  -> `image/apng`

Font files:
- `.woff`  -> `font/woff`
- `.woff2` -> `font/woff2`
- `.ttf`   -> `font/ttf`
- `.otf`   -> `font/otf`

Document files:
- `.txt`   -> `text/plain; charset=utf-8`
- `.pdf`   -> `application/pdf`
- `.doc`   -> `application/msword`
- `.docx`  -> `application/vnd.openxmlformats-officedocument.wordprocessingml.document`
- `.epub`  -> `application/epub+zip`
- `.rtf`   -> `application/rtf`

Video files:
- `.mp4`   -> `video/mp4`
- `.webm`  -> `video/webm`
- `.mkv`   -> `video/x-matroska`
- `.avi`   -> `video/x-msvideo`
- `.mov`   -> `video/quicktime`

Audio files:
- `.mp3`   -> `audio/mpeg`
- `.ogg`   -> `audio/ogg`
- `.wav`   -> `audio/wav`
- `.flac`  -> `audio/flac`
- `.aac`   -> `audio/aac`
- `.m4a`   -> `audio/mp4`
- `.opus`  -> `audio/opus`

Archive files:
- `.zip`   -> `application/zip`
- `.gz`    -> `application/gzip`
- `.tar`   -> `application/x-tar`
- `.7z`    -> `application/x-7z-compressed`
- `.bz2`   -> `application/x-bzip2`
- `.rar`   -> `application/vnd.rar`

## Configuration
You can configure ymawky with the `config.S` file. The options are documented here.
- `#define DOCROOT "www/"` -- This is the docroot, prepended to every requested path (and the root of the embedded table). Change it to wherever your HTML files are, relative to ymawky, or use an absolute path:
  - `#define DOCROOT "www/"`
  - `#define DOCROOT "/Library/WebServer/Documents`
  - `#define DOCROOT "./"`
- `#define ERR_DIR "www/err/"` -- This is the directory in which ymawky looks for custom error HTML pages in the embedded table, eg, `www/err/404.html` or `www/err/500.html`
- `#define DEFAULT_FILE "index.html"` -- This is the default file ymawky will serve when it receives an empty `GET / HTTP/1.1` request
- `.equ RESPONSE_HEADER_SIZE, 512` -- Maximum bytes the response header may occupy; a larger header is an error (500)
- `.equ RECV_TIMEOUT, 10` -- Number of seconds ymawky will wait to receive data before closing the connection. If it's more than `RECV_TIMEOUT` seconds between `read()`s, ymawky will close the connection with `408 Request Timed Out`
- `.equ MAX_PROCS, 256` -- *Vestigial* — a leftover from the fork-per-connection era; no longer read by any code
- `.equ ALLOW_DIR_LISTING, 1` -- *Vestigial* — directory listing was removed; no longer read by any code

## Implementation Notes
ymawky is written for macOS and Linux; platform differences are handled in-tree behind `#ifdef __linux__` in `defs.S`, `main.S` and `child.S`:
- Syscalls on macOS use `x16` for the number and `svc #0x80` to call it. Linux uses `x8` and `svc #0`.
- Error reporting is different. macOS sets the carry flag on error, and puts `errno` in `x0`. Linux returns a negative value in `x0`, like `-ENOENT`; the `SCERR` macro (in `defs.S`) converts it to a positive `errno` and sets/clears the carry flag so `b.cs` works identically on both platforms.
- `SO_NOSIGPIPE` doesn't exist on Linux. ymawky instead ignores `SIGPIPE` and handles the `EPIPE` from `write()`.
- `adr xN, foo@PAGE` / `add xN, xN, foo@PAGEOFF` are Mach-O relocation operators. Linux ELF uses `:pg_hi21:` and `:lo12:`. The `adr_l`, `ldr_l` and `str_l` macros in `defs.S` pick the right one per platform.
- Signal handling differs: Linux uses `rt_sigaction`, macOS uses `sigaction`.
- Struct layouts differ (`stat64`, `sockaddr_in`, ...) — the platform split in `defs.S` carries separate offsets for each.

### Special Thanks:
- [asmhttpd](https://github.com/jcalvinowens/asmhttpd), an x86_64 Linux HTTP server, was a big inspiration
- *Bob Johnson*
- *Bob Johnson's Therapist*
