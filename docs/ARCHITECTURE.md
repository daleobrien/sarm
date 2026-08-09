# ymawky Architecture & Implementation Summary

**ymawky** — "yuh maw kee" — a static-file web server written entirely in hand-rolled ARM64 (AArch64) assembly for macOS. No libc, syscall-only, fork-per-connection. GPL-3.0.

---

## Build & Link Model

- **Build**: `Makefile` compiles each `src/*.S` into `.o` via `cc -g -c`, then links with `ld -l System -e _main -arch arm64`.
- **Entry point**: `_main` (not `_start`), thus linked against `libSystem.dylib` for the Mach-O loader, but no libc symbols are called — only raw `svc #0x80` syscalls.
- **Relocation**: Uses Mach-O-specific `@PAGE`/`@PAGEOFF` PC-relative addressing via macros `adr_l`, `ldr_l`, `str_l` (in `defs.S`).

## Source File Map

| File | Role |
|---|---|
| `config.S` | All user-configurable constants (`#define` + `.equ`): docroot, timeouts, limits |
| `defs.S` | Syscall numbers, struct offsets, macros (`adr_l`, `cb`), constants, `#include`s `config.S` |
| `data.S` | Global `.data`/`.bss`: `buf`, `clientfd`, `file_des`, `filename_str/len`, `query_str/len`, `request_id` |
| `ymawky.S` | `_main`, accept loop, fork, child setup, HTTP method dispatch, `child_end`, `exit` |
| `parse.S` | HTTP header/URI parsing: `parse_path`, `parse_header_end`, `parse_range`, `parse_content_length`, `get_header_field`, `make_tmp_file`, `do_path_checks` |
| `get.S` | GET and HEAD handler: `get_setup`, file open, `mmap`, Range logic, `build_header` calls |
| `put.S` | PUT handler: temp-file atomic write, `renameatx_np`, Content-Length enforcement, SIGALRM-based read timeout |
| `delete.S` | DELETE handler: `unlinkat` with `AT_SYMLINK_NOFOLLOW_ANY` |
| `options.S` | OPTIONS handler: stat check, 204/403 |
| `header.S` | Response header builder (`build_header`), HTTP status-code lookup table, `reply_status` (serves custom error HTML pages from `err/`), `handle_fs_error` (errno→HTTP code mapping) |
| `util.S` | `write_all`, `itoa`, `atoi`, `atoi_n`, `strlen`, `memcpy`, `streqn`, `streqn_i` |
| `file.S` | `stat_fd`/`stat_path`, MIME type table + `get_filetype`, `check_path_traversal`, `check_path_safety`, `decode_url` (%XX hex decoding) |
| `directory.S` | Directory listing via `getdirentries64`, chunked transfer encoding, HTML generation with percent-encoding |
| `cgi.S` | CGI orchestration: pipe+fork+execve, stdin/stdout forwarding, header parsing/forwarding, SIGALRM timeout, `kill_kid` cleanup |
| `cgi_env.S` | CGI environment variable construction: `set_env_vars`, `sev_add_kv_var`, `sev_add_const_var`, `get_remote_addr` (IP/port extraction from sockaddr) |
| `cgi_parse.S` | `check_cgi_path`, `parse_cgi_header_end` (handles `\r\n\r\n` and `\n\n`), `get_cgi_header_field`, `get_script_path_elements` |

---

## Startup & Main Loop (`ymawky.S:_main`)

1. **Argument parsing**: If `argc > 1`, inspects `argv[1][0]`. If `< 'A'` (numeric), parses as port via `atoi` and overwrites the `addr` struct's port field (big-endian `rev16`). If `>= 'A'`, sets `x28=1` (debug mode: no fork).
2. **Socket setup**: `socket(AF_INET, SOCK_STREAM, 0)` → `setsockopt(SO_REUSEADDR)` → `bind(addr:16)` → `listen(5)`.
3. **Signal setup** (parent): `SIGCHLD` → `SIG_IGN` + `SA_NOCLDWAIT` for auto child reaping. `SIGPIPE` → `SIG_IGN` so `write()` returns `EPIPE` instead of killing the process.

### Accept Loop

```
loop:
  accept(sockfd, NULL, NULL) → clientfd
  if debug-mode (x28 != 0): skip fork, jump to child
  getpid()
  proc_info(PROC_INFO_CALL_LISTPIDS, PROC_PPID_ONLY, our_pid, buf, 2048)
    → count children = bytes/4
  if children > MAX_PROCS: reply 503, close clientfd, loop
  fork()
  if parent: close(clientfd), loop
  child: fall through
```

- Uses MacOS-specific `fork()` where child detected by `x1 == 1` (Linux: `x0 == 0`).
- `proc_info` is an undocumented Darwin syscall (336) used to count forked children in a 2048-byte stack buffer (max detectable: 512 children). Configurable via `MAX_PROCS` (default 256).

---

## Child Request Handling (`child`)

1. **Socket options**: `SO_RCVTIMEO` (from `RECV_TIMEOUT` config), `SO_NOSIGPIPE`.
2. **Header timeout**: `setitimer(ITIMER_REAL, HEADER_REQ_TIMEOUT_SECS)` + custom `sigaction` SIGALRM handler that branches directly to 408 (uses `sa_tramp` as the handler itself — MacOS-specific hack detailed in `put.S` comment block).
3. **Read loop**: `read(clientfd, buf+offset, BUF_SIZE-offset)`, cumulative `x7`. After each read, calls `parse_header_end`. Exits on `\r\n\r\n` found, 431 if buffer full, 400 on read errors, silent exit on network errors (`ECONNRESET`, `ETIMEDOUT`, etc.).
4. **Disarm timer**, NULL-terminate buffer.
5. **Log to stdout**: prints `\n\n<<<\n` + the header.
6. **`verify_http_version`**: extracts `HTTP/1.x` from end of request line. For HTTP/1.1, requires `Host:` field via `get_header_field`. Returns 400/505 on failure.
7. **Method dispatch**: sequential `streqn` against `"GET "`, `"HEAD "`, `"OPTIONS "`, `"DELETE "`, `"PUT "`, `"POST "`, `"BREW "`. Sets `request_id` global, branches to handler. Unknown → 501. BREW → 418.

---

## Path Handling (`parse.S:do_path_checks`)

Called by every method handler. Pipeline:

1. **`parse_path`**: Scans for ` /` (space+slash) or ` *` (space+asterisk) within first 16 bytes. Copies path to `filename_buf`, prepending `DOCROOT`. Collapses consecutive slashes. Splits `?query_string` into `query_buf`. If path equals just `www/`, appends `DEFAULT_FILE` (for GET/HEAD only; configurable).
2. **`decode_url`**: In-place `%XX` hex decoding. NULL-terminates result. Returns 0 on bad encoding.
3. **`check_path_safety`**: Validates all bytes are printable ASCII (0x20–0x7E).
4. **`check_path_traversal`**: Detects `..` as a complete path segment (not `foo..txt` or `...`). Works by tracking dot count vs segment length within `/` boundaries.
5. **Temp-file prefix check**: Rejects paths starting with `www/.ymawky_tmp_` (403).

---

## GET / HEAD (`get.S`)

### `get_setup` (shared by GET and HEAD)
- Calls `do_path_checks(1)` (defaults to index.html).
- If path starts with `*`, → 400.
- `check_cgi_path` — if path is under `DOCROOT/CGI_DIR`, branches to `cgi`.
- `open(path, O_RDONLY | O_NOFOLLOW_ANY)` → `stat_fd` → returns file size, type (S_IFREG/S_IFDIR).
- On open/stat error → `handle_fs_error` (errno→HTTP code).

### HEAD
- Calls `get_setup`, then `build_header(file_len, -1, -1, 200)`, writes only the header to client.

### GET
- Calls `get_setup`.
- If directory → `dir_listing`.
- **Range parsing**: `parse_range` looks for `Range: bytes=X-Y` or `bytes=-N` or `bytes=X-`. Returns start/end, or -1 for absent parts. Sets carry if no valid range.
- **Range resolution** (in `get`):
  - Empty file + non-suffix range → 416.
  - `bytes=X-N` (concrete): clamps end to `filesize-1`. 416 if start ≥ filesize.
  - `bytes=-N` (suffix): empty file → serve whole file as 200. N ≥ filesize → serve whole file. Otherwise start = `filesize - N`.
  - `bytes=X-` (open-ended): end = `filesize - 1`. 416 if start ≥ filesize.
- **`build_header`**: Builds response header string into `header_buf` (512 bytes max). Includes status line, `Content-Length`, `Content-Range` (for 206), `Content-Type` (via MIME lookup), and standard tail.
- **`mmap`**: `mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0)`. Range-aware: writes `header_buf` + body slice `[start..end]`.
- **`munmap`** after write, close fd.
- 0-byte files: writes header only, skips mmap.

---

## PUT (`put.S`)

Atomic upload via temp-file-then-rename pattern.

1. `do_path_checks(0)` (no default file).
2. `check_cgi_path` → CGI if in cgi-bin.
3. `stat_path` on target: determines if file exists (→ 204 on success) or is new (→ 201 on success). Non-regular existing file → 403.
4. `parse_content_length`: extracts, validates, deduplicates, caps at `MAX_BODY_SIZE` (1 GiB default). No length → 411. Too large → 413.
5. `make_tmp_file`: generates `www/.ymawky_tmp_<pid>`.
6. `open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW_ANY, 0644)`.
7. Write any body bytes already in buffer after header end.
8. **Dynamic timeout**: `timeout_secs = PUT_GRACE_SECS + remaining_bytes / PUT_MIN_BPS`. Sets `setitimer(ITIMER_REAL)`.
9. **Custom SIGALRM handler** (MacOS-specific): `sa_tramp` points directly to `Lput_sigalrm_handler` which closes tmp fd, unlinks tmp file, → 408. This works because the handler never returns (just sends 408 + exits), so no `sigreturn` needed.
10. **Read/write loop**: reads from clientfd in `BUF_SIZE` chunks into `buf`, writes to tmp fd via `write_all`. Tracks remaining bytes. Handles `EINTR` (retry), network errors (silent exit), `EAGAIN` (408).
11. On client hangup mid-transfer (read returns 0 but Content-Length not satisfied): close + unlink tmp, → 400.
12. **On success**: disarms timer, closes tmp fd, `renameatx_np(AT_FDCWD, tmp, AT_FDCWD, target, RENAME_NOFOLLOW_ANY)` for atomic rename. → 201 (new file) or 204 (existing).
13. On rename failure: unlinks tmp, → `handle_fs_error`.

---

## DELETE (`delete.S`)

1. `do_path_checks(0)`, `check_cgi_path`.
2. `stat_path`: non-existent → 204 (idempotent). Non-regular → 403.
3. `unlinkat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW_ANY)`.
4. Error mapping: `ENOENT`→204, `EISDIR/EACCES/EPERM/EROFS/ELOOP`→403, `EBUSY`→409, else 500.

---

## OPTIONS (`options.S`)

1. `do_path_checks(0)`, `check_cgi_path`.
2. `stat_path`: if exists and is regular file → 204, else → 403. `*` → 204.

---

## Directory Listing (`directory.S`)

Triggered when GET targets a directory.

1. Config guard: `ALLOW_DIR_LISTING` (default 1). If 0 → 403.
2. **Chunked transfer encoding**: Writes `Transfer-Encoding: chunked` header.
3. Generates HTML page with:
   - Embedded CSS (dark purple theme).
   - File/directory entries as `<a href="...">` links.
   - HTML entity encoding via `body_encode` (`&`, `"`, `'`, `<`, `>`).
   - URL percent-encoding via `href_encode` (alphanumeric + `-._~` pass through, rest → `%XX`).
4. Iterates directory via `getdirentries64(fd, buf, 8192, &basep)` in a loop, walking `dirent` structs (`d_name`, `d_namlen`, `d_type`, `d_reclen`). Each entry gets its own chunk.
5. Terminates with `0\r\n\r\n` chunked-encoding sentinel.

---

## CGI Support (`cgi.S`, `cgi_env.S`, `cgi_parse.S`)

### Entry: `cgi` (in `cgi.S`)
Reached when `check_cgi_path` finds the requested path under `DOCROOT/CGI_DIR`.

1. `stat_path`: verifies file exists, is regular, and is **executable** (`S_IXUSR`). Not executable → 500.
2. `get_script_path_elements`: splits `www/cgi-bin/scriptname` into `script_path_buf` (directory prefix) and `script_name_buf` (script basename).
3. `set_env_vars`: populates CGI environment (see below).
4. **Two pipes**: `pipe()` for `cgi_stdin` (server→script) and `cgi_stdout` (script→server).
5. `fork()`:
   - **Parent**: closes unused pipe ends. If PUT/POST, forwards request body to CGI stdin via `cgi_stdin_w` (with SIGALRM timeout). Then reads CGI stdout, parses CGI response header, forwards to client.
   - **Child**: `dup2` to remap pipes to stdin/stdout, `chdir` to script directory, `execve(script_name_buf, argv, envp)`.

### Environment Variables (`cgi_env.S:set_env_vars`)
Built into two buffers: `env_var_str_buf` (4KB, KEY=VALUE\0 strings) and `env_var_ptr_buf` (512 bytes, array of pointers). Constants: `GATEWAY_INTERFACE`, `SERVER_PROTOCOL`, `SERVER_SOFTWARE`, `PATH`, `PATH_INFO`. Dynamic: `REMOTE_ADDR`, `REMOTE_HOST`, `SERVER_NAME`, `SERVER_PORT` (extracted from sockaddr via `getpeername` + `get_remote_addr`), `HTTP_HOST`, `SCRIPT_NAME`, `QUERY_STRING`, `CONTENT_LENGTH` (PUT/POST only), `CONTENT_TYPE` (PUT/POST only), `REQUEST_METHOD` (from method table lookup).

### CGI Response Parsing
- **`parse_cgi_header_end`**: handles both `\r\n\r\n` and `\n\n` terminators (CGI scripts may use either).
- **`get_cgi_header_field`**: case-insensitive, `\n`-delimited header field extraction.
- CGI script's `Status:` header → HTTP status line; if absent → `200 OK`.
- `forward_headers_from_script`: passes through all CGI headers **except** `Status:` and `Connection:` (which ymawky supplies itself). Rejects obsolete line-folding (502). Adds `Server: ymawky`, `Connection: close`, `X-Content-Type-Options: nosniff`.
- Requires `Content-Type` if response has a body (otherwise 502).
- Streams remaining body from CGI stdout to clientfd.
- `wait4(-1, &status, 0, NULL)` to reap child.

### CGI Cleanup (`kill_kid`)
On error paths: closes pipe fds, `kill(child_pid, SIGTERM)`, `wait4` to reap.

### CGI Limitations
- No `PATH_INFO` support.
- No timeout on CGI script execution itself (script can hang indefinitely — acknowledged limitation).

---

## Response System (`header.S`)

### `build_header(file_len, range_start, range_end, status_code)`
Assembles response header into `header_buf` (512 bytes, `RESPONSE_HEADER_SIZE`):
1. Looks up status line from a 24-byte-per-entry lookup table (status code, string ptr, length).
2. Appends `Content-Length: N` (range-aware: `end-start+1` if ranged, `file_len` otherwise).
3. For 206: appends `Content-Range: bytes start-end/total`.
4. Appends `Content-Type: ...` via `get_filetype` (MIME lookup by file extension).
5. Appends fixed tail: `Connection: close`, `Allow`, `Accept-Ranges: bytes`, `Server: ymawky`, `\r\n\r\n`.
6. Sets `header_len` global. Returns carry on overflow.

### `reply_status(code, ret_bool)`
- Serves custom HTML error pages from `err/{code}.html` if they exist.
- `open(err_dir + code + ".html", O_RDONLY | O_NOFOLLOW_ANY)`.
- If file opens successfully: `mmap` it, build header with error status, write header + body.
- If file can't be opened: writes header-only error response.
- If `ret_bool == 0`: branches to `child_end`. If nonzero: returns (used for 503 in accept loop).

### `handle_fs_error(errno)`
Maps filesystem errno values to HTTP status codes:
- `ENAMETOOLONG` → 414, `EINVAL` → 400, `ELOOP` → 403 (symlink via `O_NOFOLLOW_ANY`), `ENOENT/ENOTDIR` → 404, `EACCES/EPERM/EROFS/EISDIR` → 403, `EFAULT` → 500, `EBUSY/ENOTEMPTY` → 409, `ENOSPC/EDQUOT` → 507, `EFBIG` → 413, default → 500.

---

## MIME Type Detection (`file.S:get_filetype`)

Fixed 96-byte-per-entry lookup table (`file_types`). Each entry: 8 bytes extension (NULL-padded, e.g. `".html\0\0"`), 88 bytes MIME string. Searched backwards from end of filename for `.`, then `streqn_i` (case-insensitive, 8-byte max) against table. Returns `text/plain; charset=utf-8` for unknown extensions.

---

## Utility Functions (`util.S`)

- **`write_all(fd, buf, len)`**: Retry loop handling partial writes. Returns total bytes written. Handles `EINTR`. Sets carry + returns errno on non-`EINTR` failure.
- **`itoa(n)`**: Writes decimal digits backwards into static 20-byte buffer. Returns pointer + length. No NULL terminator.
- **`atoi(str)`** / **`atoi_n(str, len)`**: String→integer, 19-digit overflow guard. Carry set on error.
- **`memcpy(dst, src, len)`**: Byte-by-byte, advances both pointers.
- **`strlen(str)`**: NULL-terminated length.
- **`streqn(a, b, maxlen)`**: Fixed-length exact compare. Returns 1/0.
- **`streqn_i(a, b, maxlen)`**: Case-insensitive (OR-with-0x20 trick for ASCII). Handles NULL termination within limit.

---

## File System Operations (`file.S`)

- **`stat_fd(fd)`** / **`stat_path(path)`**: `fstat64`/`stat64` with stack-allocated 160-byte buffer. Returns: errno (0 on success), file type (masked `S_IFMT`), size (`st_size` at offset 96), executable bit (`S_IXUSR`).
- **`decode_url(str, len)`**: In-place `%XX` → raw byte. Lowercases hex digits (OR 0x20). Rejects `%00` (NULL byte). NULL-terminates result. Returns NULL on bad encoding.
- **`check_path_traversal(path, len)`**: Tracks dot count and segment length per `/`-delimited segment. If dot count == segment length and dot count == 2 → traversal detected (returns 0).
- **`check_path_safety(path, len)`**: Validates all bytes in range 0x20–0x7E.

---

## Header Parsing (`parse.S`)

- **`parse_header_end(buf, len)`**: State-machine search for `\r\n\r\n`. Returns index past terminator. Handles false starts (e.g., `\r\n\r>\r<\n\r\n`).
- **`get_header_field(buf, len, field, field_len)`**: Line-oriented scan for `Field: value\r\n`. Returns pointer to value + remaining length. Sets carry if not found. Rejects lines starting with whitespace, fields without `:`, empty values.
- **`parse_range(buf, len)`**: Finds `Range:` header, parses `bytes=X-Y`, `bytes=-N`, `bytes=X-` formats. Returns start/end (or -1 for absent/wildcard parts). 19-digit overflow guard.
- **`parse_content_length(buf, len)`**: Finds `Content-Length:`, deduplicates (second occurrence → malformed), skips leading zeros, validates trailing `\r`, caps at `MAX_BODY_SIZE`. Returns: 0 = not found, 1 = malformed, 2 = too large.

---

## Security Model

- **Path confinement**: All paths prepended with `DOCROOT`.
- **No symlink following**: `O_NOFOLLOW_ANY` on all `open()` calls, `AT_SYMLINK_NOFOLLOW_ANY` on `unlinkat`, `RENAME_NOFOLLOW_ANY` on `renameatx_np`.
- **Path traversal prevention**: Per-segment `..` detection.
- **ASCII-only paths**: Rejects control characters and non-ASCII bytes.
- **Temp-file isolation**: PUT writes to `www/.ymawky_tmp_<pid>`, path starting with `.ymawky_tmp_` blocked from all requests (403). Atomic rename on completion.
- **Slowloris mitigation**: 
  - `SO_RCVTIMEO` per-connection socket timeout (default 10s between reads).
  - `HEADER_REQ_TIMEOUT_SECS` overall header timeout via `setitimer` + SIGALRM handler (default 10s).
  - PUT dynamic timeout: `PUT_GRACE_SECS + remaining / PUT_MIN_BPS`.
- **Process limit**: `MAX_PROCS` cap (default 256) via `proc_info` syscall. Returns 503 when exceeded.
- **CGI limitations**: Scripts confined to `cgi-bin/` directory. No timeout on script execution itself (acknowledged weakness).
- **Content-Length enforcement**: PUT requires valid Content-Length. Duplicate Content-Length headers rejected.
- **%00 rejection**: NULL byte in URL decoded path → 400.

## macOS-Specific Implementation Details

- **Syscall convention**: `x16` = syscall number, `svc #0x80`. Carry flag set on error, errno in `x0`.
- **`fork()` child detection**: Child identified by `x1 == 1` (macOS), not `x0 == 0` (Linux).
- **Signal handling**: Darwin's `sigaction` struct includes `sa_tramp` field. ymawky uses `sa_tramp` directly as the signal handler (bypassing libc trampoline), which is safe because handlers terminate the process (via 408 + exit) rather than returning. Linux port requires POSIX `sigaction` struct.
- **`SO_NOSIGPIPE`**: macOS-only socket option (Linux uses `MSG_NOSIGNAL` flag on `send`).
- **`O_NOFOLLOW_ANY`**: macOS-specific open flag (Linux equivalent: `O_NOFOLLOW` only prevents following the final component).
- **`renameatx_np`**: macOS-specific. Linux equivalent: `renameat2` with different flag values.
- **`proc_info`**: Undocumented Darwin syscall used for process counting.
- **Relocation**: Mach-O `@PAGE`/`@PAGEOFF` operators. Linux ELF uses `:pg_hi21:`/`:lo12:`.

---

## Configurable Constants (`config.S`)

| Symbol | Default | Purpose |
|---|---|---|
| `DOCROOT` | `"www/"` | Document root directory |
| `CGI_DIR` | `"cgi-bin/"` | CGI script subdirectory |
| `ERR_DIR` | `"err/"` | Custom error page directory |
| `DEFAULT_FILE` | `"index.html"` | Default file for `GET /` |
| `RESPONSE_HEADER_SIZE` | 512 | Max response header bytes |
| `RECV_TIMEOUT` | 10 | Seconds without data before close |
| `HEADER_REQ_TIMEOUT_SECS` | 10 | Max seconds to receive full header |
| `PUT_GRACE_SECS` | 5 | Base grace period for PUT timeout |
| `PUT_MIN_BPS` | 16384 | Minimum bytes/sec for PUT timeout calc |
| `MAX_BODY_SIZE` | 1 GiB | Max Content-Length for PUT |
| `MAX_PROCS` | 256 | Max concurrent child processes |
| `ALLOW_DIR_LISTING` | 1 | Enable directory listing (0 = 403) |
