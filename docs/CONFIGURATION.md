# Configuration reference

## `src/config.S`

Everything user-tunable, `#define`d or `.equ`'d. Changing any of these needs a
rebuild.

| Symbol | Default | Purpose |
|---|---|---|
| `DOCROOT` | `"www/"` | Prefixed to every requested path; also the root of the embedded table. Needs the trailing `/`. |
| `ERR_DIR` | `"www/err/"` | Where error pages are looked up in the embedded table. Trailing `/` required. |
| `DEFAULT_FILE` | `"index.html"` | Served for `GET /`. |
| `RESPONSE_HEADER_SIZE` | 512 | Max response header bytes; overflow is a 500. |
| `RECV_TIMEOUT` | 10 | Seconds without data before the connection is closed with 408. Also the total header timeout. |
| `TRANSPORT_MODE` | `TRANSPORT_PLAIN` | Compile-time default for the runtime `transport_mode` global. TLS is selected per connection by first-byte detection, so this normally stays PLAIN. |
| `MAX_PROCS` | 256 | **Vestigial** — read by nothing. sarm does fork per connection, so a cap like this is meaningful in principle; it is simply not wired up. Nothing bounds concurrent connections today except the system process limit. |
| `ALLOW_DIR_LISTING` | 1 | **Vestigial** — directory listing was removed, read by nothing. |

`DOCROOT` can be relative or absolute (`"./"`, `"/Library/WebServer/Documents/"`),
but note that it is a *prefix into the embedded table*, not a filesystem path —
whatever it points at must have been embedded at build time.

## Assets

Put files under `www/`; `make` embeds them. Text-like extensions (`html`, `htm`,
`css`, `csv`, `xml`, `js`, `json`, `mjs`, `map`, `svg`, `txt`, `ttf`, `otf`) are
gzipped at build time when that makes them smaller, cached in `www_gz/`, and
served with `Content-Encoding: gzip`. Every asset gets a precomputed SHA-256
`ETag`.

## Error pages

`build_err_pages.sh` generates `www/err/<code>.html` from `err/template.html`.
The template understands:

| Placeholder | Example |
|---|---|
| `{{CODE}}` | `404` |
| `{{TITLE}}` | `Not Found` |
| `{{MSG}}` | `the rats ate this page` |

Edit the per-code text inside `build_err_pages.sh`, the layout in
`err/template.html`. Pages are embedded like any other asset; a missing page just
means a header-only error response.

## Status codes

Produced by current handlers:

`200` `204` `206` · `400` `403` `404` `408` `414` `416` `418` `431` · `500` `501` `505`

Still present in `find_http_code`'s table but unreachable — leftovers from the
removed PUT/CGI/process-limit features: `201` `409` `411` `413` `502` `503` `507`.

## MIME types

By file extension (`src/file/get_filetype.S`), case-insensitive, dispatched on
the first character after the dot. Unknown or missing extension →
`text/plain; charset=utf-8`.

| Group | Extensions |
|---|---|
| Web | `.html` `.htm` → `text/html; charset=utf-8` · `.css` → `text/css` · `.csv` → `text/csv` · `.xml` → `text/xml` · `.js` `.mjs` → `text/javascript` · `.json` `.map` → `application/json` · `.wasm` → `application/wasm` |
| Images | `.png` `.jpg`/`.jpeg` `.gif` `.svg` `.ico` `.webp` `.avif` `.bmp` `.tiff` `.apng` |
| Fonts | `.woff` `.woff2` `.ttf` `.otf` |
| Documents | `.txt` `.pdf` `.doc` `.docx` `.epub` `.rtf` |
| Video | `.mp4` `.webm` `.mkv` `.avi` `.mov` |
| Audio | `.mp3` `.ogg` `.wav` `.flac` `.aac` `.m4a` `.opus` |
| Archives | `.zip` `.gz` `.tar` `.7z` `.bz2` `.rar` |

Text types carry `; charset=utf-8`. 43 extensions total; add one by extending the
96-byte-per-entry table in `get_filetype.S` (8-byte extension + 88-byte MIME
string), keeping it in its first-character group.

## Certificates

`certs/` holds a self-signed ECDSA P-256 (`secp256r1`) test certificate — the
only key type the server can use, since its one cipher suite is
`TLS_AES_128_GCM_SHA256` with ECDSA P-256 + SHA-256 signatures.

| File | Contents |
|---|---|
| `key.pem` | EC P-256 private key (chmod 600) |
| `cert.pem` / `cert.der` | Self-signed certificate; the DER form is what the TLS `Certificate` message carries |
| `embed_cert.sh` | Generates `src/tls/cert_data.S` (`tls_cert_der`, `tls_priv_key`) |
| `generate.sh` | Makes a fresh key + certificate |

There is **no X.509 parser** in the server: `cert.der` is embedded verbatim and
the raw 32-byte private scalar is extracted from `key.pem` at build time. To use
your own certificate, drop it in as `cert.pem`/`key.pem`, regenerate `cert.der`,
and rebuild — `make` re-runs `embed_cert.sh` whenever `certs/` changes.

## Platform differences

Handled in `src/defs.S` behind `#ifdef __linux__`; nothing to configure, but
worth knowing when reading the source.

| | macOS | Linux |
|---|---|---|
| Syscall | `x16` + `svc #0x80` | `x8` + `svc #0` |
| Error | carry set, errno in `x0` | negative return, normalised by `SCERR` |
| Listen address | `127.0.0.1` | `0.0.0.0` |
| accept | `SYS_accept` | `SYS_accept4` |
| Broken pipe | `SO_NOSIGPIPE` | ignored `SIGPIPE` + `EPIPE` |
| Signals | `sigaction` | `rt_sigaction` |
| Entropy | `getentropy(2)` | `getrandom(2)` |
| Relocation | `@PAGE` / `@PAGEOFF` | `:pg_hi21:` / `:lo12:` |

The relocation and syscall differences are hidden behind the `adr_l`, `ldr_l`,
`str_l`, `SCWINUM`, `SCWISVC` and `SCERR` macros — use those rather than writing
either form directly.
