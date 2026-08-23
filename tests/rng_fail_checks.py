#!/usr/bin/env python3
"""One TLS handshake attempt, reported at the byte level.

tests/test_rng_fail.sh runs servers whose CSPRNG has been made to fail
at a chosen draw (docs/SECURITY.md §14 A4) and needs to know not just
"did the handshake fail" but *what the server put on the wire before it
gave up*. `openssl s_client` answers the first question and not the
second, so the handshake is driven here instead, over an
ssl.MemoryBIO pair: Python does the TLS, this script owns the socket,
and every byte the server sent is counted and parsed as TLS records
before being handed to the library.

The server sends no alert on handshake failure — that is a deliberate
property, recorded in src/tls/server/handshake.S — so "aborted" looks
like a close, and the interesting measurement is how many record bytes
preceded it.

Output is one JSON object on stdout:

  ok             the handshake completed
  error          the exception class, when it did not
  server_bytes   total bytes read from the server
  records        [[content_type, length], ...] as far as they parse
  server_hello   a ServerHello (handshake type 2) was seen
  app_bytes      plaintext bytes read after the handshake, when ok
"""

import argparse
import json
import socket
import ssl
import sys

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
EMPTY_SETTINGS = bytes([0, 0, 0, 0x04, 0, 0, 0, 0, 0])


def parse_records(data):
    """TLS record headers, as far as the bytes go. Truncation is
    expected — the server may be cut off mid-record."""
    out, i = [], 0
    while i + 5 <= len(data):
        ctype = data[i]
        length = (data[i + 3] << 8) | data[i + 4]
        out.append([ctype, length])
        i += 5 + length
    return out


def saw_server_hello(data):
    # An unencrypted handshake record (0x16) whose first body byte is
    # 0x02. Only the first record of a TLS 1.3 flight is in the clear,
    # which is exactly the one this asks about.
    return len(data) >= 6 and data[0] == 0x16 and data[5] == 0x02


def attempt(host, port, timeout):
    result = {"ok": False, "error": None, "server_bytes": 0,
              "records": [], "server_hello": False, "app_bytes": 0}
    seen = bytearray()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # the tree ships a self-signed cert
    ctx.set_alpn_protocols(["h2"])           # the server negotiates h2 or nothing
    inbio, outbio = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inbio, outbio, server_hostname="localhost")

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        while True:
            try:
                tls.do_handshake()
                result["ok"] = True
                break
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass
            except Exception as exc:                      # noqa: BLE001
                result["error"] = type(exc).__name__
                break

            pending = outbio.read()
            if pending:
                sock.sendall(pending)

            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                result["error"] = "timeout"
                break
            if not chunk:
                inbio.write_eof()
                # Let the library turn the EOF into its own error on the
                # next pass rather than inventing one here.
                try:
                    tls.do_handshake()
                    result["ok"] = True
                except Exception as exc:                  # noqa: BLE001
                    result["error"] = type(exc).__name__
                break
            seen += chunk
            inbio.write(chunk)

        if result["ok"]:
            # ALPN negotiates h2, so the only thing the server will
            # answer is an HTTP/2 connection preface followed by a
            # SETTINGS frame. Reading its SETTINGS back is the point:
            # it says the application epoch works, which is what makes
            # this a control rather than another failing case.
            tls.write(H2_PREFACE + EMPTY_SETTINGS)
            pending = outbio.read()
            if pending:
                sock.sendall(pending)
            try:
                while True:
                    try:
                        result["app_bytes"] = len(tls.read(4096))
                        break
                    except ssl.SSLWantReadError:
                        chunk = sock.recv(65536)
                        if not chunk:
                            break
                        inbio.write(chunk)
            except Exception:                             # noqa: BLE001
                pass
    finally:
        sock.close()

    result["server_bytes"] = len(seen)
    result["records"] = parse_records(bytes(seen))
    result["server_hello"] = saw_server_hello(bytes(seen))
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    try:
        out = attempt(args.host, args.port, args.timeout)
    except Exception as exc:                              # noqa: BLE001
        out = {"ok": False, "error": f"connect:{type(exc).__name__}",
               "server_bytes": 0, "records": [], "server_hello": False,
               "app_bytes": 0}
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
