#!/usr/bin/env python3
"""Secret-leak regression checks against a running sarm
(docs/SECURITY.md §4.5, Step 10).

Step 10 asks for one thing: fire a large amount of malformed and fuzzed
traffic at the server, capture every byte it sends back, and assert that
nothing secret is in it.  What makes that a *regression* test rather
than a proof is that the secrets are known in advance — so this script
starts by working out exactly what to look for.

Four needle sets:

  private key   the 32-byte ECDSA P-256 private scalar, read out of
                `src/tls/cert_data.S` — the same bytes the assembler
                puts in the binary, so no guessing is involved.  Both
                the whole scalar and every 12-byte window of it, so a
                partial disclosure (an over-read that catches the tail
                of the key and stops) is caught as well as a whole one.
                12 bytes because a false positive needs a 96-bit
                coincidence and there is not enough traffic in the
                universe for one.

  request       every connection sends a unique marker
    markers     (`SARMLEAKCANARY<n>`) in its path, query, authority or a
                header.  The server echoes no request bytes in any
                response — it serves embedded assets and fixed error
                pages, and the only request-derived text in any header
                is the digits of a Content-Range — so a marker coming
                back at all is a finding, and a marker coming back on a
                *different connection* is the specific finding Step 10
                is about: one client reading another's buffer.

  key           an out-of-bounds read into the memory around the key
    neighbours  usually catches its neighbours too.  The bytes on
                either side of `tls_priv_key` in `cert_data.S` — the
                tail of the certificate DER — are public, but their
                appearance in a response body is still a disclosure of
                memory the server never means to send, so they are
                checked with the same window search.

  file content  strings that can only be present if the server read a
                file: PEM armour, /etc/passwd's first field, the ELF
                and Mach-O magic numbers.  The server makes no
                file-opening syscall at all (Step 11), so these must
                never appear; they are here because a *future* change
                that adds one would show up as a leak long before
                anyone re-ran the syscall audit.

What this does not do is prove the key cannot be extracted.  Step 9 of
docs/SECURITY.md is clear that an in-process key is extractable by
anyone who can read the process's memory, and no amount of fuzzing
changes that.  This is a detector for accidental disclosure over the
network, which is the part a regression test can own.

Usage: leak_checks.py <port> [--cases N] [--seed S] [--label TEXT]
       (started and stopped by test_leak.sh)
Output: one "OK: ..." or "FAIL: ..." line per check.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hostile_workload as hw                                # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DATA = os.path.join(REPO, "src", "tls", "cert_data.S")

WINDOW = 12          # the shortest run of key bytes treated as a leak


# ── the needles ─────────────────────────────────────────────────────
def parse_cert_data(path):
    """Return (priv_key, cert_der) from the generated cert_data.S.

    The file is `.byte` lines under two labels; parsing it is more
    honest than parsing certs/key.pem, because this is the file the
    assembler reads — if the two ever disagree, the binary holds this
    one, and this one is what the test must hunt for.
    """
    sections = {}
    label = None
    with open(path) as f:
        for line in f:
            s = line.split("//", 1)[0].strip()
            m = re.match(r"^([A-Za-z_][\w]*)\s*:", s)
            if m:
                label = m.group(1)
                sections.setdefault(label, bytearray())
                continue
            if label and s.startswith(".byte"):
                for tok in s[5:].split(","):
                    tok = tok.strip()
                    if tok:
                        sections[label].append(int(tok, 0))
    if "tls_priv_key" not in sections or len(sections["tls_priv_key"]) != 32:
        raise SystemExit(f"leak_checks: no 32-byte tls_priv_key in {path}")
    return bytes(sections["tls_priv_key"]), bytes(sections.get("tls_cert_der", b""))


def windows(data, n):
    return {bytes(data[i:i + n]) for i in range(0, len(data) - n + 1)}


FILE_STRINGS = [
    b"-----BEGIN", b"PRIVATE KEY", b"root:x:", b"root:*:",
    b"\x7fELF", b"\xcf\xfa\xed\xfe",
]


# ── the scan ────────────────────────────────────────────────────────
class Scanner:
    """Holds the needles and every violation found."""

    def __init__(self, priv, cert):
        self.priv = priv
        self.key_windows = windows(priv, WINDOW)
        # The 32 bytes on each side of the key inside cert_data.S: the
        # DER's tail is what precedes it, and nothing follows it, so the
        # neighbourhood that can be over-read *into* view is the DER.
        self.neighbour_windows = windows(cert[-64:], WINDOW) if cert else set()
        self.file_strings = FILE_STRINGS
        self.findings = []
        self.markers_seen = set()
        # A string every HTTP/1 response really does carry. Counting it
        # is the live version of the self-test: it proves the capture
        # path reaches the wire and the search runs over what came back,
        # so a clean scan means "nothing was there" rather than "nothing
        # was looked at".
        self.sentinel = b"Server: sarm"
        self.sentinel_hits = 0
        # Certificates seen over TLS, so the run can confirm it is
        # talking to the build whose key it is hunting for.
        self.certs_seen = set()
        self.bytes_scanned = 0
        self.conns = 0

    def _hit(self, kind, conn, where, detail):
        self.findings.append((kind, conn.campaign, where, detail))

    def scan(self, conn):
        self.conns += 1
        if conn.peercert:
            self.certs_seen.add(bytes(conn.peercert))
        for where, buf in (("wire", bytes(conn.raw)),
                           ("decrypted", bytes(conn.plain))):
            if not buf:
                continue
            self.bytes_scanned += len(buf)

            if self.priv in buf:
                self._hit("private key (complete)", conn, where,
                          f"at offset {buf.find(self.priv)}")
            else:
                for i in range(0, len(buf) - WINDOW + 1):
                    w = buf[i:i + WINDOW]
                    if w in self.key_windows:
                        self._hit(f"private key ({WINDOW}-byte run)", conn,
                                  where, f"at offset {i}: {w.hex()}")
                        break

            for i in range(0, len(buf) - WINDOW + 1):
                w = buf[i:i + WINDOW]
                if w in self.neighbour_windows:
                    self._hit("certificate memory outside a handshake", conn,
                              where, f"at offset {i}: {w.hex()}")
                    break

            self.sentinel_hits += buf.count(self.sentinel)

            for s in self.file_strings:
                if s in buf:
                    self._hit("file content", conn, where, repr(s))

            # Any marker at all, from any connection. `mine` separates
            # "the server echoed my request" from "the server handed me
            # someone else's", which are different bugs.
            for m in re.finditer(re.escape(hw.MARKER_PREFIX) + rb"\d{6}", buf):
                got = m.group(0)
                self.markers_seen.add(got)
                mine = conn.marker == got
                self._hit("request marker echoed"
                          + ("" if mine else " FROM ANOTHER CONNECTION"),
                          conn, where, f"{got.decode()} at offset {m.start()}")


# ── the scanner's own test ──────────────────────────────────────────
def self_test(priv, cert):
    """Feed the scanner one synthetic response per needle and check that
    every check fires.

    Without this the suite has the failure mode every leak detector has:
    a scan that cannot find anything passes exactly like a server that
    leaks nothing, and the two look identical in the output. The
    campaigns above are the same shape — the run fails if the server
    returned no bytes at all — and this is that idea applied to the
    needles themselves.
    """
    cases = [
        ("private key (complete)", b"HTTP/1.1 200 OK\r\n\r\n" + priv),
        (f"private key ({WINDOW}-byte run)",
         b"body" + priv[8:8 + WINDOW] + b"more"),
        ("certificate memory outside a handshake",
         b"body" + cert[-32:-32 + WINDOW] + b"more"),
        ("file content", b"HTTP/1.1 200 OK\r\n\r\n-----BEGIN EC PRIVATE KEY"),
        ("request marker echoed",
         b"404 " + hw.MARKER_PREFIX + b"000042"),
    ]
    failed = 0
    for kind, payload in cases:
        sc = Scanner(priv, cert)
        conn = hw.Conn("self-test", hw.MARKER_PREFIX + b"000042")
        conn.raw += payload
        sc.scan(conn)
        kinds = {k for k, _c, _w, _d in sc.findings}
        if kind in kinds:
            print(f"OK: self-test — the scanner detects: {kind}")
        else:
            failed += 1
            print(f"FAIL: self-test — the scanner MISSED: {kind} "
                  f"(found {sorted(kinds) or 'nothing'})")

    # And the cross-connection variant, which is a different message.
    sc = Scanner(priv, cert)
    conn = hw.Conn("self-test", hw.MARKER_PREFIX + b"000042")
    conn.raw += b"404 " + hw.MARKER_PREFIX + b"000099"
    sc.scan(conn)
    if any("ANOTHER CONNECTION" in k for k, _c, _w, _d in sc.findings):
        print("OK: self-test — the scanner detects: another connection's marker")
    else:
        failed += 1
        print("FAIL: self-test — the scanner MISSED another connection's marker")

    # A clean response must produce nothing at all: a scanner that fires
    # on everything is as useless as one that fires on nothing.
    sc = Scanner(priv, cert)
    conn = hw.Conn("self-test", hw.MARKER_PREFIX + b"000042")
    conn.raw += b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    sc.scan(conn)
    if sc.findings:
        failed += 1
        print(f"FAIL: self-test — the scanner fired on a clean response: "
              f"{sc.findings}")
    else:
        print("OK: self-test — the scanner is silent on a clean response")
    return failed


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", type=int, nargs="?")
    ap.add_argument("--self-test", action="store_true",
                    help="check the scanner against synthetic leaks and exit")
    ap.add_argument("--cases", type=int, default=150)
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x5A524D)
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    priv, cert = parse_cert_data(CERT_DATA)
    if args.self_test:
        return 1 if self_test(priv, cert) else 0
    if args.port is None:
        ap.error("a port is required unless --self-test is given")
    sc = Scanner(priv, cert)

    tag = f" [{args.label}]" if args.label else ""

    replied = [0]

    def on_conn(conn):
        if conn.raw or conn.plain:
            replied[0] += 1
        sc.scan(conn)

    hw.run(args.port, cases=args.cases, seed=args.seed, on_conn=on_conn)

    # A run in which the server said nothing is a run that proves
    # nothing — the scan would pass on zero bytes. Vacuity check first.
    if sc.bytes_scanned == 0:
        print(f"FAIL:{tag} the server returned no bytes at all over "
              f"{sc.conns} connections — nothing was scanned")
        return 1
    print(f"OK:{tag} {sc.conns} hostile connections, {replied[0]} answered, "
          f"{sc.bytes_scanned} bytes captured and scanned")

    if sc.sentinel_hits == 0:
        print(f"FAIL:{tag} the probe never saw {sc.sentinel.decode()!r} in any "
              f"response — the capture path is not seeing real traffic, so a "
              f"clean scan below would mean nothing")
        return 1
    print(f"OK:{tag} the probe sees real response bytes "
          f"({sc.sentinel_hits} responses carried the server's own header)")

    # The needles come from src/tls/cert_data.S; the certificate the
    # server actually served comes from the same file. If they disagree,
    # the running binary was built from different key material and every
    # "the key never appeared" line below is about the wrong key.
    if not sc.certs_seen:
        print(f"FAIL:{tag} no TLS connection completed — the private key "
              f"was never even loaded, so the key checks below are vacuous")
        return 1
    if cert and sc.certs_seen != {cert}:
        print(f"FAIL:{tag} the server served a certificate that is not the one "
              f"in src/tls/cert_data.S — this binary was built from different "
              f"key material, so the key needles are the wrong ones")
        return 1
    print(f"OK:{tag} the server's certificate matches the build the needles "
          f"came from")

    groups = {}
    for kind, campaign, where, detail in sc.findings:
        groups.setdefault(kind, []).append((campaign, where, detail))

    checks = [
        ("private key (complete)", "the 32-byte private scalar never appears "
                                   "in any response"),
        (f"private key ({WINDOW}-byte run)",
         f"no {WINDOW}-byte run of the private scalar appears in any response"),
        ("certificate memory outside a handshake",
         "no certificate-adjacent memory appears outside the handshake"),
        ("file content", "no file content (PEM, passwd, executable header) "
                         "appears in any response"),
        ("request marker echoed", "no request bytes are echoed back"),
        ("request marker echoed FROM ANOTHER CONNECTION",
         "no connection sees another connection's request bytes"),
    ]

    failed = 0
    for kind, desc in checks:
        hits = groups.get(kind, [])
        if hits:
            failed += 1
            print(f"FAIL:{tag} {desc} — {len(hits)} hit(s)")
            for campaign, where, detail in hits[:5]:
                print(f"    {campaign} / {where}: {detail}")
        else:
            print(f"OK:{tag} {desc}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
