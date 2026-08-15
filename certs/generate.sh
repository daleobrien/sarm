#!/bin/sh
# generate.sh — (re)generate the ymawky TLS 1.3 test certificates.
#
# Produces (in this directory):
#   key.pem   — EC P-256 (secp256r1) private key, chmod 600
#   cert.pem  — self-signed cert, ecdsa-with-SHA256, SANs localhost/127.0.0.1/::1
#   cert.der  — DER form of cert.pem
#
# The key type and signature scheme must match what the ymawky TLS 1.3
# implementation supports (see src/defs.S):
#   - cipher suite      TLS_AES_128_GCM_SHA256 (0x1301)
#   - signature scheme  ecdsa_secp256r1_sha256 (0x0403)
#   - cert named group  secp256r1 (0x0017)
# An RSA certificate would NOT work — the server can only sign
# CertificateVerify with an ECDSA P-256 key.
#
# Usage: ./generate.sh [-f]
#   -f   overwrite existing key.pem / cert.pem / cert.der
#   (without -f, refuses to clobber existing files)
#
# Requires OpenSSL 3.x: `genpkey -algorithm EC` and `-addext` are 3.x features.

set -eu
cd "$(dirname "$0")"

DAYS=3650
CURVE=P-256
CN=/CN=localhost
SAN="subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
KEYUSAGE="keyUsage=critical,digitalSignature"
EKUSAGE="extendedKeyUsage=serverAuth"

FORCE=0
if [ "${1:-}" = "-f" ]; then
	FORCE=1
fi

clobber() {
	if [ "$FORCE" = 1 ]; then
		return 0
	fi
	[ -e "$1" ] && { echo "error: $1 exists (use -f to overwrite)" >&2; exit 1; }
	return 0
}

clobber key.pem
clobber cert.pem
clobber cert.der

echo "==> generating EC P-256 private key (key.pem)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$CURVE -out key.pem
chmod 600 key.pem

echo "==> generating self-signed certificate (cert.pem)"
openssl req -new -x509 -key key.pem -sha256 -days $DAYS -subj "$CN" \
	-addext "$SAN" \
	-addext "$KEYUSAGE" \
	-addext "$EKUSAGE" \
	-out cert.pem

echo "==> exporting DER form (cert.der)"
openssl x509 -in cert.pem -outform der -out cert.der

echo "==> done:"
ls -l key.pem cert.pem cert.der
