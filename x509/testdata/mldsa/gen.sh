#!/usr/bin/env bash
# Regenerates the ML-DSA test certificates with OpenSSL 3.5 or later, an ML-DSA
# implementation independent of Go's crypto/mldsa. Run from this directory.
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Self-signed roots, one per parameter set.
for n in 44 65 87; do
	openssl req -x509 -newkey "ML-DSA-$n" -keyout "$tmp/root-$n.key" -nodes \
		-subj "/CN=ML-DSA-$n Root" -days 36500 \
		-addext basicConstraints=critical,CA:TRUE \
		-addext keyUsage=critical,keyCertSign,cRLSign \
		-out "mldsa-$n-root.pem"
done

# An ML-DSA-44 leaf issued by the ML-DSA-65 root, so the certificate's
# signature algorithm (ML-DSA-65) differs from its own key's (ML-DSA-44).
openssl req -new -newkey ML-DSA-44 -keyout "$tmp/leaf.key" -nodes \
	-subj "/CN=leaf.test" -out "$tmp/leaf.csr"
openssl x509 -req -in "$tmp/leaf.csr" -CA mldsa-65-root.pem -CAkey "$tmp/root-65.key" \
	-days 36500 -set_serial 2 -extfile <(printf 'subjectAltName=DNS:leaf.test\n') \
	-out mldsa-44-leaf.pem

# The ML-DSA-65 root with one signature byte flipped. The signature is the last
# field of the certificate, so flipping the final byte leaves the DER valid.
openssl x509 -in mldsa-65-root.pem -outform DER -out "$tmp/root-65.der"
python3 - "$tmp/root-65.der" "$tmp/bad.der" <<'EOF'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[-1] ^= 0x01
open(sys.argv[2], "wb").write(b)
EOF
openssl x509 -inform DER -in "$tmp/bad.der" -out mldsa-65-root-invalid-sig.pem
