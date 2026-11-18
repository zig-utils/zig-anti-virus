#!/bin/sh
# Generates the detached-signature fixtures used by src/compile/cvd_sign.zig tests:
#
#   sh src/compile/fixtures/make-sign.sh
#
# A TEST-ONLY three-level RSA chain (root, intermediate CA, leaf) signs fixtures/test.cvd the way
# Cisco signs CVDs: a detached PKCS#7 SignedData with SHA-256 signed attributes (contentType,
# signingTime, messageDigest), wrapped in the `#clamsign-1.0` text format. The keys are thrown
# away; only the signature file and the root's SubjectPublicKeyInfo SHA-256 are kept.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
cat > ext.cnf <<'CNF'
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
CNF
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 36500 -sha512 \
  -subj "/O=zav test/CN=zav test root" -extensions ca -config /dev/null 2>/dev/null ||
  openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 36500 -sha512 \
    -subj "/O=zav test/CN=zav test root" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "/O=zav test/CN=zav test sub" 2>/dev/null
openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -out sub.pem -days 36500 \
  -sha512 -extfile ext.cnf -extensions ca 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/O=zav test/CN=zav test release" 2>/dev/null
openssl x509 -req -in leaf.csr -CA sub.pem -CAkey sub.key -CAcreateserial -out leaf.pem -days 36500 \
  -sha512 -extfile ext.cnf -extensions leaf 2>/dev/null
cat sub.pem root.pem > chain.pem
openssl smime -sign -binary -md sha256 -in "$here/test.cvd" -signer leaf.pem -inkey leaf.key \
  -certfile chain.pem -outform DER -out test.p7
{
  printf '#clamsign-1.0\n'
  printf '230::pkcs7-pem:%s\n' "$(base64 < test.p7 | tr -d '\n')"
} > "$here/test.cvd.sign"
openssl x509 -in root.pem -noout -pubkey | openssl pkey -pubin -outform DER | shasum -a 256 | cut -c1-64 > "$here/test-root.pin"
echo "wrote test.cvd.sign and test-root.pin"
