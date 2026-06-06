#!/usr/bin/env bash
# Generates a self-signed cert valid for "localhost", weak (sha1, 1024-bit RSA),
# expiring in 10 days, into $TMPDIR/ps-test-cert.{pem,key}.
set -e
DIR="${TMPDIR:-/tmp}"
CRT="$DIR/ps-test-cert.pem"
KEY="$DIR/ps-test-cert.key"

openssl req -x509 -nodes \
    -newkey rsa:1024 \
    -days 10 \
    -sha1 \
    -subj "/CN=localhost" \
    -keyout "$KEY" -out "$CRT" 2>/dev/null

echo "$CRT $KEY"
