#!/usr/bin/env bash
# Generate a tiny PKI for testing tiny-webdav:
#   ca.crt / ca.key         — the certificate authority
#   server.crt / server.key — the server's TLS identity (signed by the CA)
#   client.crt / client.key — a client's identity for mTLS (signed by the CA)
#
# The server presents server.crt and trusts ca.crt to verify client certs.
# The client presents client.crt/client.key and trusts ca.crt.
#
# Usage:  ./gen-certs.sh [output-dir] [server-hostname]
set -euo pipefail

OUT="${1:-certs}"
HOST="${2:-localhost}"
mkdir -p "$OUT"
cd "$OUT"

echo "==> Creating CA"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=tiny-webdav Test CA" -out ca.crt

echo "==> Creating server certificate for CN=${HOST}"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=${HOST}" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -out server.crt \
  -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" "$HOST")

echo "==> Creating client certificate for CN=test-client"
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=test-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -out client.crt \
  -extfile <(printf "extendedKeyUsage=clientAuth\n")

rm -f server.csr client.csr
echo
echo "Done. Files written to: $(pwd)"
ls -1
