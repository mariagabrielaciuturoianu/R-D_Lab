#!/bin/bash
# Local PKI for mTLS between stack components (R-07).
# One root CA issues a leaf per component. Idempotent: existing files are kept.
# Everything lands in certs/, which git ignores; private keys never leave this machine.
set -euo pipefail

DIR="${1:-certs}"
DAYS_CA=730
DAYS_LEAF=365
ORG="/O=RDLab/OU=SOC"

mkdir -p "$DIR"
cd "$DIR"
umask 077

# PKCS#8 RSA keys: the OpenSearch security plugin rejects PKCS#1.
newkey() { openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1"; }

if [ ! -f root-ca.pem ]; then
  newkey root-ca-key.pem
  openssl req -x509 -new -key root-ca-key.pem -sha256 -days "$DAYS_CA" \
    -subj "$ORG/CN=RDLab Root CA" -out root-ca.pem \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "issued root CA"
fi

# leaf <name> <extendedKeyUsage> [subjectAltName]
leaf() {
  local name=$1 eku=$2 san=${3:-}
  [ -f "$name.pem" ] && return 0
  newkey "$name-key.pem"
  openssl req -new -key "$name-key.pem" -subj "$ORG/CN=$name" -out "$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$eku"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca-key.pem \
    -CAcreateserial -days "$DAYS_LEAF" -sha256 -extfile "$name.ext" -out "$name.pem"
  rm -f "$name.csr" "$name.ext"
  echo "issued $name"
}

# Node cert: serves HTTPS and authenticates on the transport layer (nodes_dn).
leaf opensearch "serverAuth,clientAuth" "DNS:opensearch,DNS:localhost,IP:127.0.0.1"
# Dashboards: serves its own HTTPS and presents a client cert to OpenSearch (mTLS).
leaf dashboards "serverAuth,clientAuth" "DNS:dashboards,DNS:localhost,IP:127.0.0.1"
# Operator client cert for health checks and the security admin DN.
leaf admin "clientAuth"

# Containers run as uid 1000; certificates are public, keys readable by owner and group.
chmod 644 ./*.pem
chmod 640 ./*-key.pem
chmod 600 root-ca-key.pem
