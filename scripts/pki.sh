#!/bin/bash
# Local PKI for mTLS between stack components (R-07).
# One root CA issues a leaf per component. Idempotent: existing files are kept;
# REISSUE=1 replaces the leaf certificates and keys (the root CA is kept).
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
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"
  echo "issued root CA"
fi

# leaf <name> <extendedKeyUsage> [subjectAltName]
leaf() {
  local name=$1 eku=$2 san=${3:-}
  if [ "${REISSUE:-}" = "1" ]; then rm -f "$name.pem" "$name-key.pem"; fi
  [ -f "$name.pem" ] && return 0
  newkey "$name-key.pem"
  openssl req -new -key "$name-key.pem" -subj "$ORG/CN=$name" -out "$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=$eku"
    # RFC 5280 key identifiers; strict verifiers (Python 3.13+) reject leaves without an AKI.
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
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
# MISP web front end (Lab 6): clients verify it against the same root CA.
leaf misp "serverAuth" "DNS:misp,DNS:localhost,IP:127.0.0.1"
# Monitoring (Lab 7): every link is mTLS. "monitor" is the probe's client identity towards
# OpenSearch and Dashboards; it proves reachability and is granted no data (HTTP 401).
leaf monitor "clientAuth"
leaf prometheus "serverAuth,clientAuth" "DNS:prometheus,DNS:localhost,IP:127.0.0.1"
leaf alertmanager "serverAuth" "DNS:alertmanager,DNS:localhost,IP:127.0.0.1"
leaf blackbox "serverAuth" "DNS:blackbox,DNS:localhost,IP:127.0.0.1"

# Fail now, not at deploy time, if any leaf would be rejected by a strict RFC 5280 verifier.
openssl verify -x509_strict -CAfile root-ca.pem opensearch.pem dashboards.pem admin.pem misp.pem \
  monitor.pem prometheus.pem alertmanager.pem blackbox.pem >/dev/null

# Containers run as uid 1000; certificates are public, keys readable by owner and group.
chmod 644 ./*.pem
chmod 640 ./*-key.pem
chmod 600 root-ca-key.pem
