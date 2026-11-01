#!/bin/sh
# Private CA for the links between your own boxes: firewall agent -> portal ingest (mutual TLS),
# and Pi 5 Caddy -> Pi 4 portal (HTTPS). Run on your admin PC, then keep out/ingest-ca.key offline.
#
#   sh make-pki.sh 10.10.0.22          # the Pi 4's IP (portal + ingest)
#
# Produces in ./out:
#   ingest-ca.pem / ingest-ca.key   CA (key stays offline); ingest-ca.pem goes to the Pi 4, Pi 5 and firewall
#   services.crt / services.key     -> Pi 4 (portal :9443 and ingest :9444)
#   agent.crt / agent.key           -> firewall /usr/local/etc/fw-agent/
set -eu
SERVICES_IP=${1:?usage: make-pki.sh <pi4-ip>}
DAYS=825
cd "$(dirname "$0")"
mkdir -p out && cd out
umask 077

if [ ! -f ingest-ca.key ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -keyout ingest-ca.key -out ingest-ca.pem -subj "/CN=gateway-portal ingest CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

sign() { # name cn eku san
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n%s\n' "$3" "$4" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ingest-ca.pem -CAkey ingest-ca.key -CAcreateserial -days $DAYS -out "$1.crt" -extfile "$1.ext"
  rm -f "$1.csr" "$1.ext"
}

# serverAuth only: the server cert cannot be used to pose as the agent, and vice versa.
sign services "gateway-portal" serverAuth "subjectAltName=IP:$SERVICES_IP"
sign agent "fw-agent" clientAuth ""
chmod 644 ingest-ca.pem services.crt agent.crt
# The portal containers run as uid 10001 and must read this key; keep the Pi 4 itself locked down.
chmod 644 services.key
echo "Done. Copy agent.crt, agent.key, ingest-ca.pem to the firewall; move ingest-ca.key offline."
