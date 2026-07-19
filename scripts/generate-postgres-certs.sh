#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Generate the TLS material for the Blackbook <-> Postgres channel:
#   - a private CA
#   - a server certificate for Postgres (SANs cover the in-compose hostname
#     `postgres` and localhost/127.0.0.1 for host-side testing)
#
# Run once before `docker compose up`:
#     ./scripts/generate-postgres-certs.sh
#
# Output goes to secrets/postgres/ (gitignored). The app verifies the server
# against ca.crt (sslmode=verify-full), so the channel is encrypted AND the
# database server is authenticated — no passive sniffing or MITM on the Docker
# network. Keys are PKCS#8 EC (P-256) for broad client compatibility.
#
# Also generates a client certificate (CN = the app role) for mutual TLS: the
# app presents it and Postgres verifies it (clientcert=verify-full in pg_hba),
# so BOTH ends are cryptographically authenticated, on top of SCRAM.
# ---------------------------------------------------------------------------
set -euo pipefail

OUT="$(cd "$(dirname "$0")/.." && pwd)/secrets/postgres"
mkdir -p "$OUT"
cd "$OUT"
DAYS="${PG_CERT_DAYS:-825}"

gen_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

echo "Generating Postgres CA + server certificate in $OUT ..."

# 1) Certificate Authority
gen_key ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days "$DAYS" \
  -subj "/CN=Blackbook Postgres CA" 2>/dev/null

# 2) Server certificate (CA-signed), SANs for both deployment and local testing
gen_key server.key
openssl req -new -key server.key -out server.csr -subj "/CN=postgres" 2>/dev/null
cat > server.ext <<'EXT'
subjectAltName = DNS:postgres, DNS:blackbook-postgres, DNS:localhost, IP:127.0.0.1
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -extfile server.ext 2>/dev/null

# 3) Client certificate for mTLS. PostgreSQL's `clientcert=verify-full` requires
#    the certificate CN to equal the database role name, so CN MUST be the app
#    user. The app presents this cert; Postgres verifies it against the CA.
APP_USER="${DB_USER:-blackbook_app}"
gen_key client.key
openssl req -new -key client.key -out client.csr -subj "/CN=${APP_USER}" 2>/dev/null
cat > client.ext <<'EXT'
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "$DAYS" -extfile client.ext 2>/dev/null

chmod 600 ca.key server.key client.key
rm -f server.csr server.ext client.csr client.ext ca.srl
echo "Done. Files:"
ls -l "$OUT"
echo
echo "Next: ./scripts/generate-postgres-certs.sh has populated secrets/postgres/."
echo "The Postgres container mounts these read-only and a root entrypoint hook"
echo "installs them with postgres-owned 0600 perms; the app trusts ca.crt."
