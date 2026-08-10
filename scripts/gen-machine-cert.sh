#!/usr/bin/env bash
# gen-machine-cert.sh — Generate a test machine (workstation) certificate and
# the CA that signs it, for exercising the proxy's [machine_identity] layer.
#
# Model:
#   With [machine_identity] enabled the proxy requires every request to carry a
#   machine certificate in the X-DenBrowser-Machine-Cert header (base64 DER),
#   verifies it against [machine_identity].machine_ca, and requires its Common
#   Name — the workstation's hostname — to forward-resolve to the address the
#   client connected from.  In production that certificate is provisioned onto
#   each workstation and the browser reads it at startup.  This script produces
#   that CA plus one signed machine cert so the test clients
#   (test/attestation/test_roundtrip.py and the proxy stress tester) can present
#   it exactly as a real browser would.
#
#   Unlike the user cert (gen-user-cert.sh), this certificate never enters a TLS
#   handshake: a handshake carries exactly one client chain and the user cert
#   already occupies it, which is why this identity rides a header instead.  It
#   therefore carries no clientAuth EKU.
#
#   NOTE: the header is a *bearer* claim — a certificate is a public document,
#   so this layer proves the name was issued by your CA and is being presented
#   from an address that name resolves to, NOT that the sender holds the private
#   key.  The key below exists only so the cert is well-formed; nothing signs
#   with it.
#
# Usage:
#   ./scripts/gen-machine-cert.sh                 # CN=$(hostname), 10y
#   ./scripts/gen-machine-cert.sh --cn ws-4417    # different workstation name
#   ./scripts/gen-machine-cert.sh --days 30       # shorter validity
#
# Output (all under build/, which is gitignored):
#   build/machine-ca.crt     ← CA cert; set [machine_identity].machine_ca to this
#   build/machine-ca.key     ← CA private key (signs machine certs; NEVER commit)
#   build/machine-cert.crt   ← machine cert (chains to the CA)
#   build/machine-cert.key   ← machine private key (NEVER commit)
#   build/machine-cert.pem   ← cert+key concatenated (convenience for some clients)
#
# SECURITY NOTES:
#   - All *.key files live under build/ and are gitignored; never commit them.
#   - This CA MUST be different from the mTLS user CA (gen-user-cert.sh).  The
#     browser tells the user cert apart from the machine cert by its issuer, and
#     the proxy refuses to start if the two CAs overlap.

set -euo pipefail

# Stop Git Bash / MSYS2 on Windows from rewriting a leading-"/" subject DN into a
# Windows path; a no-op on Linux/macOS.  Lets us use a plain "/CN=..." subject,
# which OpenSSL 3 parses correctly (a "//CN=..." guard silently drops the CN).
# NB: this also disables path translation for file arguments, so every openssl
# file path below is a *bare relative filename* run from inside build/ — bare
# names need no translation on any platform (a POSIX "/c/Users/..." path handed
# to a native-Windows openssl would otherwise fail to open).
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

# The CN *is* the hostname the proxy will resolve, so default to this machine's.
CN="$(hostname)"
CA_CN="DenBrowser Test Machine CA"
DAYS=3650

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cn)    CN="$2";    shift 2 ;;
        --ca-cn) CA_CN="$2"; shift 2 ;;
        --days)  DAYS="$2";  shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# The proxy lowercases the CN before matching allowed_hostnames and before
# resolving it, so emit it lowercase here too — otherwise the generated cert and
# the patterns an operator copies out of this output would disagree.
CN="$(printf '%s' "$CN" | tr '[:upper:]' '[:lower:]')"

mkdir -p "$BUILD_DIR"
# Operate from inside build/ so every openssl file argument is a bare filename
# (see the MSYS_NO_PATHCONV note above).  Paths shown to the user stay
# repo-root-relative ("build/...") since that is where the test commands run.
cd "$BUILD_DIR"

# ── 1. CA keypair + self-signed CA cert ──────────────────────────────────────
echo "[gen-machine-cert] Generating machine CA (CN=$CA_CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out machine-ca.key
chmod 600 machine-ca.key
openssl req -x509 -new -key machine-ca.key -days "$DAYS" \
    -subj "/CN=$CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out machine-ca.crt

# ── 2. Machine keypair + CSR ─────────────────────────────────────────────────
echo "[gen-machine-cert] Generating machine cert (CN=$CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out machine-cert.key
chmod 600 machine-cert.key
openssl req -new -key machine-cert.key -subj "/CN=$CN" -out machine-cert.csr

# ── 3. Sign the machine cert with the CA ─────────────────────────────────────
# No clientAuth EKU: this certificate is carried in a header, never presented in
# a TLS handshake.  A matching SAN DNS entry keeps the subject readable by the
# same extraction the mTLS layer uses.  A real temp extfile (not process
# substitution) keeps this working under Git Bash on Windows.
printf 'keyUsage=critical,digitalSignature\nsubjectAltName=DNS:%s\n' "$CN" > machine-cert.ext
openssl x509 -req -in machine-cert.csr -CA machine-ca.crt -CAkey machine-ca.key \
    -CAcreateserial -days "$DAYS" \
    -extfile machine-cert.ext \
    -out machine-cert.crt
rm -f machine-cert.csr machine-cert.ext

cat machine-cert.crt machine-cert.key > machine-cert.pem
chmod 600 machine-cert.pem

# ── 4. Summary ────────────────────────────────────────────────────────────────
cat <<EOF

[gen-machine-cert] Done.

  Machine CA cert : build/machine-ca.crt   ← set [machine_identity].machine_ca to this
  Machine CA key  : build/machine-ca.key   ← signs machine certs (NEVER commit)
  Machine cert    : build/machine-cert.crt (CN=$CN, chains to the CA)
  Machine key     : build/machine-cert.key (NEVER commit)
  Machine c+k     : build/machine-cert.pem

  Use it (from repo root):
    # proxy config (proxy/proxy.toml):
    #   [machine_identity]
    #   enabled    = true
    #   machine_ca = "build/machine-ca.crt"

    # direct-host roundtrip test (generate with --cn localhost):
    DENBROWSER_MACHINE_IDENTITY_ENABLED=1 \\
    DENBROWSER_MACHINE_CERT=build/machine-cert.crt \\
      python3 test/attestation/test_roundtrip.py

    # stress test:
    python3 proxy/stress/denbrowser_stress.py \\
      --machine-cert build/machine-cert.crt --insecure

  IMPORTANT — this CA must differ from build/user-ca.crt.  The proxy refuses to
  start if [mtls].client_ca and [machine_identity].machine_ca share a cert.

  IMPORTANT — the proxy also requires "$CN" to resolve to the address the client
  connects from. Use --cn localhost for a client running directly on the host,
  or --cn machine-client for test/minimal-proxy-stack's in-network Compose
  client.

  Windows browser integration (patch 024): generate with the workstation's
  real FQDN, DNS hostname, or NetBIOS name, then import the public certificate
  into a Personal store and restart DenBrowser:

    certutil -user -addstore My build\\machine-cert.crt   # CurrentUser\\MY
    certutil       -addstore My build\\machine-cert.crt   # LocalMachine\\MY (admin)

  The browser reads only the public DER; this protocol does not use or prove
  possession of the machine private key.
EOF
