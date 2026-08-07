#!/usr/bin/env bash
# gen-user-cert.sh — Generate a test mTLS user (browser client) certificate and
# the CA that signs it, for exercising the proxy's [mtls] client-authentication
# layer (and, optionally, [proxy_bypass]).
#
# Model:
#   With [mtls] enabled the proxy requires every client to present a *client*
#   certificate during the TLS handshake and verifies it against a CA configured
#   as [mtls].client_ca.  In production that certificate is provisioned into each
#   DenBrowser user's cert store; the browser presents it automatically.  This
#   script produces that CA plus one signed user cert so the test clients
#   (test/attestation/test_roundtrip.py and the proxy stress tester) can present
#   it exactly as a real browser would.
#
#   Unlike the attestation public key (gen-attest-key.sh) and the TLS SPKI pin
#   (gen-proxy-tls.sh), nothing here is baked into the browser build — this is
#   test/deployment material only.  mTLS authenticates the *user* to the proxy;
#   it is a separate, orthogonal layer from those two, and from the machine
#   certificate (gen-machine-cert.sh) that names the workstation.
#
# Usage:
#   ./scripts/gen-user-cert.sh                 # CN=denbrowser-user, 10y
#   ./scripts/gen-user-cert.sh --cn alice      # different user subject
#   ./scripts/gen-user-cert.sh --days 30       # shorter validity
#
# Output (all under build/, which is gitignored):
#   build/user-ca.crt     ← CA cert; set [mtls].client_ca to this on the proxy
#   build/user-ca.key     ← CA private key (signs user certs; NEVER commit)
#   build/user-cert.crt   ← user/browser client cert (chains to the CA)
#   build/user-cert.key   ← user client private key (NEVER commit)
#   build/user-cert.pem   ← cert+key concatenated (convenience for some clients)
#
# SECURITY NOTES:
#   - All *.key files live under build/ and are gitignored; never commit them.
#   - This CA authenticates users to the proxy.  It is independent of the proxy
#     TLS server cert (gen-proxy-tls.sh) and the attestation keypair
#     (gen-attest-key.sh).

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

CN="denbrowser-user"
CA_CN="DenBrowser Test User CA"
DAYS=3650

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cn)    CN="$2";    shift 2 ;;
        --ca-cn) CA_CN="$2"; shift 2 ;;
        --days)  DAYS="$2";  shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$BUILD_DIR"
# Operate from inside build/ so every openssl file argument is a bare filename
# (see the MSYS_NO_PATHCONV note above).  Paths shown to the user stay
# repo-root-relative ("build/...") since that is where the test commands run.
cd "$BUILD_DIR"

# ── 1. CA keypair + self-signed CA cert ──────────────────────────────────────
echo "[gen-user-cert] Generating mTLS CA (CN=$CA_CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out user-ca.key
chmod 600 user-ca.key
openssl req -x509 -new -key user-ca.key -days "$DAYS" \
    -subj "/CN=$CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out user-ca.crt

# ── 2. User keypair + CSR ────────────────────────────────────────────────────
echo "[gen-user-cert] Generating user client cert (CN=$CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out user-cert.key
chmod 600 user-cert.key
openssl req -new -key user-cert.key -subj "/CN=$CN" -out user-cert.csr

# ── 3. Sign the user cert with the CA ────────────────────────────────────────
# clientAuth EKU marks it as a client certificate, and a matching SAN DNS entry
# means both the CN and the SAN-DNS allowlist paths in passthrough.rs resolve to
# this identity.  A real temp extfile (not process substitution) keeps this
# working under Git Bash on Windows.
printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:%s\n' "$CN" > user-cert.ext
openssl x509 -req -in user-cert.csr -CA user-ca.crt -CAkey user-ca.key \
    -CAcreateserial -days "$DAYS" \
    -extfile user-cert.ext \
    -out user-cert.crt
rm -f user-cert.csr user-cert.ext

cat user-cert.crt user-cert.key > user-cert.pem
chmod 600 user-cert.pem

# ── 4. Summary ────────────────────────────────────────────────────────────────
cat <<EOF

[gen-user-cert] Done.

  mTLS CA cert   : build/user-ca.crt   ← set [mtls].client_ca to this on the proxy
  mTLS CA key    : build/user-ca.key   ← signs user certs (NEVER commit)
  User cert      : build/user-cert.crt (CN=$CN, chains to the CA)
  User key       : build/user-cert.key (NEVER commit)
  User cert+key  : build/user-cert.pem

  Use it (from repo root):
    # proxy config (proxy/proxy.toml):
    #   [mtls]
    #   enabled   = true
    #   client_ca = "build/user-ca.crt"

    # roundtrip test:
    DENBROWSER_CLIENT_CERT=build/user-cert.crt \\
    DENBROWSER_CLIENT_KEY=build/user-cert.key \\
      python3 test/attestation/test_roundtrip.py

    # stress test:
    python3 proxy/stress/denbrowser_stress.py \\
      --client-cert build/user-cert.crt --client-key build/user-cert.key --insecure

  For [proxy_bypass] testing, add "$CN" to allowed_subjects.
EOF
