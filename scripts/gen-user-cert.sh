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
#   it is a separate, orthogonal layer from those two.
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

CA_CRT="$BUILD_DIR/user-ca.crt"
CA_KEY="$BUILD_DIR/user-ca.key"
USER_CRT="$BUILD_DIR/user-cert.crt"
USER_KEY="$BUILD_DIR/user-cert.key"
USER_PEM="$BUILD_DIR/user-cert.pem"
USER_CSR="$BUILD_DIR/user-cert.csr"

# ── 1. CA keypair + self-signed CA cert ──────────────────────────────────────
echo "[gen-user-cert] Generating mTLS CA (CN=$CA_CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
chmod 600 "$CA_KEY"
openssl req -x509 -new -key "$CA_KEY" -days "$DAYS" \
    -subj "/CN=$CA_CN" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA_CRT"

# ── 2. User keypair + CSR ────────────────────────────────────────────────────
echo "[gen-user-cert] Generating user client cert (CN=$CN, ${DAYS}d)..."
openssl ecparam -name prime256v1 -genkey -noout -out "$USER_KEY"
chmod 600 "$USER_KEY"
openssl req -new -key "$USER_KEY" -subj "/CN=$CN" -out "$USER_CSR"

# ── 3. Sign the user cert with the CA ────────────────────────────────────────
# clientAuth EKU marks it as a client certificate, and a matching SAN DNS entry
# means both the CN and the SAN-DNS allowlist paths in passthrough.rs resolve to
# this identity.
openssl x509 -req -in "$USER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -CAcreateserial -days "$DAYS" \
    -extfile <(printf 'extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:%s\n' "$CN") \
    -out "$USER_CRT"
rm -f "$USER_CSR"

cat "$USER_CRT" "$USER_KEY" > "$USER_PEM"
chmod 600 "$USER_PEM"

# ── 4. Summary ────────────────────────────────────────────────────────────────
cat <<EOF

[gen-user-cert] Done.

  mTLS CA cert   : $CA_CRT   ← set [mtls].client_ca to this on the proxy
  mTLS CA key    : $CA_KEY   ← signs user certs (NEVER commit)
  User cert      : $USER_CRT (CN=$CN, chains to the CA)
  User key       : $USER_KEY (NEVER commit)
  User cert+key  : $USER_PEM

  Use it:
    # proxy config (proxy/proxy.toml):
    #   [mtls]
    #   enabled   = true
    #   client_ca = "build/user-ca.crt"

    # roundtrip test (from repo root):
    DENBROWSER_CLIENT_CERT=$USER_CRT \\
    DENBROWSER_CLIENT_KEY=$USER_KEY \\
      python3 test/attestation/test_roundtrip.py

    # stress test (from repo root):
    python3 proxy/stress/denbrowser_stress.py \\
      --client-cert $USER_CRT --client-key $USER_KEY --insecure

  For [proxy_bypass] testing, add "$CN" to allowed_subjects.
EOF
