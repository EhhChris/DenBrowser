#!/usr/bin/env bash
# gen-attest-key.sh — Generate a DenBrowser browser-attestation keypair.
#
# Key model:
#   Private key  → stays on the proxy (copy to your gateway config)
#   Public key   → embedded in the DenBrowser browser build (not secret)
#
# A deployment runs one attestation proxy per partner application, each with
# its own keypair, so run this once per proxy with a distinct --name:
#
#   ./scripts/gen-attest-key.sh                    # name defaults to "proxy"
#   ./scripts/gen-attest-key.sh --name partner-a
#   ./scripts/gen-attest-key.sh --name partner-b
#
# Usage:  ./scripts/gen-attest-key.sh [--name NAME] [--force]
#
#   --name NAME   Label for this proxy.  Names the output files and should
#                 match the "name" of the proxy's entry in
#                 config/site-config.json.  Default: "proxy".
#   --force       Overwrite an existing private key for this name.  Refused by
#                 default: regenerating a deployed key revokes every build that
#                 embeds its public half.
#
# Output:
#   build/<name>-private.pem  — EC P-256 private key  (deploy to that proxy)
#   build/<name>-public.pem   — matching public key   (not secret)
#   build/<name>-public.der   — public key in DER form (baked into the build)
#
# This script does NOT modify the Firefox source tree.  The public key reaches
# the binary through config/site-config.json: add (or update) a "proxies" entry
# naming the .der, and build.sh Step 2.5 generates the compiled-in proxy table
# from it.  That keeps one writer for the table and keeps what is compiled in
# matching what is committed.
#
# Workflow for each new DenBrowser release:
#   1. Run this script for each proxy.
#   2. Point that proxy's "attest_key" in config/site-config.json at the new
#      build/<name>-public.der (unchanged if the name is the same).
#   3. Rebuild DenBrowser (public keys are now baked in).
#   4. Copy each build/<name>-private.pem to its proxy and reload.
#   5. The old build's tokens will no longer decrypt correctly once the proxies
#      are updated — old builds are effectively revoked.
#
# SECURITY NOTES:
#   - Never commit *-private.pem.  build/ is gitignored.
#   - Treat each proxy private key like any other TLS private key.
#   - The public keys in the build are not secret; embedding them in the binary
#     gives attackers nothing useful (they cannot forge tokens without the
#     proxy private key to complete ECDH on the other side).
#   - Keys are per proxy on purpose: one partner can never verify — or mint —
#     another partner's tokens.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

NAME="proxy"
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)  NAME="$2"; shift 2 ;;
        --force) FORCE=1;   shift ;;
        -h|--help)
            echo "Usage: $0 [--name NAME] [--force]"
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# The name lands in a C string literal in the generated proxy table and in the
# output filenames; keep it to characters that are safe in both.
if [[ ! "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "[gen-attest-key] ERROR: --name must be letters/digits/._- : $NAME" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

PRIV="$BUILD_DIR/$NAME-private.pem"
PUB_PEM="$BUILD_DIR/$NAME-public.pem"
PUB_DER="$BUILD_DIR/$NAME-public.der"

if [[ -f "$PRIV" && $FORCE -eq 0 ]]; then
    echo "[gen-attest-key] ERROR: $PRIV already exists." >&2
    echo "[gen-attest-key]        Overwriting it revokes every build carrying the" >&2
    echo "[gen-attest-key]        matching public key.  Re-run with --force if that" >&2
    echo "[gen-attest-key]        is what you want, or pick another --name." >&2
    exit 1
fi

# ── 1. Generate EC P-256 keypair ─────────────────────────────────────────────
echo "[gen-attest-key] Generating EC P-256 keypair for \"$NAME\"..."
openssl ecparam -genkey -name prime256v1 -noout -out "$PRIV"
chmod 600 "$PRIV"

# ── 2. Extract public key (PEM + DER) ────────────────────────────────────────
echo "[gen-attest-key] Extracting public key..."
openssl ec -in "$PRIV" -pubout -out "$PUB_PEM"
openssl ec -in "$PRIV" -pubout -outform DER -out "$PUB_DER"

KEY_SIZE=$(wc -c < "$PUB_DER" | tr -d ' ')
echo "[gen-attest-key] Public key DER: $KEY_SIZE bytes"

# ── 3. Summary ────────────────────────────────────────────────────────────────
cat <<EOF

[gen-attest-key] Done.

  Proxy private key : $PRIV  ← deploy to the "$NAME" proxy
  Proxy public key  : $PUB_PEM   ← not secret
  Public key DER    : $PUB_DER   ← baked into the build

  Next steps:
    1. Add or update this proxy in config/site-config.json:

         "proxies": [
           { "name":       "$NAME",
             "domains":    ["app.example.com"],
             "attest_key": "$NAME-public.der",
             "tls_cert":   "$NAME-tls.crt" }
         ]

       "domains" is every hostname this proxy fronts (subdomains included
       automatically).  There is no wildcard: hosts no proxy claims are sent
       without attestation headers.  Generate the TLS cert referenced above
       with:  ./scripts/gen-proxy-tls.sh --name $NAME

    2. Rebuild DenBrowser — build.sh regenerates the compiled-in proxy table.
    3. Copy $NAME-private.pem to the "$NAME" proxy and reload it
       (proxy --key, or DENBROWSER_KEY).
    4. Distribute the new DenBrowser build.
    5. Old builds are now revoked for this proxy — the new private key means
       their tokens cannot be decrypted.

  NEVER commit $NAME-private.pem to version control.
EOF
