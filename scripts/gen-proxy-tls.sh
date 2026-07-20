#!/usr/bin/env bash
# gen-proxy-tls.sh — Generate an attestation proxy's TLS server cert (or take
# the SPKI pin from an existing cert) so the browser build can pin that proxy
# and refuse to talk to any other TLS endpoint claiming to be it.
#
# Purpose:
#   Even with valid attestation, a local attacker on the same machine could
#   passively sniff outbound headers via a TUN device, WireGuard interface,
#   or libpcap.  When the browser pins a proxy's SPKI, that traffic is
#   inside TLS to a server only that proxy can speak as — so the captured
#   bytes are useless ciphertext.
#
# A deployment runs one proxy per partner application, each with its own cert,
# so run this once per proxy with a distinct --name:
#
#   # Fresh self-signed cert for development:
#   ./scripts/gen-proxy-tls.sh --name partner-a --host app.partner-a.example.com
#
#   # Existing production cert (internal CA, ACME, …):
#   ./scripts/gen-proxy-tls.sh --name partner-a \
#       --cert /path/to/server.crt --key /path/to/server.key
#
# Usage:
#   ./scripts/gen-proxy-tls.sh [--name NAME] [--host HOST]
#                              [--cert FILE --key FILE] [--force]
#
#   --name NAME   Label for this proxy.  Names the output files and should
#                 match the "name" of the proxy's entry in
#                 config/site-config.json.  Default: "proxy".
#   --host HOST   CN/SAN for a generated self-signed cert.  Default: localhost.
#   --cert/--key  Import an existing cert+key instead of generating one.
#   --force       Overwrite existing cert/key files for this name.
#
# Output:
#   build/<name>-tls.crt   ← the proxy's cert (Pingora reads it)
#   build/<name>-tls.key   ← the proxy's TLS private key
#
# This script does NOT modify the Firefox source tree.  The pin reaches the
# binary through config/site-config.json: the proxy's entry names either the
# cert file ("tls_cert") or the hash itself ("tls_spki_sha256"), and build.sh
# Step 2.5 generates the compiled-in proxy table from that.  One writer for the
# table means what is compiled in always matches what is committed.
#
# SECURITY NOTES:
#   - build/ is gitignored; never commit *-tls.key.
#   - Rotating a cert requires rebuilding DenBrowser so the pin matches.
#     This is intentional — it ties the browser binary to a specific server
#     identity, the way HPKP would for a website.  Rotating one partner's cert
#     does not disturb the other proxies' pins.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

NAME="proxy"
PROXY_HOST="localhost"
CERT_IN=""
KEY_IN=""
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)  NAME="$2";       shift 2 ;;
        --host)  PROXY_HOST="$2"; shift 2 ;;
        --cert)  CERT_IN="$2";    shift 2 ;;
        --key)   KEY_IN="$2";     shift 2 ;;
        --force) FORCE=1;         shift ;;
        -h|--help)
            echo "Usage: $0 [--name NAME] [--host HOST] [--cert FILE --key FILE] [--force]"
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# The name lands in the output filenames and in the site-config entry that
# refers to them; keep it to characters that are safe in both.
if [[ ! "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo "[gen-proxy-tls] ERROR: --name must be letters/digits/._- : $NAME" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"
CERT_OUT="$BUILD_DIR/$NAME-tls.crt"
KEY_OUT="$BUILD_DIR/$NAME-tls.key"

if [[ ( -f "$CERT_OUT" || -f "$KEY_OUT" ) && $FORCE -eq 0 ]]; then
    echo "[gen-proxy-tls] ERROR: $NAME-tls.{crt,key} already exist in build/." >&2
    echo "[gen-proxy-tls]        Replacing a cert invalidates the pin in every" >&2
    echo "[gen-proxy-tls]        build carrying the old one, so those builds stop" >&2
    echo "[gen-proxy-tls]        connecting to this proxy until they are rebuilt." >&2
    echo "[gen-proxy-tls]        Re-run with --force, or pick another --name." >&2
    exit 1
fi

# ── 1. Either generate a fresh self-signed cert or import the supplied one ──
if [[ -n "$CERT_IN" || -n "$KEY_IN" ]]; then
    [[ -n "$CERT_IN" && -n "$KEY_IN" ]] || {
        echo "[gen-proxy-tls] --cert and --key must be supplied together" >&2
        exit 1
    }
    echo "[gen-proxy-tls] Importing existing cert for \"$NAME\": $CERT_IN"
    cp "$CERT_IN" "$CERT_OUT"
    cp "$KEY_IN"  "$KEY_OUT"
    chmod 600    "$KEY_OUT"
else
    echo "[gen-proxy-tls] Generating self-signed cert for \"$NAME\" (CN=$PROXY_HOST, 10y)..."
    # The "//CN=..." double-slash stops Git Bash on Windows from mangling the
    # subject DN into a Windows path. OpenSSL tolerates the empty leading
    # component, and Linux/macOS treat // identically to /.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "//CN=$PROXY_HOST" \
        -addext "subjectAltName=DNS:$PROXY_HOST" \
        -keyout "$KEY_OUT" -out "$CERT_OUT"
    chmod 600 "$KEY_OUT"
fi

# ── 2. Extract SPKI sha256 (RFC 7469 style) ───────────────────────────────────
SPKI_HASH_HEX=$(openssl x509 -in "$CERT_OUT" -pubkey -noout \
                | openssl pkey -pubin -outform DER 2>/dev/null \
                | openssl dgst -sha256 -binary \
                | xxd -p -c 256)

SPKI_HASH_B64=$(openssl x509 -in "$CERT_OUT" -pubkey -noout \
                | openssl pkey -pubin -outform DER 2>/dev/null \
                | openssl dgst -sha256 -binary \
                | openssl base64)

echo "[gen-proxy-tls] SPKI sha256 (hex)    : $SPKI_HASH_HEX"
echo "[gen-proxy-tls] SPKI sha256 (base64) : $SPKI_HASH_B64"

cat <<EOF

[gen-proxy-tls] Done.

  Proxy TLS cert : $CERT_OUT
  Proxy TLS key  : $KEY_OUT  (NEVER commit)
  Cert hostname  : $PROXY_HOST
  SPKI pin       : $SPKI_HASH_B64

  Next steps:
    1. Reference this proxy in config/site-config.json.  Either point at the
       cert file and let the build hash it:

         { "name":       "$NAME",
           "domains":    ["$PROXY_HOST"],
           "attest_key": "$NAME-public.der",
           "tls_cert":   "$NAME-tls.crt" }

       …or, when the cert is not on the build host, paste the hash instead:

         { "name":       "$NAME",
           "domains":    ["$PROXY_HOST"],
           "attest_key": "$NAME-public.der",
           "tls_spki_sha256": "$SPKI_HASH_HEX" }

       "domains" is every hostname this proxy fronts; the pin applies to
       exactly those hosts and nothing else.

    2. Rebuild DenBrowser — build.sh bakes the pin into the proxy table.
    3. Restart the "$NAME" proxy with this cert/key
       (--cert/--tls-key, or DENBROWSER_TLS_CERT/DENBROWSER_TLS_KEY).
    4. Any older build, or any TLS endpoint not presenting this exact
       public key, will fail the handshake before any request is sent.
EOF
