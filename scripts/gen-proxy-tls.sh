#!/usr/bin/env bash
# gen-proxy-tls.sh — Generate the DenBrowser proxy's TLS server cert (or refresh
# the SPKI pin from an existing cert) and patch the pin into the browser
# source so the next build refuses to talk to any other TLS endpoint claiming
# to be the proxy.
#
# Purpose:
#   Even with valid attestation, a local attacker on the same machine could
#   passively sniff outbound headers via a TUN device, WireGuard interface,
#   or libpcap.  When the browser pins the proxy's SPKI, that traffic is
#   inside TLS to a server only the proxy can speak as — so the captured
#   bytes are useless ciphertext.
#
# Usage:
#   # Generate a fresh self-signed cert (development):
#   ./scripts/gen-proxy-tls.sh
#
#   # Use an existing production cert (e.g., from an internal CA or ACME):
#   ./scripts/gen-proxy-tls.sh --cert /path/to/server.crt --key /path/to/server.key
#
#   # Override the hostname baked into the pin:
#   ./scripts/gen-proxy-tls.sh --host proxy.internal.example.com
#
# Output:
#   build/proxy-tls.crt        ← the proxy's cert (kept; Pingora reads it)
#   build/proxy-tls.key        ← the proxy's TLS private key
#
# Side-effect:
#   Patches kProxyHost[] and kProxySpkiSha256[] in
#   netwerk/base/DenBrowserAttest.cpp between the REPLACE TLS PIN markers.
#
# SECURITY NOTES:
#   - build/proxy-tls.key is gitignored; never commit it.
#   - Rotating the cert requires rebuilding DenBrowser so the pin matches.
#     This is intentional — it ties the browser binary to a specific server
#     identity, the way HPKP would for a website.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

PROXY_HOST="localhost"
CERT_IN=""
KEY_IN=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)  PROXY_HOST="$2"; shift 2 ;;
        --cert)  CERT_IN="$2";    shift 2 ;;
        --key)   KEY_IN="$2";     shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$BUILD_DIR"
CERT_OUT="$BUILD_DIR/proxy-tls.crt"
KEY_OUT="$BUILD_DIR/proxy-tls.key"

# ── 1. Either generate a fresh self-signed cert or import the supplied one ──
if [[ -n "$CERT_IN" || -n "$KEY_IN" ]]; then
    [[ -n "$CERT_IN" && -n "$KEY_IN" ]] || {
        echo "[gen-proxy-tls] --cert and --key must be supplied together" >&2
        exit 1
    }
    echo "[gen-proxy-tls] Importing existing cert: $CERT_IN"
    cp "$CERT_IN" "$CERT_OUT"
    cp "$KEY_IN"  "$KEY_OUT"
    chmod 600    "$KEY_OUT"
else
    echo "[gen-proxy-tls] Generating self-signed cert for CN=$PROXY_HOST (10y)..."
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

# ── 3. Build the C array body for kProxySpkiSha256[] ──────────────────────────
SPKI_C_BYTES=$(echo "$SPKI_HASH_HEX" | fold -w2 \
               | awk '{printf "0x%s, ", $1}' \
               | sed 's/, $//' \
               | fold -s -w 60 \
               | sed 's/^/  /')

# ── 4. Patch DenBrowserAttest.cpp if the source tree is available ────────────────
if [[ -f "$ROOT_DIR/src/.esr_version" ]]; then
    ESR_VER=$(cat "$ROOT_DIR/src/.esr_version" | sed 's/esr//')
    ATTEST_CPP="$ROOT_DIR/src/firefox-${ESR_VER}/netwerk/base/DenBrowserAttest.cpp"
else
    ATTEST_CPP=""
fi

if [[ -n "$ATTEST_CPP" && -f "$ATTEST_CPP" ]]; then
    echo "[gen-proxy-tls] Patching kProxyHost / kProxySpkiSha256 in DenBrowserAttest.cpp..."
    python3 - "$ATTEST_CPP" "$PROXY_HOST" "$SPKI_C_BYTES" <<'PYEOF'
import sys, re

cpp_path, host, spki_c = sys.argv[1], sys.argv[2], sys.argv[3]

with open(cpp_path, encoding="utf-8") as f:
    src = f.read()

new_block = (
    "// ── REPLACE TLS PIN: gen-proxy-tls.sh updates these ─────────────────────\n"
    f'static const char kProxyHost[] = "{host}";\n'
    "static const uint8_t kProxySpkiSha256[32] = {\n"
    f"{spki_c}\n"
    "};\n"
    "// ── END REPLACE TLS PIN ──────────────────────────────────────────────────"
)

pattern = re.compile(
    r"// ── REPLACE TLS PIN:.*?// ── END REPLACE TLS PIN ─+",
    re.DOTALL,
)

new_src, n = pattern.subn(new_block, src)
if n != 1:
    print("ERROR: REPLACE TLS PIN markers not found in", cpp_path, file=sys.stderr)
    sys.exit(1)

with open(cpp_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(new_src)
print(f"  Updated {cpp_path}")
PYEOF
else
    echo "[gen-proxy-tls] Source tree not found; paste manually into DenBrowserAttest.cpp:"
    echo ""
    echo "  static const char kProxyHost[] = \"$PROXY_HOST\";"
    echo "  static const uint8_t kProxySpkiSha256[32] = {"
    echo "$SPKI_C_BYTES"
    echo "  };"
    echo ""
fi

cat <<EOF

[gen-proxy-tls] Done.

  Proxy TLS cert : $CERT_OUT
  Proxy TLS key  : $KEY_OUT  (NEVER commit)
  Pinned host    : $PROXY_HOST
  Pinned SPKI    : $SPKI_HASH_B64

  Next steps:
    1. Rebuild DenBrowser (the pin is now baked into the binary).
    2. Restart the proxy — it will load the new cert/key automatically.
    3. Any older build, or any TLS endpoint not presenting this exact
       public key, will fail the handshake before any request is sent.
EOF
