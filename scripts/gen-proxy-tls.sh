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
#   ./scripts/gen-proxy-tls.sh [--name NAME] [--host HOST] [--san HOST]
#                              [--cert FILE --key FILE] [--force]
#
#   --name NAME   Label for this proxy.  Names the output files and should
#                 match the "name" of the proxy's entry in
#                 config/site-config.json.  Default: "proxy".
#   --host HOST   CN/SAN for a generated self-signed cert.  Default: localhost.
#   --san HOST    Additional DNS SAN for a generated certificate. Repeatable;
#                 useful when the same development proxy is reached by both a
#                 host name and a Compose service name.
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

NAME="proxy"
PROXY_HOST="localhost"
CERT_IN=""
KEY_IN=""
EXTRA_SANS=()
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)  NAME="$2";       shift 2 ;;
        --host)  PROXY_HOST="$2"; shift 2 ;;
        --san)   EXTRA_SANS+=("$2"); shift 2 ;;
        --cert)  CERT_IN="$2";    shift 2 ;;
        --key)   KEY_IN="$2";     shift 2 ;;
        --force) FORCE=1;         shift ;;
        -h|--help)
            echo "Usage: $0 [--name NAME] [--host HOST] [--san HOST] [--cert FILE --key FILE] [--force]"
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
# Bare filenames for the openssl calls below, which run from inside build/ (see
# the MSYS_NO_PATHCONV note above).  The absolute forms stay for messages and
# for `cp`, which is an MSYS program and handles POSIX paths on its own.
CERT_FILE="$NAME-tls.crt"
KEY_FILE="$NAME-tls.key"

# Resolve any supplied import paths before changing directory, so a relative
# --cert/--key still refers to where the user ran this from.  Left untouched
# when the file is missing, so `cp` reports it rather than a `cd` failure.
[[ -f "$CERT_IN" ]] && CERT_IN="$(cd "$(dirname "$CERT_IN")" && pwd)/$(basename "$CERT_IN")"
[[ -f "$KEY_IN"  ]] && KEY_IN="$(cd "$(dirname "$KEY_IN")" && pwd)/$(basename "$KEY_IN")"

if [[ ( -f "$CERT_OUT" || -f "$KEY_OUT" ) && $FORCE -eq 0 ]]; then
    echo "[gen-proxy-tls] ERROR: $NAME-tls.{crt,key} already exist in build/." >&2
    echo "[gen-proxy-tls]        Replacing a cert invalidates the pin in every" >&2
    echo "[gen-proxy-tls]        build carrying the old one, so those builds stop" >&2
    echo "[gen-proxy-tls]        connecting to this proxy until they are rebuilt." >&2
    echo "[gen-proxy-tls]        Re-run with --force, or pick another --name." >&2
    exit 1
fi

# Operate from inside build/ so every openssl file argument is a bare filename
# (see the MSYS_NO_PATHCONV note above).
cd "$BUILD_DIR"

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
    # Single-slash subject: OpenSSL 3 reads "//CN=..." as an empty leading RDN
    # followed by an unknown "/CN" attribute, warns, and silently drops the CN —
    # producing a cert with no subject at all.  MSYS_NO_PATHCONV (set at the top)
    # is what makes the plain "/CN=..." form safe under Git Bash.
    SAN_LIST="DNS:$PROXY_HOST"
    for san in "${EXTRA_SANS[@]}"; do
        SAN_LIST+=",DNS:$san"
    done
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=$PROXY_HOST" \
        -addext "subjectAltName=$SAN_LIST" \
        -keyout "$KEY_FILE" -out "$CERT_FILE"
    chmod 600 "$KEY_FILE"
fi

# Guard against silently shipping a subject-less cert again: the pin would still
# be computed and the proxy would still serve, but clients could not use the
# cert as a CA file and the identity it is supposed to assert would be missing.
if ! openssl x509 -in "$CERT_FILE" -noout -subject | grep -q 'CN *='; then
    echo "[gen-proxy-tls] ERROR: $CERT_FILE has no Common Name in its subject." >&2
    echo "[gen-proxy-tls]        Refusing to report a pin for an unusable cert." >&2
    exit 1
fi

# ── 2. Extract SPKI sha256 (RFC 7469 style) ───────────────────────────────────
# `od` rather than `xxd`: xxd ships with vim, not coreutils, so it is absent on
# plenty of minimal Linux images and on a stock macOS without developer tools.
# Under `set -euo pipefail` that killed this script *after* writing the cert and
# key but *before* printing the pin, leaving a usable cert and no way to pin it.
# `-v` stops od from collapsing repeated bytes into a "*" line.
SPKI_HASH_HEX=$(openssl x509 -in "$CERT_FILE" -pubkey -noout \
                | openssl pkey -pubin -outform DER 2>/dev/null \
                | openssl dgst -sha256 -binary \
                | od -An -v -tx1 | tr -d ' \n')

SPKI_HASH_B64=$(openssl x509 -in "$CERT_FILE" -pubkey -noout \
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
       ([proxy].tls_cert / [proxy].tls_key in proxy.toml).
    4. Any older build, or any TLS endpoint not presenting this exact
       public key, will fail the handshake before any request is sent.
EOF
