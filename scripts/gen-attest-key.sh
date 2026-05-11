#!/usr/bin/env bash
# gen-attest-key.sh — Generate the ZeroFox browser-attestation keypair.
#
# Key model:
#   Private key  → stays on the proxy (copy to your gateway config)
#   Public key   → embedded in the ZeroFox browser build (not secret)
#
# Usage:  ./scripts/gen-attest-key.sh
#
# Output:
#   build/proxy-private.pem  — EC P-256 private key  (deploy to the proxy)
#   build/proxy-public.pem   — matching public key    (not secret)
#   build/proxy-public.der   — public key in DER form (bytes for the patch)
#
# The public key bytes are also patched directly into kHapPublicKeyDer[]
# in netwerk/base/ZeroFoxAttest.cpp so the next Firefox build includes them.
#
# Workflow for each new ZeroFox release:
#   1. Run this script.
#   2. Rebuild Firefox (public key is now baked in).
#   3. Copy build/proxy-private.pem to the proxy and reload.
#   4. The old build's tokens will no longer decrypt correctly once the proxy
#      is updated — old builds are effectively revoked.
#
# SECURITY NOTES:
#   - Never commit proxy-private.pem.  It is gitignored from build/.
#   - Treat the proxy private key like any other TLS private key.
#   - The public key in kHapPublicKeyDer[] is not secret; embedding it in
#     the binary gives attackers nothing useful (they cannot forge tokens
#     without the proxy private key to complete ECDH on the other side).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

# Locate ZeroFoxAttest.cpp inside the unpacked Firefox source tree.
if [[ -f "$ROOT_DIR/src/.esr_version" ]]; then
    ESR_VER=$(cat "$ROOT_DIR/src/.esr_version" | sed 's/esr//')
    ATTEST_CPP="$ROOT_DIR/src/firefox-${ESR_VER}/netwerk/base/ZeroFoxAttest.cpp"
else
    ATTEST_CPP=""
fi

mkdir -p "$BUILD_DIR"

# ── 1. Generate EC P-256 keypair ─────────────────────────────────────────────
echo "[gen-attest-key] Generating EC P-256 keypair..."
openssl ecparam -genkey -name prime256v1 -noout \
        -out "$BUILD_DIR/proxy-private.pem"

# ── 2. Extract public key (PEM + DER) ────────────────────────────────────────
echo "[gen-attest-key] Extracting public key..."
openssl ec -in "$BUILD_DIR/proxy-private.pem" -pubout \
        -out "$BUILD_DIR/proxy-public.pem"
openssl ec -in "$BUILD_DIR/proxy-private.pem" -pubout \
        -outform DER -out "$BUILD_DIR/proxy-public.der"

KEY_SIZE=$(wc -c < "$BUILD_DIR/proxy-public.der" | tr -d ' ')
echo "[gen-attest-key] Public key DER: $KEY_SIZE bytes"

# ── 3. Build C hex array ──────────────────────────────────────────────────────
KEY_BYTES=$(xxd -i "$BUILD_DIR/proxy-public.der" \
            | grep -v '^unsigned\|^};' \
            | sed 's/^  /  /')

# ── 4. Patch ZeroFoxAttest.cpp (if the source tree is available) ─────────────
if [[ -n "$ATTEST_CPP" && -f "$ATTEST_CPP" ]]; then
    echo "[gen-attest-key] Patching kHapPublicKeyDer[] in ZeroFoxAttest.cpp..."
    python3 - "$ATTEST_CPP" "$KEY_BYTES" <<'PYEOF'
import sys, re

cpp_path = sys.argv[1]
new_bytes = sys.argv[2]

with open(cpp_path, "r") as f:
    src = f.read()

pattern = re.compile(
    r'(// ── REPLACE:.*?──\n).*?(  // ── END REPLACE)',
    re.DOTALL
)

replacement = r'\g<1>' + new_bytes + r'\n\g<2>'

new_src, n = pattern.subn(replacement, src)
if n != 1:
    print(f"ERROR: Could not find REPLACE markers in {cpp_path}", file=sys.stderr)
    sys.exit(1)

with open(cpp_path, "w") as f:
    f.write(new_src)

print(f"  Updated {cpp_path}")
PYEOF
else
    echo "[gen-attest-key] Source tree not found; printing bytes for manual paste:"
    echo ""
    echo "  Replace kHapPublicKeyDer[] in netwerk/base/ZeroFoxAttest.cpp with:"
    echo ""
    echo "$KEY_BYTES"
    echo ""
fi

# ── 5. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "[gen-attest-key] Done."
echo ""
echo "  Proxy private key : $BUILD_DIR/proxy-private.pem  ← deploy to the proxy"
echo "  Proxy public key  : $BUILD_DIR/proxy-public.pem   ← not secret"
echo "  Public key DER    : $BUILD_DIR/proxy-public.der   ← baked into build"
echo ""
echo "  Next steps:"
echo "    1. Rebuild Firefox (public key is now in ZeroFoxAttest.cpp)."
echo "    2. Copy proxy-private.pem to the proxy and reload."
echo "    3. Distribute the new ZeroFox build."
echo "    4. Old builds are now revoked — the new private key means"
echo "       their tokens cannot be decrypted."
echo ""
echo "  NEVER commit proxy-private.pem to version control."
