#!/usr/bin/env bash
# build.sh — Orchestrate a full DenBrowser build from scratch
# Usage: ./build.sh [--skip-fetch] [--skip-patches] [--skip-patch N]... [--jobs N] [--dev]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$ROOT_DIR/scripts"
CONFIG_DIR="$ROOT_DIR/config"
SRC_DIR="$ROOT_DIR/src"

SKIP_FETCH=0
SKIP_PATCHES=0
SKIP_PATCH_ARGS=()
DEV_MODE=0
JOBS=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-fetch)   SKIP_FETCH=1 ;;
        --skip-patches) SKIP_PATCHES=1 ;;
        --skip-patch)   SKIP_PATCH_ARGS+=(--skip-patch "$2"); shift ;;
        --jobs)         JOBS="$2"; shift ;;
        --dev)          DEV_MODE=1 ;;
        -h|--help)
            echo "Usage: $0 [--skip-fetch] [--skip-patches] [--skip-patch N]... [--jobs N] [--dev]"
            echo "  --skip-patch N  Skip patch N (by number, e.g. 6 for 006-attest-requests.patch)."
            echo "                  Repeatable: --skip-patch 6 --skip-patch 8"
            echo "  --dev           Enable DevTools + testing features: skips patch 008, strips"
            echo "                  devtools locks from policies.json and mozilla.cfg, and adjusts"
            echo "                  mozconfig to enable marionette, crashreporter, profiling, and"
            echo "                  preserve debug symbols (no strip)."
            exit 0 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ $DEV_MODE -eq 1 ]]; then
    echo "[build] DEV MODE: DevTools enabled, marionette/crashreporter/profiling enabled, strip disabled"
    SKIP_PATCH_ARGS+=(--skip-patch 8)
fi

# ── Step 1: Fetch Firefox ESR source ─────────────────────────────────────────
if [[ $SKIP_FETCH -eq 0 ]]; then
    bash "$SCRIPTS_DIR/fetch-esr.sh"
else
    echo "[build] Skipping fetch (--skip-fetch)"
fi

ESR_VERSION=$(cat "$SRC_DIR/.esr_version")
FIREFOX_SRC="$SRC_DIR/firefox-${ESR_VERSION%esr}"
echo "[build] Firefox source: $FIREFOX_SRC"

# ── Step 2: Apply DenBrowser patches ────────────────────────────────────────────
if [[ $SKIP_PATCHES -eq 0 ]]; then
    bash "$SCRIPTS_DIR/apply-patches.sh" ${SKIP_PATCH_ARGS[@]+"${SKIP_PATCH_ARGS[@]}"}
else
    echo "[build] Skipping patches (--skip-patches)"
fi

# ── Step 2.5: Inject attestation public key ──────────────────────────────────
# If build/proxy-public.der exists, replace the all-zeros placeholder in
# DenBrowserAttest.cpp with the real key bytes so attestation is active in this
# build. Skipped (with a warning) if the key hasn't been generated yet; aborts
# if the key exists but injection fails (e.g. sentinels missing from source).
ATTEST_SRC="$FIREFOX_SRC/netwerk/base/DenBrowserAttest.cpp"
ATTEST_KEY="$ROOT_DIR/build/proxy-public.der"
if [[ -f "$ATTEST_KEY" && -f "$ATTEST_SRC" ]]; then
    echo "[build] Injecting attestation public key into DenBrowserAttest.cpp..."
    python3 - "$ATTEST_KEY" "$ATTEST_SRC" <<'PYEOF' || { echo "[build] ERROR: key injection failed — aborting build."; exit 1; }
import sys

der_path, src_path = sys.argv[1], sys.argv[2]
with open(der_path, 'rb') as f:
    raw = f.read()

# Format as a C hex array, 10 bytes per line, indented to match the source.
key_lines = []
for i in range(0, len(raw), 10):
    chunk = raw[i:i+10]
    key_lines.append('  ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',\n')

with open(src_path, 'r', encoding='utf-8') as f:
    src_lines = f.readlines()

# Find the sentinel lines and replace everything between them.
START = '// ── REPLACE:'
END   = '// ── END REPLACE'
start_i = end_i = None
for i, line in enumerate(src_lines):
    if START in line:
        start_i = i
    elif END in line and start_i is not None:
        end_i = i
        break

if start_i is None or end_i is None:
    print('ERROR: REPLACE sentinels not found in source file', file=sys.stderr)
    sys.exit(1)

new_lines = src_lines[:start_i + 1] + key_lines + src_lines[end_i:]

with open(src_path, 'w', encoding='utf-8', newline='\n') as f:
    f.writelines(new_lines)

print(f'[build] Injected {len(raw)}-byte public key ({len(key_lines)} lines).')
PYEOF
elif [[ ! -f "$ATTEST_KEY" ]]; then
    echo "[build] WARNING: build/proxy-public.der not found — attestation headers disabled."
    echo "[build]          Run scripts/gen-attest-key.sh to generate a keypair."
elif [[ ! -f "$ATTEST_SRC" ]]; then
    echo "[build] ERROR: proxy-public.der exists but DenBrowserAttest.cpp not in source tree." >&2
    echo "[build]        Patch 006 must be applied before key injection can run." >&2
    echo "[build]        Check that apply-patches.sh succeeded for 006-attest-requests.patch." >&2
    exit 1
fi

# ── Step 2.6: Inject site configuration ──────────────────────────────────────
# Reads config/site-config.json (if present) and fills the compile-time sentinel
# blocks in nsCopySupport.cpp and nsDocShell.cpp that were added by patches 003
# and 014.  If the file is absent or a list is empty, the array defaults to
# { nullptr } and that feature is disabled for this build.
SITE_CONFIG="$ROOT_DIR/config/site-config.json"
NCOPY_SRC="$FIREFOX_SRC/dom/base/nsCopySupport.cpp"
DOCSHELL_SRC="$FIREFOX_SRC/docshell/base/nsDocShell.cpp"
CONTENT_PARENT_SRC="$FIREFOX_SRC/dom/ipc/ContentParent.cpp"
if [[ -f "$SITE_CONFIG" ]]; then
    python3 - "$SITE_CONFIG" "$NCOPY_SRC" "$DOCSHELL_SRC" "$CONTENT_PARENT_SRC" <<'PYEOF' || { echo "[build] ERROR: site-config injection failed — aborting build."; exit 1; }
import json, sys, re

config_path, ncopy_path, docshell_path, content_parent_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

with open(config_path, encoding='utf-8') as f:
    config = json.load(f)

VAR_NAMES = {
    'CLIPBOARD_SITES': 'kDenClipboardSites',
    'SITE_WHITELIST':  'kDenSiteWhitelist',
    'SITE_BLACKLIST':  'kDenSiteBlacklist',
}

def inject(filepath, sentinel_name, items):
    varname = VAR_NAMES[sentinel_name]
    with open(filepath, encoding='utf-8') as f:
        content = f.read()
    start = f'// ── DEN: {sentinel_name} ──'
    end   = f'// ── DEN END: {sentinel_name} ──'
    pattern = re.compile(re.escape(start) + r'.*?' + re.escape(end), re.DOTALL)
    entries = ''.join(f'  "{item}",\n' for item in items)
    replacement = (
        f'{start}\n'
        f'static const char* const {varname}[] = {{\n'
        f'{entries}'
        f'  nullptr\n'
        f'}};\n'
        f'{end}'
    )
    new_content, n = pattern.subn(replacement, content)
    if n == 0:
        print(f'ERROR: sentinel {sentinel_name} not found in {filepath}',
              file=sys.stderr)
        sys.exit(1)
    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write(new_content)
    print(f'[build] Injected {sentinel_name} ({len(items)} entries) into {filepath}')

inject(ncopy_path,         'CLIPBOARD_SITES', config.get('clipboard_sites', []))
inject(content_parent_path,'CLIPBOARD_SITES', config.get('clipboard_sites', []))
inject(docshell_path,      'SITE_WHITELIST',  config.get('site_whitelist',  []))
inject(docshell_path,      'SITE_BLACKLIST',  config.get('site_blacklist',  []))
PYEOF
else
    echo "[build] No site-config.json — clipboard allow-list and site filter disabled."
fi

# ── Step 2.7: Copy DenBrowser branding assets ───────────────────────────────────
BRANDING_DIR="$FIREFOX_SRC/browser/branding/denbrowser"
if [[ -d "$BRANDING_DIR" ]]; then
    ICONSET="$ROOT_DIR/branding/DenBrowser.iconset"
    echo "[build] Copying DenBrowser branding icons..."

    cp "$ICONSET/icon_16x16.png"    "$BRANDING_DIR/default16.png"
    cp "$ICONSET/icon_32x32.png"    "$BRANDING_DIR/default32.png"
    cp "$ICONSET/icon_32x32@2x.png" "$BRANDING_DIR/default64.png"
    cp "$ICONSET/icon_128x128.png"  "$BRANDING_DIR/default128.png"
    cp "$ICONSET/icon_256x256.png"  "$BRANDING_DIR/default256.png"

    cp "$ICONSET/icon_48x48.png"   "$BRANDING_DIR/default48.png"

    # Generate macOS .icns (macOS only)
    if command -v iconutil &>/dev/null; then
        iconutil -c icns "$ICONSET" -o "$BRANDING_DIR/firefox.icns"
        # document.icns = file-association icon for .html files; reuse app icon
        cp "$BRANDING_DIR/firefox.icns" "$BRANDING_DIR/document.icns"
        # disk.icns = DMG volume icon; reuse app icon as placeholder
        cp "$BRANDING_DIR/firefox.icns" "$BRANDING_DIR/disk.icns"
        echo "[build] Generated firefox.icns, document.icns, disk.icns"
    fi

    echo "[build] Branding assets installed."
else
    echo "[build] Branding directory not found — skipping branding asset copy."
fi

# ── Step 3: Install build configuration ──────────────────────────────────────
echo "[build] Installing mozconfig..."
cp "$CONFIG_DIR/mozconfig" "$FIREFOX_SRC/.mozconfig"

# In dev mode, reverse the production-only flags marked [dev-reversed] in mozconfig.
# Uses Python3 (already required by this script) to stay portable across macOS/Linux.
if [[ $DEV_MODE -eq 1 ]]; then
    python3 - "$FIREFOX_SRC/.mozconfig" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    content = f.read()
# Strip production-only flags (comments on same line are also removed).
for flag in ('--enable-strip', '--enable-install-strip',
             '--disable-crashreporter', '--disable-profiling'):
    content = re.sub(r'ac_add_options ' + re.escape(flag) + r'[^\n]*\n?', '', content)
# Append dev-only overrides.
content += (
    '\n# ── Dev mode additions (injected by build.sh --dev) ─────────────────────\n'
    'ac_add_options --enable-crashreporter\n'
    'ac_add_options --enable-profiling\n'
)
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
PYEOF
    echo "[build] DEV MODE: mozconfig adjusted (marionette+crashreporter+profiling enabled, strip disabled)"
fi

# Append job count to mozconfig
echo "mk_add_options MOZ_MAKE_FLAGS=\"-j${JOBS}\"" >> "$FIREFOX_SRC/.mozconfig"

# ── Step 4: Install enterprise policies ──────────────────────────────────────
# policies.json goes into distribution/ inside the build; install it into source
# so it gets picked up at build time.
DIST_DIR="$FIREFOX_SRC/browser/app/distribution"
mkdir -p "$DIST_DIR"
if [[ $DEV_MODE -eq 1 ]]; then
    python3 - "$CONFIG_DIR/policies.json" "$DIST_DIR/policies.json" <<'PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    p = json.load(f)
p["policies"].pop("DisableDeveloperTools", None)
with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
    json.dump(p, f, indent=2)
PYEOF
    echo "[build] Installed policies.json (DevTools policy removed) to $DIST_DIR"
else
    cp "$CONFIG_DIR/policies.json" "$DIST_DIR/policies.json"
    echo "[build] Installed policies.json to $DIST_DIR"
fi

# ── Step 5: Run the Firefox build ────────────────────────────────────────────
echo "[build] Starting Firefox build (this will take 30–90 minutes)..."
cd "$FIREFOX_SRC"
./mach build

# ── Step 6: Install autoconfig lockdown ──────────────────────────────────────
# mozilla.cfg and autoconfig.js must live in the built app bundle, not the source.
# They cannot be installed pre-build because they are not part of the Firefox build
# system — they are runtime files read directly from the installation directory.
#
# autoconfig.js  → <app>/Contents/Resources/defaults/pref/  (tells Firefox to load mozilla.cfg)
# mozilla.cfg    → <app>/Contents/Resources/                 (NS_GRE_DIR on macOS; this is where
#                                                             the autoconfig system looks for it)
OBJDIR="$(dirname "$FIREFOX_SRC")/denbrowser-obj"
APP_BUNDLE="$OBJDIR/dist/DenBrowser.app"
if [[ -d "$APP_BUNDLE" ]]; then
    echo "[build] Installing autoconfig lockdown..."
    PREF_DIR="$APP_BUNDLE/Contents/Resources/defaults/pref"
    GRE_DIR="$APP_BUNDLE/Contents/Resources"
    mkdir -p "$PREF_DIR"
    cp "$CONFIG_DIR/autoconfig.js" "$PREF_DIR/autoconfig.js"
    if [[ $DEV_MODE -eq 1 ]]; then
        sed -E '/^\/\/ ── Developer tools/,/^$/d; /lockPref\("devtools\./d' \
            "$CONFIG_DIR/mozilla.cfg" > "$GRE_DIR/mozilla.cfg"
        echo "[build] Installed autoconfig.js and mozilla.cfg (DevTools locks removed)"
    else
        cp "$CONFIG_DIR/mozilla.cfg" "$GRE_DIR/mozilla.cfg"
        echo "[build] Installed autoconfig.js and mozilla.cfg"
    fi
else
    echo "[build] WARNING: App bundle not found at $APP_BUNDLE — skipping autoconfig install"
    echo "[build]          Run a full build first, or check MOZ_OBJDIR in mozconfig."
fi

echo ""
echo "[build] Build complete."
echo "[build] Run artifact: $(./mach run --dry-run 2>/dev/null | head -1 || true)"
echo "[build] To run: cd $FIREFOX_SRC && ./mach run"
