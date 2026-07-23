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
FF_VERSION=""
TARBALL_PATH=""
JOBS=$(sysctl -n hw.logicalcpu 2>/dev/null || nproc 2>/dev/null || echo 4)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-fetch)   SKIP_FETCH=1 ;;
        --skip-patches) SKIP_PATCHES=1 ;;
        --skip-patch)   SKIP_PATCH_ARGS+=(--skip-patch "$2"); shift ;;
        --jobs)         JOBS="$2"; shift ;;
        --dev)          DEV_MODE=1 ;;
        --ffversion)    FF_VERSION="$2"; shift ;;
        --tarball)      TARBALL_PATH="$2"; shift ;;
        -h|--help)
            echo "Usage: $0 [--skip-fetch] [--skip-patches] [--skip-patch N]... [--jobs N] [--dev] [--ffversion X.Y.Z] [--tarball PATH]"
            echo "  --skip-patch N    Skip patch N (by number, e.g. 6 for 006-attest-requests.patch)."
            echo "                    Repeatable: --skip-patch 6 --skip-patch 8"
            echo "  --dev             Enable DevTools + testing features: skips patch 008, strips"
            echo "                    devtools locks from policies.json and mozilla.cfg, and adjusts"
            echo "                    mozconfig to enable marionette, crashreporter, profiling, and"
            echo "                    preserve debug symbols (no strip)."
            echo "  --ffversion X.Y.Z Pin the Firefox ESR version (e.g. 140.11.0) instead of"
            echo "                    fetching the latest from Mozilla's product-details API."
            echo "  --tarball PATH    Use a specific source tarball (firefox-X.Y.Zesr.source.tar.xz)."
            echo "                    Implies --skip-fetch and --no-revert (no git snapshot is created)."
            echo "                    Cannot be combined with --ffversion."
            exit 0 ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ -n "$TARBALL_PATH" && -n "$FF_VERSION" ]]; then
    echo "[build] ERROR: --tarball and --ffversion are mutually exclusive." >&2
    exit 1
fi

if [[ -n "$TARBALL_PATH" && ! -f "$TARBALL_PATH" ]]; then
    echo "[build] ERROR: Tarball not found: $TARBALL_PATH" >&2
    exit 1
fi

if [[ $DEV_MODE -eq 1 ]]; then
    echo "[build] DEV MODE: DevTools enabled, marionette/crashreporter/profiling enabled, strip disabled"
    SKIP_PATCH_ARGS+=(--skip-patch 8)
    # Patch 017 compiles every mozilla.cfg lockPref into libxul, including the
    # devtools.* locks. Skipping it in dev mode lets the sed-stripped on-disk
    # mozilla.cfg govern devtools state and keeps the compiled binary clean of
    # dev-tools locks for marionette/inspector use.
    SKIP_PATCH_ARGS+=(--skip-patch 17)
fi

# ── Step 1: Fetch Firefox ESR source ─────────────────────────────────────────
if [[ -n "$TARBALL_PATH" ]]; then
    TARBALL_PATH="$(cd "$(dirname "$TARBALL_PATH")" && pwd)/$(basename "$TARBALL_PATH")"
    # Discover the top-level directory from the archive itself rather than parsing
    # the filename — handles stripped/renamed tarballs without caring about the name.
    # Some tarballs prefix every entry with "./" (and may lead with a bare "./"
    # directory entry), so take the first real path component — skipping empty and
    # "." fields — instead of blindly cutting field 1. Otherwise _topdir becomes "."
    # and .esr_version becomes ".esr", sending the build to look for src/firefox-.
    _topdir=$(tar -tf "$TARBALL_PATH" 2>/dev/null | awk -F/ '
        { for (i = 1; i <= NF; i++) if ($i != "" && $i != ".") { print $i; exit } }') || true
    if [[ -z "$_topdir" ]]; then
        echo "[build] ERROR: Could not read tarball: $TARBALL_PATH" >&2
        exit 1
    fi
    mkdir -p "$SRC_DIR"
    # Derive the version from the archive's top-level dir (e.g. firefox-140.12.0).
    # Mozilla's ESR tarballs extract to firefox-<ver> WITHOUT the "esr" suffix (it
    # only appears in the filename), so normalize to the canonical "<ver>esr" form
    # that fetch-esr.sh writes. The %esr strip makes this idempotent regardless of
    # whether a renamed/stripped tarball happens to carry esr in its dir name.
    _ver="${_topdir#firefox-}"
    echo "${_ver%esr}esr" > "$SRC_DIR/.esr_version"
    unset _ver
    EXTRACT_DIR="$SRC_DIR/$_topdir"
    if [[ -d "$EXTRACT_DIR" ]]; then
        echo "[build] Source already extracted at $EXTRACT_DIR, skipping extraction."
    else
        echo "[build] Extracting $(basename "$TARBALL_PATH") (this may take a few minutes)..."
        tar -xJf "$TARBALL_PATH" -C "$SRC_DIR"
        echo "[build] Extracted to $EXTRACT_DIR"
    fi
    unset _topdir
elif [[ $SKIP_FETCH -eq 0 ]]; then
    bash "$SCRIPTS_DIR/fetch-esr.sh" ${FF_VERSION:+--ffversion "$FF_VERSION"}
else
    echo "[build] Skipping fetch (--skip-fetch)"
fi

ESR_VERSION=$(cat "$SRC_DIR/.esr_version")
FIREFOX_SRC="$SRC_DIR/firefox-${ESR_VERSION%esr}"
echo "[build] Firefox source: $FIREFOX_SRC"

# config/mozconfig pins MOZ_OBJDIR to a fixed path next to the source tree
# (@TOPSRCDIR@/../denbrowser-obj) that does NOT encode the ESR version. fetch-esr.sh
# always grabs whatever ESR point release is current, so a rebuild after Mozilla
# ships a new point release extracts a new firefox-<version> tree but would reuse
# an objdir last built against the old one. Mach only regenerates some Makefiles
# incrementally, so stale per-directory Makefiles keep absolute paths into the old
# (possibly deleted) tree, and mozmake fails deep into the build with "No rule to
# make target .../firefox-<old-version>/...". Clobber automatically on version
# mismatch so this can never resurface on either platform.
OBJDIR="$(dirname "$FIREFOX_SRC")/denbrowser-obj"
OBJ_VERSION_MARKER="$OBJDIR/.denbrowser_esr_version"
if [[ -d "$OBJDIR" ]]; then
    PREV_VERSION=$(cat "$OBJ_VERSION_MARKER" 2>/dev/null || echo "")
    if [[ "$PREV_VERSION" != "$ESR_VERSION" ]]; then
        echo "[build] Object directory was built against a different Firefox source version (${PREV_VERSION:-unknown} -> $ESR_VERSION)."
        echo "[build] Removing stale object directory to avoid mismatched-path build failures: $OBJDIR"
        rm -rf "$OBJDIR"
    fi
fi

# ── Step 2: Apply DenBrowser patches ────────────────────────────────────────────
if [[ $SKIP_PATCHES -eq 0 ]]; then
    PATCH_ARGS=(${SKIP_PATCH_ARGS[@]+"${SKIP_PATCH_ARGS[@]}"})
    [[ -n "$TARBALL_PATH" ]] && PATCH_ARGS+=(--no-revert)
    bash "$SCRIPTS_DIR/apply-patches.sh" ${PATCH_ARGS[@]+"${PATCH_ARGS[@]}"}
else
    echo "[build] Skipping patches (--skip-patches)"
fi

# ── Step 2.5: Generate the attestation proxy table ───────────────────────────
# A deployment fronts N partner applications, each behind its own attestation
# proxy with its own keypair and TLS cert.  Reads the "proxies" array from
# config/site-config.json and regenerates the DEN: PROXY_TABLE block in
# DenBrowserAttest.cpp (patch 006) with, per proxy: the domains it fronts, its
# attestation public key (patch 006), and its TLS SPKI pin (patch 012).
#
# This is the ONLY writer of that block — the gen-* scripts only produce key
# material in build/ and never touch the source tree, so what is compiled in
# always matches the checked-in config.
#
# With no "proxies" configured the table stays empty: attestation headers and
# proxy pinning are both inert and requests go out unmodified, so a dev build
# works before any proxy exists.  A configured proxy whose key material is
# missing or malformed aborts the build rather than silently producing a
# binary that attests nothing.
SITE_CONFIG="$ROOT_DIR/config/site-config.json"
ATTEST_SRC="$FIREFOX_SRC/netwerk/base/DenBrowserAttest.cpp"
if [[ -f "$SITE_CONFIG" ]]; then
    python3 - "$SITE_CONFIG" "$ATTEST_SRC" "$ROOT_DIR" <<'PYEOF' || { echo "[build] ERROR: proxy-table generation failed — aborting build."; exit 1; }
import base64, hashlib, json, os, re, subprocess, sys

config_path, src_path, root_dir = sys.argv[1], sys.argv[2], sys.argv[3]

# Entry name: goes into a C string literal and log messages.
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
# Hostname (already lowercased).  A single label ("localhost") is allowed so
# dev deployments work; a wildcard is not — see the no-catch-all note below.
HOST_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$')

def die(msg):
    print(f'ERROR: {msg}', file=sys.stderr)
    sys.exit(1)

with open(config_path, encoding='utf-8') as f:
    config = json.load(f)

proxies = config.get('proxies', [])
if not isinstance(proxies, list):
    die('site-config.json: "proxies" must be an array')

if not proxies:
    print('[build] No "proxies" in site-config.json — request attestation and '
          'proxy TLS pinning are DISABLED for this build.')
    legacy = os.path.join(root_dir, 'build', 'proxy-public.der')
    if os.path.isfile(legacy):
        print('[build]   NOTE: build/proxy-public.der exists but a key alone no '
              'longer configures attestation.')
        print('[build]   Name it from a proxy entry, e.g.:')
        print('[build]     "proxies": [{ "name": "proxy", "domains": '
              '["app.example.com"], "attest_key": "proxy-public.der", '
              '"tls_cert": "proxy-tls.crt" }]')
    sys.exit(0)

if not os.path.isfile(src_path):
    die(f'"proxies" is configured but {src_path} is missing.\n'
        '       Patch 006 must be applied before the proxy table can be '
        'generated.\n'
        '       Check that apply-patches.sh succeeded for '
        '006-attest-requests.patch.')

def resolve(value, kind, name):
    """A bare filename lives in build/; a path is taken relative to the repo."""
    if os.path.isabs(value):
        path = value
    elif '/' in value or os.sep in value:
        path = os.path.join(root_dir, value)
    else:
        path = os.path.join(root_dir, 'build', value)
    if not os.path.isfile(path):
        die(f'proxy "{name}": {kind} not found: {path}')
    return path

def spki_sha256_from_cert(cert_path, name):
    """sha256 of the cert's SubjectPublicKeyInfo (RFC 7469 style)."""
    try:
        pem = subprocess.run(
            ['openssl', 'x509', '-in', cert_path, '-pubkey', '-noout'],
            capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        die(f'proxy "{name}": openssl is not on PATH and is needed to read '
            f'tls_cert.\n       Install openssl, or paste the hash into '
            f'"tls_spki_sha256" instead.')
    except subprocess.CalledProcessError as exc:
        die(f'proxy "{name}": openssl could not read {cert_path}: '
            f'{exc.stderr.strip()}')
    # The body of a "BEGIN PUBLIC KEY" PEM *is* the DER SubjectPublicKeyInfo.
    body = ''.join(l for l in pem.splitlines() if not l.startswith('-----'))
    return hashlib.sha256(base64.b64decode(body)).digest()

def spki_sha256_from_literal(value, name):
    """Accept the pin as 64 hex chars (with optional colons) or base64."""
    stripped = re.sub(r'[\s:]', '', value)
    if re.fullmatch(r'[0-9a-fA-F]{64}', stripped):
        return bytes.fromhex(stripped)
    try:
        raw = base64.b64decode(stripped, validate=True)
    except Exception:
        raw = b''
    if len(raw) != 32:
        die(f'proxy "{name}": tls_spki_sha256 must be a 32-byte sha256 as 64 '
            f'hex characters or base64, got {value!r}')
    return raw

def c_bytes(raw, per_line=12):
    return '\n'.join(
        '    ' + ' '.join(f'0x{b:02x},' for b in raw[i:i + per_line])
        for i in range(0, len(raw), per_line))

def claims(domain, host):
    """True if `domain` matches `host` exactly or as a parent domain —
    the same rule FindProxyForHost() applies at runtime."""
    return host == domain or host.endswith('.' + domain)

# ── Validate every entry before writing anything ────────────────────────────
entries = []
seen_names = set()
for raw_entry in proxies:
    if not isinstance(raw_entry, dict):
        die('site-config.json: each "proxies" entry must be an object')

    name = raw_entry.get('name')
    if not name or not isinstance(name, str) or not NAME_RE.match(name):
        die(f'proxy entry needs a "name" of letters/digits/._- : {raw_entry!r}')
    if name in seen_names:
        die(f'duplicate proxy name: {name!r}')
    seen_names.add(name)

    domains = raw_entry.get('domains')
    if not isinstance(domains, list) or not domains:
        die(f'proxy "{name}": "domains" must be a non-empty array of hostnames')
    normalized = []
    for domain in domains:
        if not isinstance(domain, str):
            die(f'proxy "{name}": domain entries must be strings')
        domain = domain.strip().lower().rstrip('.')
        if '*' in domain:
            die(f'proxy "{name}": wildcard domains are not supported ({domain!r}).\n'
                '       There is no catch-all: list every hostname this proxy '
                'fronts.  Hosts no proxy claims are sent unattested, and a\n'
                '       listed domain already covers its subdomains.')
        if not HOST_RE.match(domain):
            die(f'proxy "{name}": invalid hostname {domain!r}')
        normalized.append(domain)

    attest_key = raw_entry.get('attest_key')
    if not attest_key or not isinstance(attest_key, str):
        die(f'proxy "{name}": "attest_key" (public key DER) is required')
    with open(resolve(attest_key, 'attest_key', name), 'rb') as f:
        key_der = f.read()
    if not key_der or key_der[0] != 0x30:
        die(f'proxy "{name}": {attest_key} is not a DER SubjectPublicKeyInfo '
            f'(expected first byte 0x30).\n'
            f'       Point at the .der written by scripts/gen-attest-key.sh '
            f'--name {name}, not the .pem.')
    if len(key_der) != 91:
        print(f'[build] WARNING: proxy "{name}": attestation key is '
              f'{len(key_der)} bytes; an EC P-256 SPKI is normally 91. '
              f'Verify it is a P-256 key.')

    if raw_entry.get('tls_cert') and raw_entry.get('tls_spki_sha256'):
        die(f'proxy "{name}": set only one of "tls_cert" / "tls_spki_sha256"')
    if raw_entry.get('tls_cert'):
        pin = spki_sha256_from_cert(
            resolve(raw_entry['tls_cert'], 'tls_cert', name), name)
    elif raw_entry.get('tls_spki_sha256'):
        pin = spki_sha256_from_literal(raw_entry['tls_spki_sha256'], name)
    else:
        pin = None
        print(f'[build] WARNING: proxy "{name}" has no "tls_cert" or '
              f'"tls_spki_sha256" — its TLS hop is NOT pinned, so a MITM with '
              f'a trusted cert could read its attestation headers.')

    entries.append({'name': name, 'domains': normalized, 'key': key_der,
                    'pin': pin})

# First match wins at runtime, so warn when an earlier entry's domain already
# covers a later entry's — the later one would never be reached for those hosts.
for i, entry in enumerate(entries):
    for other in entries[:i]:
        for domain in entry['domains']:
            shadowing = [d for d in other['domains'] if claims(d, domain)]
            if shadowing:
                print(f'[build] WARNING: proxy "{other["name"]}" claims '
                      f'{shadowing[0]!r}, which already covers '
                      f'{domain!r} from proxy "{entry["name"]}". '
                      f'"{other["name"]}" wins — list the more specific proxy '
                      f'first if that is backwards.')

# ── Emit the table ───────────────────────────────────────────────────────────
out = ['// ── DEN: PROXY_TABLE ──',
       '// GENERATED by build.sh (Step 2.5) from the "proxies" array in',
       '// config/site-config.json.  Do not edit here — edit the JSON, rebuild.']
for i, entry in enumerate(entries):
    out.append(f'static const char* const kDenProxyDomains_{i}[] = {{')
    out.extend(f'    "{d}",' for d in entry['domains'])
    out.append('    nullptr')
    out.append('};')
    out.append(f'static const uint8_t kDenProxyKey_{i}[] = {{')
    out.append(c_bytes(entry['key']))
    out.append('};')
    if entry['pin'] is not None:
        out.append(f'static const uint8_t kDenProxyPin_{i}[32] = {{')
        out.append(c_bytes(entry['pin']))
        out.append('};')
out.append('static const DenProxyEntry kDenProxies[] = {')
for i, entry in enumerate(entries):
    pin_ref = f'kDenProxyPin_{i}' if entry['pin'] is not None else 'nullptr'
    out.append(f'  {{"{entry["name"]}", kDenProxyDomains_{i}, '
               f'kDenProxyKey_{i}, '
               f'static_cast<uint32_t>(sizeof(kDenProxyKey_{i})), {pin_ref}}},')
out.append('  {nullptr, nullptr, nullptr, 0, nullptr},')
out.append('};')
out.append('// ── DEN END: PROXY_TABLE ──')

with open(src_path, encoding='utf-8') as f:
    content = f.read()
pattern = re.compile(r'// ── DEN: PROXY_TABLE ──.*?// ── DEN END: PROXY_TABLE ──',
                     re.DOTALL)
new_content, n = pattern.subn(lambda _: '\n'.join(out), content)
if n != 1:
    die(f'PROXY_TABLE sentinels not found in {src_path} '
        f'(expected exactly 1, found {n})')
with open(src_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(new_content)

for entry in entries:
    print(f'[build] Proxy "{entry["name"]}": {len(entry["domains"])} domain(s), '
          f'{len(entry["key"])}-byte key, '
          f'{"pinned" if entry["pin"] is not None else "UNPINNED"}')
print(f'[build] Injected proxy table ({len(entries)} proxy/proxies) into '
      f'DenBrowserAttest.cpp')
PYEOF
else
    echo "[build] No site-config.json — request attestation and proxy TLS pinning disabled."
fi

# ── Step 2.6: Inject site configuration ──────────────────────────────────────
# Reads config/site-config.json (if present) and fills the compile-time sentinel
# blocks in nsCopySupport.cpp, ContentParent.cpp, and the shared network site
# filter added by patches 003 and 014. If the file is absent or a list is empty,
# the array defaults to
# { nullptr } and that feature is disabled for this build.
NCOPY_SRC="$FIREFOX_SRC/dom/base/nsCopySupport.cpp"
CONTENT_PARENT_SRC="$FIREFOX_SRC/dom/ipc/ContentParent.cpp"
SITE_FILTER_SRC="$FIREFOX_SRC/netwerk/base/DenBrowserSiteFilter.h"
if [[ -f "$SITE_CONFIG" ]]; then
    python3 - "$SITE_CONFIG" "$NCOPY_SRC" "$CONTENT_PARENT_SRC" "$SITE_FILTER_SRC" <<'PYEOF' || { echo "[build] ERROR: site-config injection failed — aborting build."; exit 1; }
import json, sys, re

config_path, ncopy_path, content_parent_path, site_filter_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

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
inject(site_filter_path,   'SITE_WHITELIST',  config.get('site_whitelist',  []))
inject(site_filter_path,   'SITE_BLACKLIST',  config.get('site_blacklist',  []))
PYEOF
else
    echo "[build] No site-config.json — clipboard allow-list and site filter disabled."
fi

# ── Step 2.7: Generate custom new-tab page shortcuts ─────────────────────────
# Injects config/site-config.json's "bookmarks" list as static <a> tiles into
# the custom new-tab page added by patch 018 (between its DEN_SHORTCUTS markers).
# URLs are restricted to http(s) and every value is HTML-escaped, because the
# tiles are injected as raw HTML — an unescaped title or a javascript:/chrome:
# URL would otherwise be an injection vector. Empty/absent list → "No shortcuts".
NEWTAB_PAGE="$FIREFOX_SRC/browser/base/content/denbrowser-newtab.html"
if [[ -f "$NEWTAB_PAGE" ]]; then
    python3 - "$NEWTAB_PAGE" "$SITE_CONFIG" <<'PYEOF' || { echo "[build] ERROR: new-tab shortcut injection failed — aborting build."; exit 1; }
import html, json, os, re, sys

page_path, site_config_path = sys.argv[1], sys.argv[2]

bookmarks = []
if os.path.isfile(site_config_path):
    with open(site_config_path, encoding="utf-8") as f:
        bookmarks = json.load(f).get("bookmarks", [])

tiles = []
for b in bookmarks:
    title, url = b.get("title"), b.get("url")
    if not title or not url:
        print(f"ERROR: bookmark entry needs both title and url: {b!r}",
              file=sys.stderr)
        sys.exit(1)
    if not re.match(r"^https?://", url, re.IGNORECASE):
        print(f"ERROR: bookmark url must be http(s): {url!r}", file=sys.stderr)
        sys.exit(1)
    badge = html.escape(title.strip()[0].upper())
    # target="_self" forces the click to navigate the current tab. A plain
    # (empty-target) top-level link can be defaulted to a new tab by Gecko
    # (nsDocShell::ShouldOpenInBlankTarget); an explicit non-empty target
    # bypasses that path so the shortcut consumes the tab in use.
    tiles.append(
        f'<a class="den-tile" target="_self" href="{html.escape(url, quote=True)}">'
        f'<span class="den-badge">{badge}</span>'
        f'<span class="den-label">{html.escape(title)}</span></a>'
    )

inner = ("\n        ".join(tiles) if tiles
         else '<p class="den-empty">No shortcuts configured.</p>')

start, end = "<!-- DEN_SHORTCUTS_START -->", "<!-- DEN_SHORTCUTS_END -->"
with open(page_path, encoding="utf-8") as f:
    content = f.read()
pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
new_content, n = pattern.subn(f"{start}\n        {inner}\n        {end}", content)
if n == 0:
    print(f"ERROR: DEN_SHORTCUTS markers not found in {page_path}",
          file=sys.stderr)
    sys.exit(1)
with open(page_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(new_content)
print(f"[build] Injected {len(tiles)} new-tab shortcut(s) into denbrowser-newtab.html")
PYEOF
else
    echo "[build] WARNING: denbrowser-newtab.html not found (patch 018 not applied?) — skipping shortcut injection"
fi

# ── Step 2.8: Copy DenBrowser branding assets ───────────────────────────────────
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

# ── Step 4: Generate enterprise policies ─────────────────────────────────────
# Writes the effective policies.json to a staging path here; it is installed
# into the packaged app's distribution/ directory in Step 6 (after the build).
# NOTE: mach does NOT package browser/app/distribution/, so this file is a
# runtime artifact like mozilla.cfg — the Step 6 copy is what actually makes the
# policy engine read it.
#
# Default bookmarks/shortcuts are NOT delivered via the Bookmarks policy: the
# activity-stream new-tab page does not render in this hardened, permanent-PBM
# build, so they are baked into the custom new-tab page instead (patch 018,
# injected in Step 2.7 from config/site-config.json).
DIST_DIR="$FIREFOX_SRC/browser/app/distribution"
mkdir -p "$DIST_DIR"
if [[ $DEV_MODE -eq 1 ]]; then
    python3 - "$CONFIG_DIR/policies.json" "$DIST_DIR/policies.json" <<'PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    p = json.load(f)
# Dev builds: drop the DevTools lock so the toolbox is usable.
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

# Record the source version this objdir is now built against, so the next run
# can detect a mismatch (see the clobber guard above) instead of silently
# reusing stale Makefiles from a different ESR release.
echo "$ESR_VERSION" > "$OBJ_VERSION_MARKER"

# ── Step 6: Install autoconfig lockdown ──────────────────────────────────────
# mozilla.cfg and autoconfig.js must live in the built application directory,
# not the source. They cannot be installed pre-build because they are not part
# of the Firefox build system — they are runtime files read directly from the
# installation directory at startup.
#
# Layout differs by platform:
#   macOS:         <app>/Contents/Resources/defaults/pref/autoconfig.js
#                  <app>/Contents/Resources/mozilla.cfg
#   Windows/Linux: <dist/bin>/defaults/pref/autoconfig.js
#                  <dist/bin>/mozilla.cfg
#
# Detect by probing for the macOS bundle first, then falling back to dist/bin
# (which is what Firefox produces on Windows and Linux).
APP_BUNDLE="$OBJDIR/dist/DenBrowser.app"
DIST_BIN="$OBJDIR/dist/bin"

if [[ -d "$APP_BUNDLE" ]]; then
    PREF_DIR="$APP_BUNDLE/Contents/Resources/defaults/pref"
    GRE_DIR="$APP_BUNDLE/Contents/Resources"
    PLATFORM_LABEL="macOS app bundle"
elif [[ -d "$DIST_BIN" ]]; then
    PREF_DIR="$DIST_BIN/defaults/pref"
    GRE_DIR="$DIST_BIN"
    PLATFORM_LABEL="dist/bin (Windows/Linux)"
else
    PREF_DIR=""
fi

if [[ -n "$PREF_DIR" ]]; then
    echo "[build] Installing autoconfig lockdown into $PLATFORM_LABEL..."
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

    # Enterprise policies: the policy engine reads <app>/distribution/policies.json
    # (relative to the binary on Windows/Linux, or Contents/Resources on macOS).
    # mach does not package browser/app/distribution/, so install the file
    # generated in Step 4 here — without this, NO policy (Bookmarks, FirefoxHome,
    # DisablePocket, …) takes effect; the lockdown otherwise rides on mozilla.cfg.
    mkdir -p "$GRE_DIR/distribution"
    cp "$DIST_DIR/policies.json" "$GRE_DIR/distribution/policies.json"
    echo "[build] Installed policies.json into $PLATFORM_LABEL distribution/"
else
    echo "[build] WARNING: No build output found at $APP_BUNDLE or $DIST_BIN — skipping autoconfig/policies install"
    echo "[build]          Run a full build first, or check MOZ_OBJDIR in mozconfig."
fi

echo ""
echo "[build] Build complete."
echo "[build] Run artifact: $(./mach run --dry-run 2>/dev/null | head -1 || true)"
echo "[build] To run: cd $FIREFOX_SRC && ./mach run"
