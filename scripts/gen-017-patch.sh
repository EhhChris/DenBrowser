#!/usr/bin/env bash
# gen-017-patch.sh — Regenerate patch 017 from config/mozilla.cfg.
#
# Reads every lockPref() call in config/mozilla.cfg and emits a patch that
# inserts an equivalent SetBool/SetInt/SetCString + Preferences::Lock() call
# sequence into modules/libpref/Preferences.cpp, plus an early call site.
# The production patch also removes AutoConfig's pref file from the package
# manifest because production builds disable pref extensions.
#
# Run this whenever:
#   - config/mozilla.cfg changes (to keep the compiled-in copy in sync), or
#   - Firefox ESR is upgraded and patch 017 fails to apply (sentinel drift).
#
# The patch is generated semantically (text-search, not line numbers) so it
# produces correct hunk offsets for any ESR version whose source still
# contains the expected sentinel text.
#
# Usage: ./scripts/gen-017-patch.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/src"
PATCHES_DIR="$ROOT_DIR/patches"
CONFIG_DIR="$ROOT_DIR/config"

VERSION_FILE="$SRC_DIR/.esr_version"
if [[ ! -f "$VERSION_FILE" ]]; then
    echo "ERROR: $SRC_DIR/.esr_version not found. Run fetch-esr.sh first." >&2
    exit 1
fi

ESR_VERSION=$(cat "$VERSION_FILE")
FIREFOX_SRC="${GEN017_SOURCE_DIR:-$SRC_DIR/firefox-${ESR_VERSION%esr}}"
TARGET_REL="modules/libpref/Preferences.cpp"
TARGET="$FIREFOX_SRC/$TARGET_REL"
MANIFEST_REL="browser/installer/package-manifest.in"
MANIFEST="$FIREFOX_SRC/$MANIFEST_REL"
CFG="$CONFIG_DIR/mozilla.cfg"
PATCH_OUT="$PATCHES_DIR/017-compile-in-lockprefs.patch"

if [[ ! -f "$TARGET" ]]; then
    echo "ERROR: $TARGET not found." >&2
    exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
    echo "ERROR: $MANIFEST not found." >&2
    exit 1
fi
if [[ ! -f "$CFG" ]]; then
    echo "ERROR: $CFG not found." >&2
    exit 1
fi

echo "[gen-017] Source: $FIREFOX_SRC"
echo "[gen-017] Target: $TARGET_REL"
echo "[gen-017] Config: $CFG"

python3 - "$TARGET" "$TARGET_REL" "$MANIFEST" "$MANIFEST_REL" "$CFG" "$PATCH_OUT" <<'PYEOF'
import sys, re, difflib

target_path, target_rel, manifest_path, manifest_rel, cfg_path, patch_path = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
)

# ── Parse mozilla.cfg ─────────────────────────────────────────────────────────
# Accept three literal forms:
#   lockPref("name", true|false);
#   lockPref("name", <signed int>);
#   lockPref("name", "string with no embedded quote");
LOCKPREF_RE = re.compile(
    r'^\s*lockPref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;\s*(?://.*)?$'
)

with open(cfg_path, encoding='utf-8') as f:
    cfg_lines = f.readlines()

entries = []  # list of (kind, name, c_literal)
for lineno, raw in enumerate(cfg_lines, 1):
    stripped = raw.strip()
    if not stripped or stripped.startswith('//'):
        continue
    m = LOCKPREF_RE.match(raw)
    if not m:
        if 'lockPref' in raw:
            print(f'ERROR: {cfg_path}:{lineno}: unparseable lockPref line:',
                  file=sys.stderr)
            print(f'       {raw.rstrip()}', file=sys.stderr)
            sys.exit(1)
        continue
    name, value = m.group(1), m.group(2).strip()
    if value in ('true', 'false'):
        entries.append(('bool', name, value))
    elif re.fullmatch(r'-?\d+', value):
        # int32_t range check — anything outside fails the build later anyway.
        n = int(value)
        if not (-2**31 <= n <= 2**31 - 1):
            print(f'ERROR: {cfg_path}:{lineno}: int out of int32_t range: {n}',
                  file=sys.stderr)
            sys.exit(1)
        entries.append(('int', name, value))
    elif value.startswith('"') and value.endswith('"'):
        inner = value[1:-1]
        if '"' in inner or '\\' in inner:
            print(f'ERROR: {cfg_path}:{lineno}: string contains quote or '
                  f'backslash; extend gen-017 to handle escapes.',
                  file=sys.stderr)
            sys.exit(1)
        entries.append(('str', name, f'"{inner}"'))
    else:
        print(f'ERROR: {cfg_path}:{lineno}: unrecognised value form: {value}',
              file=sys.stderr)
        sys.exit(1)

if not entries:
    print('ERROR: no lockPref entries parsed from mozilla.cfg.',
          file=sys.stderr)
    sys.exit(1)

print(f'[gen-017] Parsed {len(entries)} lockPref entries.')

# ── Emit C++ body ─────────────────────────────────────────────────────────────
def emit(kind, name, lit):
    if kind == 'bool':
        return (f'  Preferences::SetBool("{name}", {lit},\n'
                f'                       PrefValueKind::Default);\n'
                f'  Preferences::Lock("{name}");\n')
    if kind == 'int':
        return (f'  Preferences::SetInt("{name}", {lit},\n'
                f'                      PrefValueKind::Default);\n'
                f'  Preferences::Lock("{name}");\n')
    if kind == 'str':
        return (f'  Preferences::SetCString("{name}", {lit},\n'
                f'                          PrefValueKind::Default);\n'
                f'  Preferences::Lock("{name}");\n')
    raise AssertionError(kind)

body = ''.join(emit(*e) for e in entries)

FUNCTION_BLOCK = f'''\
// DenBrowser: enforce the lockPref set from config/mozilla.cfg directly in
// libxul.  Generated by scripts/gen-017-patch.sh — do not edit by hand.
//
// Runs before default preference files are read, so their values cannot
// replace these locked defaults. Production builds exclude AutoConfig.
//
// {len(entries)} prefs locked.
static void SetupDenBrowserLockdown() {{
  MOZ_ASSERT(XRE_IsParentProcess());
{body}}}

'''

# ── Insertion 1: function definition ─────────────────────────────────────────
# Anchor between the end of the SetupTelemetryPref #ifdef block and the
# definition of GetInstanceForService.  This text has been stable in libpref
# for many ESR versions.
FUNC_SENTINEL = (
    '#endif  // MOZ_WIDGET_ANDROID\n'
    '\n'
    '/* static */\n'
    'already_AddRefed<Preferences> Preferences::GetInstanceForService() {\n'
)

with open(target_path, encoding='utf-8') as f:
    orig_src = f.read()

if ('static void SetupDenBrowserLockdown()' in orig_src or
        '  SetupDenBrowserLockdown();' in orig_src):
    print('ERROR: source already contains patch 017. Generate from a pristine '
          'Firefox tree (or set GEN017_SOURCE_DIR to one).', file=sys.stderr)
    sys.exit(1)

if orig_src.count(FUNC_SENTINEL) != 1:
    print('ERROR: function-insertion sentinel not found in Preferences.cpp.',
          file=sys.stderr)
    print('       The MOZ_WIDGET_ANDROID block before GetInstanceForService '
          'may have moved.', file=sys.stderr)
    sys.exit(1)

FUNC_REPLACEMENT = (
    '#endif  // MOZ_WIDGET_ANDROID\n'
    '\n'
    f'{FUNCTION_BLOCK}'
    '/* static */\n'
    'already_AddRefed<Preferences> Preferences::GetInstanceForService() {\n'
)

src = orig_src.replace(FUNC_SENTINEL, FUNC_REPLACEMENT, 1)

# ── Insertion 2: call site ────────────────────────────────────────────────────
# Lock after StaticPrefs::InitAll and before on-disk default pref files.
CALL_SENTINEL = (
    '  // Initialize static prefs before prefs from data files so that the latter\n'
    '  // will override the former.\n'
    '  StaticPrefs::InitAll();\n'
)
if src.count(CALL_SENTINEL) != 1:
    print('ERROR: call-site sentinel not found in Preferences.cpp.',
          file=sys.stderr)
    print('       The StaticPrefs::InitAll block in InitInitialObjects '
          'may have changed.', file=sys.stderr)
    sys.exit(1)

CALL_REPLACEMENT = (
    '  // Initialize static prefs before prefs from data files so that the latter\n'
    '  // will override the former.\n'
    '  StaticPrefs::InitAll();\n'
    '\n'
    '  // DenBrowser: lock prefs before loading defaults from data files.\n'
    '  SetupDenBrowserLockdown();\n'
)
src = src.replace(CALL_SENTINEL, CALL_REPLACEMENT, 1)

if src == orig_src:
    print('ERROR: no edits produced — source may already be patched.',
          file=sys.stderr)
    sys.exit(1)

with open(manifest_path, encoding='utf-8') as f:
    orig_manifest = f.read()

MANIFEST_SENTINEL = '@RESPATH@/defaults/autoconfig/prefcalls.js\n'
if orig_manifest.count(MANIFEST_SENTINEL) != 1:
    print('ERROR: AutoConfig package-manifest entry not found exactly once.',
          file=sys.stderr)
    sys.exit(1)
manifest = orig_manifest.replace(MANIFEST_SENTINEL, '', 1)

# ── Generate unified diff ─────────────────────────────────────────────────────
diff_lines = list(difflib.unified_diff(
    orig_src.splitlines(keepends=True),
    src.splitlines(keepends=True),
    fromfile=f'a/{target_rel}',
    tofile=f'b/{target_rel}',
    n=3,
))
diff_lines.extend(difflib.unified_diff(
    orig_manifest.splitlines(keepends=True),
    manifest.splitlines(keepends=True),
    fromfile=f'a/{manifest_rel}',
    tofile=f'b/{manifest_rel}',
    n=3,
))
# A blank context line is represented as " \\n" in a unified diff.  An empty
# line is accepted by git apply as the same context, and avoids making the
# generated patch itself fail the outer repository's whitespace check.
new_diff = ''.join('\n' if line == ' \n' else line for line in diff_lines)

# ── Splice into existing patch file (preserve the comment header) ─────────────
with open(patch_path, encoding='utf-8') as f:
    patch = f.read()

diff_start = patch.find('\ndiff --git ')
if diff_start == -1:
    diff_start = patch.find('\n--- a/')
if diff_start == -1:
    print('ERROR: could not locate diff section marker in patch file.',
          file=sys.stderr)
    sys.exit(1)

updated = patch[:diff_start + 1] + new_diff

with open(patch_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(updated)

hunks = [l for l in diff_lines if l.startswith('@@')]
print(f'[gen-017] Wrote {len(hunks)} hunk(s) to {patch_path}')
for h in hunks:
    print(f'          {h.rstrip()}')
PYEOF

echo "[gen-017] Verifying patch applies cleanly..."
if (cd "$FIREFOX_SRC" && GIT_CEILING_DIRECTORIES="$ROOT_DIR" git apply --no-index -p1 --check "$PATCH_OUT"); then
    echo "[gen-017] OK — patch applies cleanly to $ESR_VERSION"
else
    echo "[gen-017] FAILED — patch does not apply. Check sentinel text in $TARGET_REL" >&2
    exit 1
fi
