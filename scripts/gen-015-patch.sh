#!/usr/bin/env bash
# gen-015-patch.sh — Regenerate patch 015 for the current Firefox ESR source.
#
# Run this whenever Firefox ESR is upgraded and patch 015 fails to apply.
# The patch is generated semantically (text-search, not line numbers) so it
# will produce correct hunk offsets for any ESR version whose source still
# contains the expected sentinel text.
#
# Usage: ./scripts/gen-015-patch.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/src"
PATCHES_DIR="$ROOT_DIR/patches"

VERSION_FILE="$SRC_DIR/.esr_version"
if [[ ! -f "$VERSION_FILE" ]]; then
    echo "ERROR: $SRC_DIR/.esr_version not found. Run fetch-esr.sh first." >&2
    exit 1
fi

ESR_VERSION=$(cat "$VERSION_FILE")
FIREFOX_SRC="$SRC_DIR/firefox-${ESR_VERSION%esr}"
TARGET_REL="toolkit/xre/nsAppRunner.cpp"
TARGET="$FIREFOX_SRC/$TARGET_REL"
PATCH_OUT="$PATCHES_DIR/015-strip-blocked-args.patch"

if [[ ! -f "$TARGET" ]]; then
    echo "ERROR: $TARGET not found." >&2
    exit 1
fi

echo "[gen-015] Source: $FIREFOX_SRC"
echo "[gen-015] Target: $TARGET_REL"

python3 - "$TARGET" "$TARGET_REL" "$PATCH_OUT" <<'PYEOF'
import sys, difflib, re

target_path, target_rel, patch_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(target_path) as f:
    orig_src = f.read()

src = orig_src

# ── Insertion 1: DenStripArg + DenBrowserStripBlockedArgs ────────────────────
# Inserted immediately before the XRE_main doxygen comment block so the
# functions are defined before their only call site below.
FUNC_SENTINEL = '/*\n * XRE_main - A class based main entry point used by most platforms.\n *            Note that on OSX'
if FUNC_SENTINEL not in src:
    print('ERROR: function sentinel not found in source.', file=sys.stderr)
    print('       The comment block before XREMain::XRE_main may have changed.', file=sys.stderr)
    sys.exit(1)

FUNC_INSERT_BEFORE = '/*\n * XRE_main - A class based main entry point'
FUNCTIONS = '''\
// DenBrowser: strip command-line flags that can bypass security controls.
// --profile / -P override the ramdisk profile (patch 007). --marionette and
// --remote-debugging-port enable remote control of the browser.
// --ProfileManager opens a profile-picker UI allowing profile switching.
// A following argv value without a leading '-' is treated as the flag's
// argument and removed along with it.
static void DenStripArg(const char* aFlag) {
  for (int i = 1; i < gArgc;) {
    const char* p = gArgv[i];
    if (p[0] == '-') {
      p += (p[1] == '-') ? 2 : 1;
    }
#ifdef XP_WIN
    else if (p[0] == '/') {
      p += 1;
    }
#endif
    else {
      ++i;
      continue;
    }
    if (nsCRT::strcasecmp(p, aFlag) != 0) {
      ++i;
      continue;
    }
    // Flag matched. If the next entry is not itself a flag, treat it as
    // this flag's value and remove both; otherwise remove the flag only.
    int toRemove = 1;
    if (i + 1 < gArgc && gArgv[i + 1][0] != '-') {
      toRemove = 2;
    }
    gArgc -= toRemove;
    memmove(gArgv + i, gArgv + i + toRemove, sizeof(char*) * (gArgc - i + 1));
    // Do not increment i: the slot now holds the next argument.
  }
}

static void DenBrowserStripBlockedArgs() {
  DenStripArg("profile");               // --profile <path>: custom profile dir
  DenStripArg("p");                     // -P <name>: profile by name
  DenStripArg("profilemanager");        // --ProfileManager: profile-picker UI
  DenStripArg("marionette");            // --marionette: WebDriver / GeckoDriver
  DenStripArg("remote-debugging-port"); // --remote-debugging-port: CDP
  DenStripArg("start-debugger-server"); // --start-debugger-server: DevTools
}

/*
 * XRE_main - A class based main entry point'''

src = src.replace(FUNC_INSERT_BEFORE, FUNCTIONS, 1)

# ── Insertion 2: call site ────────────────────────────────────────────────────
# Inserted immediately after gArgv = argv; so that all blocked flags are
# stripped before any other Firefox argument processing runs.
CALL_SENTINEL = '  gArgv = argv;\n\n  ScopedLogging log;'
if CALL_SENTINEL not in src:
    print('ERROR: call sentinel not found in source.', file=sys.stderr)
    print('       The gArgv/ScopedLogging block in XREMain::XRE_main may have changed.', file=sys.stderr)
    sys.exit(1)

CALL_REPLACEMENT = (
    '  gArgv = argv;\n'
    '  DenBrowserStripBlockedArgs();'
    '  // DenBrowser: remove blocked flags before any processing.\n'
    '\n'
    '  ScopedLogging log;'
)
src = src.replace(CALL_SENTINEL, CALL_REPLACEMENT, 1)

# ── Generate unified diff ─────────────────────────────────────────────────────
orig_lines = orig_src.splitlines(keepends=True)
new_lines  = src.splitlines(keepends=True)

diff_lines = list(difflib.unified_diff(
    orig_lines,
    new_lines,
    fromfile=f'a/{target_rel}',
    tofile=f'b/{target_rel}',
    n=3,
))

if not diff_lines:
    print('ERROR: diff produced no output — source may already be patched.', file=sys.stderr)
    sys.exit(1)

new_diff = ''.join(diff_lines)

# ── Splice into existing patch file (preserve the comment header) ─────────────
with open(patch_path) as f:
    patch = f.read()

# Find the "--- a/" marker that starts the diff section.
diff_start = patch.find('\n--- a/')
if diff_start == -1:
    print('ERROR: could not locate diff section in patch file.', file=sys.stderr)
    sys.exit(1)

updated = patch[:diff_start + 1] + new_diff  # +1 keeps the preceding newline

with open(patch_path, 'w') as f:
    f.write(updated)

# Report hunk summary.
hunks = [l for l in diff_lines if l.startswith('@@')]
print(f'[gen-015] Wrote {len(hunks)} hunk(s) to {patch_path}')
for h in hunks:
    print(f'          {h.rstrip()}')

PYEOF

echo "[gen-015] Verifying patch applies cleanly..."
if (cd "$FIREFOX_SRC" && GIT_CEILING_DIRECTORIES="$ROOT_DIR" git apply --no-index -p1 --check "$PATCH_OUT"); then
    echo "[gen-015] OK — patch applies cleanly to $ESR_VERSION"
else
    echo "[gen-015] FAILED — patch does not apply. Check sentinel text in $TARGET_REL" >&2
    exit 1
fi
