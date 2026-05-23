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

with open(target_path, encoding='utf-8') as f:
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
// DenBrowser: strip command-line flags and environment variables that can
// bypass security controls before any Firefox code reads them.
//
// argv stripping covers:
//   - --profile / -P / --ProfileManager / --CreateProfile / --migration
//     (custom profile that bypasses the autoconfig lockdown + ramdisk hook)
//   - --marionette / --remote-debugging-port / --start-debugger-server /
//     --jsdebugger / --wait-for-jsdebugger / --jsconsole / --attach-console /
//     --console  (remote-control and debugging surfaces)
//   - --screenshot (CLI capture-to-disk mode that bypasses patch 001)
//   - --headless / --new-instance / --no-remote / --safe-mode / --purgecaches
//     (modes that change save / sandbox / pref-load semantics)
//   - --setDefaultBrowser / --preferences / --recording / --recordreplay
//
// A following argv value without a leading '-' is treated as the flag's
// argument and is removed together with the flag.
//
// Env stripping covers:
//   - MOZ_LOG / MOZ_LOG_FILE / NSPR_LOG_MODULES / NSPR_LOG_FILE / R_LOG_*
//     (logging targets — would write request bodies, prefs, JS, etc. to disk)
//   - MOZ_DISABLE_*_SANDBOX (process-sandbox bypasses)
//   - MOZ_HEADLESS / MOZ_FORCE_DISABLE_E10S / MOZ_USE_REMOTE / MOZ_NO_REMOTE /
//     MOZ_MARIONETTE / MARIONETTE  (remote-control + alternate-mode toggles)
//   - MOZ_CRASHREPORTER* (re-enable crash dump writes despite mozconfig flag)
//   - MOZ_PROFILER_STARTUP* (writes profile samples — incl. JS source — to disk)
//   - XPCOM_DEBUG_BREAK / MOZ_DEBUG_CHILD_* (debugger attach helpers)
//
// This patch operates at the C++ level and cannot be circumvented by profile
// configuration, mozilla.cfg edits, or enterprise policy changes.
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

// Fully remove a variable from the environment so PR_GetEnv() / getenv() see
// it as unset.  PR_SetEnv("NAME=") only sets it to empty string — code that
// uses `if (PR_GetEnv("X"))` for presence checks would still take the branch.
// We need real unset semantics from the OS layer.
static void DenStripEnv(const char* aName) {
#ifdef XP_WIN
  // MSVC CRT: _putenv_s(name, "") removes the entry from the _environ table
  // that getenv() / PR_GetEnv() consult on Windows.  SetEnvironmentVariableA
  // also clears the process env block read by some Win32 APIs directly.
  _putenv_s(aName, "");
  ::SetEnvironmentVariableA(aName, nullptr);
#else
  unsetenv(aName);
#endif
}

static void DenBrowserStripBlockedArgs() {
  // Profile manipulation (bypasses autoconfig lockdown + ramdisk profile).
  DenStripArg("profile");               // --profile <path>
  DenStripArg("p");                     // -P <name>
  DenStripArg("profilemanager");        // --ProfileManager UI
  DenStripArg("createprofile");         // --CreateProfile name [dir]
  DenStripArg("migration");             // --migration profile-import wizard

  // Remote control and debugging surfaces.
  DenStripArg("marionette");            // WebDriver / GeckoDriver
  DenStripArg("remote-debugging-port"); // Chrome DevTools Protocol agent
  DenStripArg("start-debugger-server"); // DevTools remote server
  DenStripArg("jsdebugger");            // JS debugger attach
  DenStripArg("wait-for-jsdebugger");
  DenStripArg("jsconsole");             // legacy JS console
  DenStripArg("attach-console");        // Windows console attach
  DenStripArg("console");

  // Modes that change save / sandbox / pref-load semantics.
  DenStripArg("screenshot");            // CLI screenshot-to-disk mode
  DenStripArg("headless");
  DenStripArg("new-instance");          // skip single-instance check
  DenStripArg("no-remote");             // ditto
  DenStripArg("safe-mode");             // disables JIT + custom prefs
  DenStripArg("purgecaches");           // wipes startup cache
  DenStripArg("allow-downgrade");       // bypass profile-schema downgrade guard

  // Side-effecting flags with no place in a locked-down deployment.
  DenStripArg("setdefaultbrowser");
  DenStripArg("preferences");           // shortcut to about:preferences
  DenStripArg("recording");             // record-and-replay (debug builds)
  DenStripArg("recordreplay");
}

static void DenBrowserStripBlockedEnv() {
  // Logging — would route request bodies, prefs, JS source, NSS/SSL session
  // data into a user-readable file on disk.
  DenStripEnv("MOZ_LOG");
  DenStripEnv("MOZ_LOG_FILE");
  DenStripEnv("NSPR_LOG_MODULES");
  DenStripEnv("NSPR_LOG_FILE");
  DenStripEnv("R_LOG_DESTINATION");
  DenStripEnv("R_LOG_LEVEL");
  DenStripEnv("R_LOG_VERBOSE");
  DenStripEnv("SSLKEYLOGFILE");         // dumps TLS keys to a file — catastrophic

  // Sandbox bypasses — weaken process isolation between content and parent.
  DenStripEnv("MOZ_DISABLE_CONTENT_SANDBOX");
  DenStripEnv("MOZ_DISABLE_GMP_SANDBOX");
  DenStripEnv("MOZ_DISABLE_RDD_SANDBOX");
  DenStripEnv("MOZ_DISABLE_SOCKET_PROCESS_SANDBOX");
  DenStripEnv("MOZ_DISABLE_GPU_SANDBOX");
  DenStripEnv("MOZ_DISABLE_UTILITY_SANDBOX");
  DenStripEnv("MOZ_DISABLE_VR_SANDBOX");
  DenStripEnv("MOZ_PERMIT_CSP_VIOLATION");

  // Remote control, alternate modes, debug attach.
  DenStripEnv("MOZ_HEADLESS");
  DenStripEnv("MOZ_HEADLESS_WIDTH");
  DenStripEnv("MOZ_HEADLESS_HEIGHT");
  DenStripEnv("MOZ_FORCE_DISABLE_E10S");
  DenStripEnv("MOZ_USE_REMOTE");
  DenStripEnv("MOZ_NO_REMOTE");
  DenStripEnv("MOZ_MARIONETTE");
  DenStripEnv("MARIONETTE");
  DenStripEnv("MOZ_REMOTE_AGENT");
  DenStripEnv("XPCOM_DEBUG_BREAK");
  DenStripEnv("XRE_MAIN_BREAK");
  DenStripEnv("MOZ_DEBUG_CHILD_PROCESS");
  DenStripEnv("MOZ_DEBUG_CHILD_PAUSE");

  // Crash reporter — overrides mozconfig --disable-crashreporter and would
  // write a minidump (process memory snapshot) to disk on crash.
  DenStripEnv("MOZ_CRASHREPORTER");
  DenStripEnv("MOZ_CRASHREPORTER_DISABLE");
  DenStripEnv("MOZ_CRASHREPORTER_NO_REPORT");
  DenStripEnv("MOZ_CRASHREPORTER_SHUTDOWN");
  DenStripEnv("MOZ_CRASHREPORTER_FULLDUMP");
  DenStripEnv("MOZ_CRASHREPORTER_RESTART_ARG_0");

  // Profiler — writes performance samples (incl. JS source frames) to disk.
  DenStripEnv("MOZ_PROFILER_STARTUP");
  DenStripEnv("MOZ_PROFILER_STARTUP_INTERVAL");
  DenStripEnv("MOZ_PROFILER_STARTUP_FEATURES");
  DenStripEnv("MOZ_PROFILER_STARTUP_FEATURES_BITFIELD");
  DenStripEnv("MOZ_PROFILER_STARTUP_FILTERS");
  DenStripEnv("MOZ_PROFILER_SHUTDOWN");
  DenStripEnv("MOZ_PROFILER_HELP");

  // gtest / fuzzer entry points — enable special test-only execution paths.
  DenStripEnv("MOZ_RUN_GTEST");
  DenStripEnv("FUZZER");
  DenStripEnv("MOZ_FUZZ");
  DenStripEnv("MOZ_GMP_SANDBOX_LOGGING");
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
    '  // DenBrowser: strip blocked argv flags and environment variables\n'
    '  // before any other Firefox code reads them.\n'
    '  DenBrowserStripBlockedArgs();\n'
    '  DenBrowserStripBlockedEnv();\n'
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
with open(patch_path, encoding='utf-8') as f:
    patch = f.read()

# Find the "--- a/" marker that starts the diff section.
diff_start = patch.find('\n--- a/')
if diff_start == -1:
    print('ERROR: could not locate diff section in patch file.', file=sys.stderr)
    sys.exit(1)

updated = patch[:diff_start + 1] + new_diff  # +1 keeps the preceding newline

with open(patch_path, 'w', encoding='utf-8', newline='\n') as f:
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
