#!/usr/bin/env bash
# strip-test-files.sh — Remove test files from a Firefox ESR source tarball.
#
# Usage: ./scripts/strip-test-files.sh [INPUT_TARBALL] [-o OUTPUT_TARBALL]
#        ./scripts/strip-test-files.sh --list INPUT_TARBALL
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"

INPUT=""
OUTPUT=""
LIST_ONLY=0
XZ_THREADS=0   # 0 = auto (use all cores)
XZ_LEVEL=6     # balance of speed vs size; original Mozilla tarballs use -9

# Convert a possibly-Windows path (C:\... or with backslashes) to MSYS/POSIX form.
# GNU tar treats a leading "drive:" as a remote host (host:path syntax), so an
# output like C:\...\out.tar.xz makes it try to "connect to C". cygpath -u fixes
# this by yielding /c/... ; the fallback just swaps backslashes for slashes.
to_posix() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        printf '%s\n' "${1//\\//}"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)   OUTPUT="$2"; shift ;;
        --list)        LIST_ONLY=1 ;;
        --xz-level)    XZ_LEVEL="$2"; shift ;;
        --xz-threads)  XZ_THREADS="$2"; shift ;;
        -h|--help)
            echo "Usage: $0 [INPUT_TARBALL] [-o OUTPUT_TARBALL] [--list] [--xz-level N] [--xz-threads N]"
            echo ""
            echo "  INPUT_TARBALL   Path to firefox-*esr.source.tar.xz"
            echo "                  Defaults to the newest such file in src/"
            echo "  -o OUTPUT       Destination path (default: <input>-stripped.tar.xz)"
            echo "  --list          Print the directories that would be removed, then exit"
            echo "  --xz-level N    xz compression level 1-9 (default: 6)"
            echo "  --xz-threads N  xz thread count (default: 0 = all cores)"
            exit 0 ;;
        -*) echo "[strip-test-files] Unknown flag: $1" >&2; exit 1 ;;
        *)
            if [[ -z "$INPUT" ]]; then
                INPUT="$1"
            else
                echo "[strip-test-files] Unexpected argument: $1" >&2; exit 1
            fi ;;
    esac
    shift
done

# ── Resolve input ─────────────────────────────────────────────────────────────

if [[ -z "$INPUT" ]]; then
    INPUT=$(ls -t "$SRC_DIR"/firefox-*esr.source.tar.xz 2>/dev/null | head -1 || true)
    if [[ -z "$INPUT" ]]; then
        echo "[strip-test-files] ERROR: No firefox-*esr.source.tar.xz found in $SRC_DIR" >&2
        echo "[strip-test-files] Pass the tarball path explicitly." >&2
        exit 1
    fi
    echo "[strip-test-files] Auto-detected input: $INPUT"
fi

if [[ ! -f "$INPUT" ]]; then
    echo "[strip-test-files] ERROR: File not found: $INPUT" >&2
    exit 1
fi

INPUT="$(to_posix "$INPUT")"
INPUT="$(cd "$(dirname "$INPUT")" && pwd)/$(basename "$INPUT")"

# ── List-only mode ─────────────────────────────────────────────────────────────

if [[ $LIST_ONLY -eq 1 ]]; then
    echo "[strip-test-files] Scanning archive (streaming — may take a minute)..."
    # Print entries whose path component matches any test-dir name
    tar -tf "$INPUT" | grep -E \
        '/(testing|test|tests|mochitest|mochitests|reftest|reftests|crashtests|crashtest|jit-test|gtest)(/|$)' \
        | head -50
    echo "..."
    echo "[strip-test-files] (truncated to 50 lines; rerun without --list to strip)"
    exit 0
fi

# ── Resolve output ─────────────────────────────────────────────────────────────

if [[ -z "$OUTPUT" ]]; then
    base="$(basename "$INPUT" .tar.xz)"
    OUTPUT="$(dirname "$INPUT")/${base}-stripped.tar.xz"
fi
OUTPUT="$(to_posix "$OUTPUT")"

if [[ -e "$OUTPUT" ]]; then
    echo "[strip-test-files] ERROR: Output file already exists: $OUTPUT" >&2
    echo "[strip-test-files] Delete it or pass -o to specify a different path." >&2
    exit 1
fi

echo "[strip-test-files] Input:  $INPUT  ($(du -sh "$INPUT" | cut -f1))"
echo "[strip-test-files] Output: $OUTPUT"

# ── Work in a temp directory ───────────────────────────────────────────────────
# Created next to the input tarball so you can add that one folder to your AV
# exclusion list and avoid it scanning every file as it's written.

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
TMPDIR_WORK="$(dirname "$INPUT")/temp-${TIMESTAMP}"
mkdir -p "$TMPDIR_WORK"
echo "[strip-test-files] Working directory: $TMPDIR_WORK"
echo "[strip-test-files] Add this path to your AV exclusions to avoid scan interference."

cleanup() { echo "[strip-test-files] Cleaning up $TMPDIR_WORK..."; rm -rf "$TMPDIR_WORK"; }
trap cleanup EXIT

echo "[strip-test-files] Extracting archive (this takes several minutes for a ~600 MB xz tarball)..."
tar -xJf "$INPUT" -C "$TMPDIR_WORK"

FF_DIR=$(ls -d "$TMPDIR_WORK"/firefox-*/ 2>/dev/null | head -1 || true)
if [[ -z "$FF_DIR" ]]; then
    echo "[strip-test-files] ERROR: No firefox-* directory found after extraction." >&2
    exit 1
fi
FF_DIRNAME=$(basename "${FF_DIR%/}")

BEFORE_KB=$(du -sk "$FF_DIR" | cut -f1)

# ── Neutralize test payloads (keep the build graph intact) ────────────────────
#
# Rather than DELETING test files — which breaks the build wherever a moz.build
# references a test-dir path (DIRS, *_MANIFESTS, and especially GeneratedFile
# inputs whose paths are computed dynamically and so can't be found statically) —
# we keep every file and directory and blank only the CONTENTS of payload files
# (.html/.js/.svg/... fixtures) inside test dirs. Build inputs (.yaml/.pem/.conf/...,
# plus anything a moz.build names as a real input) are kept intact. Because no path
# is ever removed, the configure/emitter stage cannot fail on a missing file.

echo "[strip-test-files] Blanking test payload files (keeping the build graph intact)..."
python3 "$SCRIPT_DIR/blank-test-payloads.py" "$FF_DIR"

AFTER_KB=$(du -sk "$FF_DIR" | cut -f1)
REMOVED_MB=$(( (BEFORE_KB - AFTER_KB) / 1024 ))
echo "[strip-test-files] Blanked approximately ${REMOVED_MB} MB of test payload content."

# ── Repack ─────────────────────────────────────────────────────────────────────

echo "[strip-test-files] Repacking with xz -${XZ_LEVEL} -T${XZ_THREADS} (this takes several minutes)..."
XZ_OPT="-${XZ_LEVEL} -T${XZ_THREADS}" tar -cJf "$OUTPUT" -C "$TMPDIR_WORK" "$FF_DIRNAME"

OUT_SIZE=$(du -sh "$OUTPUT" | cut -f1)
IN_SIZE=$(du -sh "$INPUT" | cut -f1)
echo "[strip-test-files] Original archive: $IN_SIZE"
echo "[strip-test-files] Stripped archive: $OUT_SIZE"
echo "[strip-test-files] Done: $OUTPUT"
