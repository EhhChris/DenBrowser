#!/usr/bin/env bash
# apply-patches.sh — Apply all DenBrowser patches to the Firefox ESR source tree
# Usage: ./scripts/apply-patches.sh [--skip-patch N]...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"
PATCHES_DIR="$ROOT_DIR/patches"

SKIP_PATCH_NUMS=()
NO_REVERT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-patch) SKIP_PATCH_NUMS+=("$((10#$2))"); shift ;;
        --no-revert)  NO_REVERT=1 ;;
        *) echo "[apply-patches] Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

VERSION_FILE="$SRC_DIR/.esr_version"
if [[ ! -f "$VERSION_FILE" ]]; then
    echo "[apply-patches] ERROR: Run fetch-esr.sh first." >&2
    exit 1
fi

ESR_VERSION=$(cat "$VERSION_FILE")
FIREFOX_SRC="$SRC_DIR/firefox-${ESR_VERSION%esr}"

if [[ ! -d "$FIREFOX_SRC" ]]; then
    echo "[apply-patches] ERROR: Firefox source not found at $FIREFOX_SRC" >&2
    exit 1
fi

# Pristine baseline.  Before the first patch touches the tree we copy aside each
# file the patch set will modify and record each path it will create, so a revert
# is ~70 file operations instead of snapshotting all 350k files in the tree.
# The manifest is written from the patches actually queued for this run, so
# dropping a patch later still reverts the files it used to touch.
BACKUP_DIR="$SRC_DIR/.pristine-backup-${ESR_VERSION%esr}"
MANIFEST="$BACKUP_DIR/manifest.tsv"

restore_pristine() {
    local path kind
    while IFS=$'\t' read -r path kind; do
        [[ -n "$path" ]] || continue
        case "$kind" in
            MODIFIED)
                mkdir -p "$FIREFOX_SRC/$(dirname "$path")"
                cp -p "$BACKUP_DIR/files/$path" "$FIREFOX_SRC/$path" ;;
            CREATED)
                rm -rf "${FIREFOX_SRC:?}/$path" ;;
        esac
    done < "$MANIFEST"
    rm -rf "$BACKUP_DIR"
}

# Highest ancestor of $1 that does not yet exist, so reverting also removes the
# directories a patch introduces along with whatever later steps (the branding
# asset copies below) drop inside them.
topmost_missing() {
    local path="$1" parent
    while parent="$(dirname "$path")"; [[ "$parent" != "." && ! -e "$FIREFOX_SRC/$parent" ]]; do
        path="$parent"
    done
    echo "$path"
}

snapshot_pristine() {
    local patch_file path
    mkdir -p "$BACKUP_DIR/files"
    for patch_file in ${PATCH_QUEUE[@]+"${PATCH_QUEUE[@]}"}; do
        sed -n -e 's@^+++ b/@@p' -e 's@^--- a/@@p' "$patch_file"
    done | sort -u | while read -r path; do
        [[ -n "$path" && "$path" != "/dev/null" ]] || continue
        if [[ -e "$FIREFOX_SRC/$path" ]]; then
            mkdir -p "$BACKUP_DIR/files/$(dirname "$path")"
            cp -p "$FIREFOX_SRC/$path" "$BACKUP_DIR/files/$path"
            printf '%s\tMODIFIED\n' "$path"
        else
            printf '%s\tCREATED\n' "$(topmost_missing "$path")"
        fi
    done | sort -u > "$MANIFEST"
}

echo "[apply-patches] Applying patches to $FIREFOX_SRC"
echo "[apply-patches] Patch directory: $PATCHES_DIR"
if [[ ${#SKIP_PATCH_NUMS[@]} -gt 0 ]]; then
    echo "[apply-patches] Skipping patch(es): ${SKIP_PATCH_NUMS[*]}"
fi

APPLIED=0
SKIPPED=0
FAILED=0
PATCH_QUEUE=()

for patch_file in "$PATCHES_DIR"/*.patch; do
    [[ -f "$patch_file" ]] || continue
    patch_name="$(basename "$patch_file")"

    # Skip placeholder-only patches (marked with STUB header)
    if head -5 "$patch_file" | grep -q "^# STUB"; then
        echo "[apply-patches] SKIP (stub not yet implemented): $patch_name"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Skip patches requested via --skip-patch
    if [[ ${#SKIP_PATCH_NUMS[@]} -gt 0 ]]; then
        patch_num=$((10#${patch_name%%[^0-9]*}))
        for skip in "${SKIP_PATCH_NUMS[@]}"; do
            if [[ $patch_num -eq $skip ]]; then
                echo "[apply-patches] SKIP (--skip-patch $skip): $patch_name"
                SKIPPED=$((SKIPPED + 1))
                continue 2
            fi
        done
    fi

    PATCH_QUEUE+=("$patch_file")
done

if [[ $NO_REVERT -eq 1 ]]; then
    echo "[apply-patches] Skipping revert (--no-revert)"
elif [[ -f "$MANIFEST" ]]; then
    echo "[apply-patches] Reverting source to pristine state..."
    restore_pristine
    echo "[apply-patches] Source reverted."
fi

if [[ -f "$MANIFEST" ]]; then
    echo "[apply-patches] Keeping existing pristine baseline: $BACKUP_DIR"
else
    echo "[apply-patches] Recording pristine baseline..."
    snapshot_pristine
    echo "[apply-patches] Baseline recorded ($(wc -l < "$MANIFEST" | tr -d ' ') paths): $BACKUP_DIR"
fi

for patch_file in ${PATCH_QUEUE[@]+"${PATCH_QUEUE[@]}"}; do
    patch_name="$(basename "$patch_file")"
    echo "[apply-patches] Applying: $patch_name"
    if (cd "$FIREFOX_SRC" && GIT_CEILING_DIRECTORIES="$ROOT_DIR" git apply --no-index -p1 --check "$patch_file") 2>/dev/null; then
        (cd "$FIREFOX_SRC" && GIT_CEILING_DIRECTORIES="$ROOT_DIR" git apply --no-index -p1 "$patch_file")
        echo "[apply-patches]   OK: $patch_name"
        APPLIED=$((APPLIED + 1))
    else
        echo "[apply-patches]   FAILED: $patch_name" >&2
        echo "[apply-patches]   Run manually: (cd $FIREFOX_SRC && GIT_CEILING_DIRECTORIES=$ROOT_DIR git apply --no-index -p1 $patch_file)" >&2
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "[apply-patches] Applied: $APPLIED  Skipped: $SKIPPED  Failed: $FAILED"
[[ $FAILED -eq 0 ]] || exit 1

# ── Windows branding binary assets ───────────────────────────────────────────
# These binary files are required by browser/branding/denbrowser/ on Windows builds.
# Each asset is sourced from this repo's branding/denbrowser/ if present (custom
# DenBrowser art), otherwise from Firefox nightly branding as a placeholder. As
# more assets are authored in-repo they automatically override the nightly copy;
# the nightly fallback shrinks toward zero.  See TASKS.md §4a/§4b for the split.
DENBROWSER_BRANDING="$FIREFOX_SRC/browser/branding/denbrowser"
NIGHTLY_BRANDING="$FIREFOX_SRC/browser/branding/nightly"
REPO_BRANDING="$ROOT_DIR/branding/denbrowser"

if [[ -d "$REPO_BRANDING" || -d "$NIGHTLY_BRANDING" ]]; then
    echo "[apply-patches] Installing branding binary assets to denbrowser branding..."
    mkdir -p "$DENBROWSER_BRANDING/stubinstaller" "$DENBROWSER_BRANDING/msix/Assets" "$DENBROWSER_BRANDING/content"
    for asset in \
        VisualElements_150.png VisualElements_70.png \
        PrivateBrowsing_150.png PrivateBrowsing_70.png \
        firefox.ico firefox64.ico document.ico document_pdf.ico \
        newwindow.ico newtab.ico pbmode.ico \
        background.png \
        default22.png default24.png \
        disk.icns document.icns dsstore firefox.icns \
        content/about-logo.png content/about-logo@2x.png \
        content/about-logo-private.png content/about-logo-private@2x.png \
        content/about.png \
        stubinstaller/bgstub.jpg \
        wizHeader.bmp wizHeaderRTL.bmp wizWatermark.bmp \
        msix/Assets/Document44x44.png \
        msix/Assets/LargeTile.scale-200.png \
        msix/Assets/SmallTile.scale-200.png \
        msix/Assets/Square150x150Logo.scale-200.png \
        msix/Assets/Square44x44Logo.altform-lightunplated_targetsize-256.png \
        msix/Assets/Square44x44Logo.altform-unplated_targetsize-256.png \
        msix/Assets/Square44x44Logo.scale-200.png \
        msix/Assets/Square44x44Logo.targetsize-256.png \
        msix/Assets/StoreLogo.scale-200.png \
        msix/Assets/Wide310x150Logo.scale-200.png \
        content/about-logo.svg content/about-wordmark.svg \
        content/document_pdf.svg content/firefox-wordmark.svg \
        stubinstaller/installing_page.css \
        stubinstaller/profile_cleanup_page.css; do
        mkdir -p "$(dirname "$DENBROWSER_BRANDING/$asset")"
        if [[ -f "$REPO_BRANDING/$asset" ]]; then
            cp "$REPO_BRANDING/$asset" "$DENBROWSER_BRANDING/$asset"
            echo "[apply-patches]   Copied (repo):    $asset"
        elif [[ -f "$NIGHTLY_BRANDING/$asset" ]]; then
            cp "$NIGHTLY_BRANDING/$asset" "$DENBROWSER_BRANDING/$asset"
            echo "[apply-patches]   Copied (nightly): $asset"
        else
            echo "[apply-patches]   WARNING: $asset not found in repo or nightly branding" >&2
        fi
    done
fi
