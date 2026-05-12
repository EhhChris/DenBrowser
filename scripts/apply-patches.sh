#!/usr/bin/env bash
# apply-patches.sh — Apply all ZeroFox patches to the Firefox ESR source tree
# Usage: ./scripts/apply-patches.sh [--skip-patch N]...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"
PATCHES_DIR="$ROOT_DIR/patches"

SKIP_PATCH_NUMS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-patch) SKIP_PATCH_NUMS+=("$((10#$2))"); shift ;;
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

echo "[apply-patches] Applying patches to $FIREFOX_SRC"
echo "[apply-patches] Patch directory: $PATCHES_DIR"
if [[ ${#SKIP_PATCH_NUMS[@]} -gt 0 ]]; then
    echo "[apply-patches] Skipping patch(es): ${SKIP_PATCH_NUMS[*]}"
fi

APPLIED=0
SKIPPED=0
FAILED=0

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
# These binary files are required by browser/branding/zerofox/ on Windows builds.
# Copied from nightly branding as placeholders; replace with custom ZeroFox
# artwork before distribution.
ZEROFOX_BRANDING="$FIREFOX_SRC/browser/branding/zerofox"
NIGHTLY_BRANDING="$FIREFOX_SRC/browser/branding/nightly"

if [[ -d "$NIGHTLY_BRANDING" ]]; then
    echo "[apply-patches] Copying branding binary assets to zerofox branding..."
    mkdir -p "$ZEROFOX_BRANDING/stubinstaller" "$ZEROFOX_BRANDING/msix/Assets"
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
        if [[ -f "$NIGHTLY_BRANDING/$asset" ]]; then
            cp "$NIGHTLY_BRANDING/$asset" "$ZEROFOX_BRANDING/$asset"
            echo "[apply-patches]   Copied: $asset"
        else
            echo "[apply-patches]   WARNING: $asset not found in nightly branding" >&2
        fi
    done
fi
