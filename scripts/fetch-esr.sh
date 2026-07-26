#!/usr/bin/env bash
# fetch-esr.sh — Download the latest Firefox ESR source tarball
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"

VERSIONS_URL="https://product-details.mozilla.org/1.0/firefox_versions.json"
DOWNLOAD_BASE="https://archive.mozilla.org/pub/firefox/releases"

PINNED_VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ffversion) PINNED_VERSION="$2"; shift ;;
        *) echo "[fetch-esr] Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

if [[ -n "$PINNED_VERSION" ]]; then
    ESR_VERSION="${PINNED_VERSION}esr"
    echo "[fetch-esr] Using pinned Firefox ESR version: $ESR_VERSION"
else
    echo "[fetch-esr] Fetching version metadata..."
    if VERSIONS_JSON=$(curl -fsSL --max-time 10 "$VERSIONS_URL" 2>/dev/null); then
        ESR_VERSION=$(echo "$VERSIONS_JSON" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['FIREFOX_ESR'])")
        if [[ -z "$ESR_VERSION" ]]; then
            echo "[fetch-esr] ERROR: Could not determine ESR version from metadata." >&2
            exit 1
        fi
        echo "[fetch-esr] Latest Firefox ESR: $ESR_VERSION"
    elif [[ -f "$SRC_DIR/.esr_version" ]]; then
        ESR_VERSION=$(cat "$SRC_DIR/.esr_version")
        echo "[fetch-esr] WARNING: Network unavailable; using cached version: $ESR_VERSION"
    else
        echo "[fetch-esr] ERROR: Network unavailable and no cached version found." >&2
        exit 1
    fi
fi

TARBALL="firefox-${ESR_VERSION}.source.tar.xz"
DOWNLOAD_URL="${DOWNLOAD_BASE}/${ESR_VERSION}/source/${TARBALL}"
# Mozilla publishes SHA512SUMS at the release root, not in the source/ subdirectory.
# The file contains lines like: <hash>  source/firefox-128.8.0esr.source.tar.xz
SHA512SUMS_URL="${DOWNLOAD_BASE}/${ESR_VERSION}/SHA512SUMS"

mkdir -p "$SRC_DIR"

if [[ -f "$SRC_DIR/$TARBALL" ]]; then
    echo "[fetch-esr] Tarball already present, skipping download."
else
    echo "[fetch-esr] Downloading $TARBALL..."
    curl -fL --progress-bar -o "$SRC_DIR/$TARBALL" "$DOWNLOAD_URL"

    echo "[fetch-esr] Downloading SHA512SUMS..."
    curl -fsSL -o "$SRC_DIR/SHA512SUMS" "$SHA512SUMS_URL"

    echo "[fetch-esr] Verifying checksum..."
    # Lines in SHA512SUMS look like: <hash>  source/firefox-128.8.0esr.source.tar.xz
    EXPECTED_SHA=$(grep "source/${TARBALL}$" "$SRC_DIR/SHA512SUMS" | awk '{print $1}')
    ACTUAL_SHA=$(shasum -a 512 "$SRC_DIR/$TARBALL" | awk '{print $1}')

    if [[ -z "$EXPECTED_SHA" ]]; then
        echo "[fetch-esr] ERROR: Could not find checksum for $TARBALL in SHA512SUMS." >&2
        exit 1
    fi

    if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
        echo "[fetch-esr] ERROR: Checksum mismatch! Deleting corrupt file." >&2
        rm -f "$SRC_DIR/$TARBALL"
        exit 1
    fi
    echo "[fetch-esr] Checksum OK."
fi

EXTRACT_DIR="$SRC_DIR/firefox-${ESR_VERSION%esr}"
if [[ -d "$EXTRACT_DIR" ]]; then
    echo "[fetch-esr] Source already extracted at $EXTRACT_DIR"
else
    echo "[fetch-esr] Extracting (this may take a few minutes)..."
    tar -xJf "$SRC_DIR/$TARBALL" -C "$SRC_DIR"
    echo "[fetch-esr] Extracted to $EXTRACT_DIR"
fi

# No pristine snapshot is taken here: apply-patches.sh records its own baseline
# from the handful of files the patch set actually touches, which is instant.

# Write version file so other scripts can reference it
echo "$ESR_VERSION" > "$SRC_DIR/.esr_version"
echo "[fetch-esr] Done. Source ready at: $EXTRACT_DIR"
