#!/usr/bin/env bash
# gen-patches.sh — Regenerate patches/NNN-*.patch from the fork DenBrowser branch.
#
# Inverse of seed-fork-branch.sh. For each commit in <base-tag>..<branch>, writes
#   patches/<subject>.patch =
#     3-line MPL header + blank
#     + commit body (the `# PATCH:` doc block, verbatim) + blank
#     + `git diff <commit>~1 <commit>`  (pure diff, no commit header/signature)
#
# The DenBrowser branch is the source of truth; patches/ is a generated artifact.
# STUB patches (e.g. 007-ramdisk-profile.patch) have no commit and are left as-is.
#
# Idempotent: re-running on an unchanged branch produces no diff in patches/.
# NOTE: the first run after a re-seed normalizes any hand-authored plain-unified
# patches into `diff --git` style (adds `index …` lines) — a benign one-time diff.
#
# Usage:
#   scripts/gen-patches.sh --base-tag FIREFOX_153_0esr_RELEASE \
#       [--fork ../firefox] [--branch DenBrowser]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PATCHES_DIR="$ROOT_DIR/patches"

FORK="$ROOT_DIR/../firefox"
BRANCH="DenBrowser"
BASE_TAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fork)     FORK="$2"; shift ;;
        --branch)   BRANCH="$2"; shift ;;
        --base-tag) BASE_TAG="$2"; shift ;;
        *) echo "[gen] Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

[[ -n "$BASE_TAG" ]] || { echo "[gen] ERROR: --base-tag is required" >&2; exit 1; }
FORK="$(cd "$FORK" && pwd)"

git -C "$FORK" rev-parse --verify -q "${BASE_TAG}^{commit}" >/dev/null \
    || { echo "[gen] ERROR: base tag '$BASE_TAG' not found in $FORK" >&2; exit 1; }

read -r -d '' MPL_HEADER <<'EOF' || true
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
EOF

WROTE=0
for commit in $(git -C "$FORK" rev-list --reverse "${BASE_TAG}..${BRANCH}"); do
    stem="$(git -C "$FORK" log -1 --format=%s "$commit")"
    out="$PATCHES_DIR/${stem}.patch"
    {
        printf '%s\n\n' "$MPL_HEADER"
        git -C "$FORK" log -1 --format=%b "$commit"   # the `# PATCH:` doc block
        printf '\n'
        git -C "$FORK" diff "${commit}~1" "$commit"    # pure diff
    } > "$out"
    echo "[gen]   wrote ${stem}.patch"
    WROTE=$((WROTE + 1))
done

echo ""
echo "[gen] Done. Wrote $WROTE patch files from ${BASE_TAG}..${BRANCH} (STUBs untouched)."
