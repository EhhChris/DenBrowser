#!/usr/bin/env bash
# seed-fork-branch.sh — Bootstrap a fork branch from this repo's patch FILES.
#
# Creates/resets a branch in the Firefox fork at a base tag, then replays each
# patches/NNN-*.patch as ONE commit:
#   - commit subject = patch filename stem (e.g. 014-site-filter)
#   - commit body    = the `# PATCH:` doc block, verbatim (the MPL header is dropped)
# STUB patches (first content line `# STUB`) are skipped — they get no commit.
#
# This is the BOOTSTRAP half of the workflow. The recurring half is:
#   git rebase --onto <new ESR tag> <old base> DenBrowser   (see docs/patch-workflow.md)
# then scripts/gen-patches.sh to write the files back.
#
# Usage:
#   scripts/seed-fork-branch.sh --base-tag FIREFOX_140_13_0esr_RELEASE \
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
        *) echo "[seed] Unknown flag: $1" >&2; exit 1 ;;
    esac
    shift
done

[[ -n "$BASE_TAG" ]] || { echo "[seed] ERROR: --base-tag is required" >&2; exit 1; }
FORK="$(cd "$FORK" && pwd)"

git -C "$FORK" rev-parse --verify -q "${BASE_TAG}^{commit}" >/dev/null \
    || { echo "[seed] ERROR: base tag '$BASE_TAG' not found in $FORK" >&2; exit 1; }

if [[ -n "$(git -C "$FORK" status --porcelain)" ]]; then
    echo "[seed] ERROR: $FORK has uncommitted changes; aborting." >&2
    exit 1
fi

echo "[seed] Fork:   $FORK"
echo "[seed] Branch: $BRANCH  (reset onto $BASE_TAG)"
git -C "$FORK" switch -C "$BRANCH" "$BASE_TAG" >/dev/null

# Emit the commit message for a patch file: subject (stem) + blank + `# PATCH:`
# doc block (everything from `# PATCH:` up to, but not including, the diff).
emit_msg() {
    local pf="$1"
    basename "$pf" .patch
    echo
    awk '
        /^# PATCH:/ { started=1 }
        started {
            if ($0 ~ /^diff --git / || $0 ~ /^--- / || $0 ~ /^Index: /) exit
            print
        }
    ' "$pf"
}

APPLIED=0
SKIPPED=0
TMPMSG="$(mktemp)"
trap 'rm -f "$TMPMSG"' EXIT

for pf in "$PATCHES_DIR"/*.patch; do
    [[ -f "$pf" ]] || continue
    name="$(basename "$pf")"
    stem="$(basename "$pf" .patch)"

    if head -5 "$pf" | grep -q '^# STUB'; then
        echo "[seed] SKIP (stub): $name"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # git apply ignores the leading MPL / `# PATCH:` text and applies only the
    # diff — the same behavior apply-patches.sh relies on.
    if ! git -C "$FORK" apply --index -p1 "$pf" 2>/dev/null; then
        echo "[seed] FAILED to apply: $name" >&2
        echo "[seed]   Inspect: (cd $FORK && git apply --index -p1 --reject $pf)" >&2
        exit 1
    fi

    emit_msg "$pf" > "$TMPMSG"
    git -C "$FORK" commit -q --cleanup=whitespace -F "$TMPMSG"
    echo "[seed]   committed: $stem"
    APPLIED=$((APPLIED + 1))
done

echo ""
echo "[seed] Done. Commits: $APPLIED  Skipped (stub): $SKIPPED"
echo "[seed] $BRANCH tip: $(git -C "$FORK" rev-parse --short "$BRANCH")"
