# DenBrowser patch workflow

DenBrowser's security patches are maintained as **one commit per patch** on a
long-lived `DenBrowser` branch of the Firefox fork at `../firefox`, and mirrored
into this repo as `patches/NNN-*.patch` files.

- **Source of truth = the `DenBrowser` branch** (an ESR release tag + one commit
  per patch). This is where conflicts are resolved during an ESR bump, using
  git's real 3-way merge.
- **`patches/` is a generated artifact**, regenerated from the branch. `build.sh`
  consumes the `patches/` files (fetch ESR tarball → `apply-patches.sh` → build).

Two scripts move between the two representations:

| Script | Direction | When |
|--------|-----------|------|
| `scripts/seed-fork-branch.sh` | patch files → per-patch commits on a fresh branch | **bootstrap** (first time, or a deliberate restart) |
| `scripts/gen-patches.sh` | branch commits → `patches/NNN-*.patch` | **after every rebase** |

## Conventions

- **Branch:** `DenBrowser` — the single moving branch. It sits on the current ESR
  release tag with the patch commits on top.
- **Tags:** `denbrowser-<esr-version>-<rev>` snapshot the branch tip per ESR
  (e.g. `denbrowser-140.13.0esr-1`). Bump `<rev>` for a rebuild against the same ESR.
  Old tags are kept, so any prior snapshot stays recoverable.
- **One commit per patch.** Commit **subject = patch filename stem**
  (e.g. `014-site-filter`); commit **body = the `# PATCH:` doc block, verbatim**
  (the MPL header is *not* in the body — `gen-patches.sh` re-adds it).
- **Patch file layout:** 3-line MPL header + blank + `# PATCH:` doc block + blank
  + `diff --git` body.
- **STUB patches** (first content line `# STUB`, e.g. `007-ramdisk-profile.patch`)
  have **no commit**. `seed` skips them; `gen` never emits them; the file is left
  untouched.
- **Branding binaries** are *not* in any patch or on the branch —
  `apply-patches.sh` copies them from this repo's `branding/denbrowser/` (falling
  back to Firefox `nightly`) at build time. See `apply-patches.sh`.

## Recurring workflow: bump to a new ESR

Use the latest **DenBrowser snapshot**, not just the old Firefox ESR base. A
fetch makes commits and tags available but does not update your local
`DenBrowser` branch. Rebasing a stale branch can silently omit newer patches
and replay older versions of existing patches.

Run the following blocks in the same Bash session. Replace the example values
with the intended releases; select `OLD_SNAPSHOT` after checking the available
DenBrowser tags. `origin` is the DenBrowser fork and `upstream` is Mozilla.

```bash
cd ../firefox
git fetch origin --tags || exit 1
git fetch upstream --tags || exit 1
git tag --list 'denbrowser-*' --sort=-version:refname | head -20

OLD_BASE=FIREFOX_153_6_0esr_RELEASE
OLD_SNAPSHOT=denbrowser-153.6.0esr-4
NEW_BASE=FIREFOX_153_7_0esr_RELEASE
NEW_VERSION=153.7.0esr
NEW_TAG=denbrowser-${NEW_VERSION}-1

# Stop if the local branch does not contain the latest intended snapshot.
git merge-base --is-ancestor "$OLD_SNAPSHOT" DenBrowser || {
    echo "STOP: DenBrowser is missing the intended starting snapshot."
    exit 1
}
git merge-base --is-ancestor "$OLD_BASE" DenBrowser || exit 1
git switch DenBrowser
git status --short
```

Commit or preserve outstanding work before continuing. If the snapshot check
fails, inspect the local branch, `origin/DenBrowser`, and `OLD_SNAPSHOT` before
choosing the starting point. Fetching or pulling the remote branch alone is
not sufficient if that branch is also stale. Do not bypass the check or reset
away local work. For an already-completed bad rebase, use the recovery section
below.

Create a backup and compare the branch's patch inventory with the saved files
**before regeneration**. STUBs have no commit. Investigate any difference; an
intentionally retired patch must be reviewed and its saved file removed.
The generator currently checks commit documentation but does **not** reject
saved patch files that have no corresponding commit, so this check is required.

```bash
BACKUP=backup/denbrowser-before-${NEW_VERSION}-$(date +%Y%m%d-%H%M%S)
git branch "$BACKUP" DenBrowser
AUDIT_DIR=$(mktemp -d)
PATCHES_DIR=$(cd ../DenBrowser/patches && pwd)

git log --format=%s "$OLD_BASE..$BACKUP" | LC_ALL=C sort > "$AUDIT_DIR/before.txt"
for pf in "$PATCHES_DIR"/*.patch; do
    if head -5 "$pf" | grep -q '^# STUB'; then continue; fi
    basename "$pf" .patch
done | LC_ALL=C sort > "$AUDIT_DIR/files.txt"
diff -u "$AUDIT_DIR/files.txt" "$AUDIT_DIR/before.txt" || {
    echo "STOP: saved patches and branch commits disagree."
    exit 1
}
```

Set Git's comment character before rebasing. Patch documentation uses `#`
lines, which Git's default message cleanup otherwise removes when editing a
commit message after resolving conflicts. Using `;` preserves those lines.

```bash
git config rerere.enabled true
git config --local core.commentChar ';'
git rebase --onto "$NEW_BASE" "$OLD_BASE" DenBrowser
# Resolve conflicts: edit files, git add <file>, then:
# GIT_EDITOR=true git rebase --continue
```

Skip an empty patch only after confirming that upstream supplies its behavior;
record why and remove its saved patch file. If a resolution changes behavior,
update that commit's documentation too. A completed rebase is not sufficient
verification: compare the patch subjects and review each change in range-diff.
Patch counts alone cannot detect older versions of existing patches.

```bash
git log --format=%s "$NEW_BASE..DenBrowser" | LC_ALL=C sort > "$AUDIT_DIR/after.txt"
diff -u "$AUDIT_DIR/before.txt" "$AUDIT_DIR/after.txt"
git range-diff "$OLD_BASE..$BACKUP" "$NEW_BASE..DenBrowser"
```

Stop on unexplained additions, omissions, or content changes. For deliberately
retired patches, reconcile the saved-file inventory and document the reviewed
before/after difference before proceeding. Then regenerate and verify:

```bash
cd ../DenBrowser
scripts/gen-patches.sh --base-tag "$NEW_BASE" || exit 1

# Round-trip: requires a clean Firefox checkout, including no untracked files.
# Choose an unused throwaway branch name; seed resets an existing branch.
ROUNDTRIP=_roundtrip-$(date +%Y%m%d-%H%M%S)
scripts/seed-fork-branch.sh --base-tag "$NEW_BASE" --branch "$ROUNDTRIP" || exit 1
git -C ../firefox diff --quiet DenBrowser "$ROUNDTRIP" || {
    echo "STOP: round-trip tree differs from DenBrowser."
    exit 1
}
git -C ../firefox switch DenBrowser
git -C ../firefox branch -D "$ROUNDTRIP"

# Build gate: fetch the target ESR tarball, apply regenerated patches, build.
./build.sh --ffversion "${NEW_VERSION%esr}" || exit 1    # see build.sh --help
```

Only after the inventory, range-diff, round-trip, and build checks pass, create
the release tag. If the build has not been run, record that limitation and do
not treat the snapshot as a validated release.

```bash
git -C ../firefox tag "$NEW_TAG" DenBrowser
```

Review and commit the refreshed `patches/`, then push the fork branch and tag
as desired. A rebased published branch requires a coordinated history update;
use `--force-with-lease`, not an unconditional force push. Keep the backup
until verification and publication are complete.

## Recovering a rebase from a stale branch

Back up the bad branch first. Create a separate recovery branch from the latest
known-good DenBrowser snapshot and rebase that complete stack onto the new ESR
base. Do not cherry-pick only the missing last patch: earlier patches may also
have newer versions or prerequisites in the known-good snapshot.

```bash
cd ../firefox
# Set OLD_BASE, OLD_SNAPSHOT, NEW_BASE, and NEW_TAG as above.
BAD_BACKUP=backup/denbrowser-bad-rebase-$(date +%Y%m%d-%H%M%S)
RECOVERY=recover/denbrowser-$(date +%Y%m%d-%H%M%S)
git branch "$BAD_BACKUP" DenBrowser
git switch -c "$RECOVERY" "$OLD_SNAPSHOT"
git -c core.commentChar=';' rebase --onto "$NEW_BASE" "$OLD_BASE"
```

Repeat the inventory and range-diff checks against `OLD_SNAPSHOT`, using the
recovery branch in place of `DenBrowser`. Regenerate with
`gen-patches.sh --base-tag "$NEW_BASE" --branch "$RECOVERY"` and verify the
round-trip against that branch. After verification, switch back to
`"$RECOVERY"`, move `DenBrowser` to it with `git branch -f DenBrowser "$RECOVERY"`,
and switch back to `DenBrowser`. Preserve the backup and unrelated local files.

Prefer a new revision tag for a published release. If deliberately correcting
an incorrect existing tag, preserve its old target, record the remote branch
and tag object IDs with `git ls-remote origin`, and move the local tag with
`git tag -f "$NEW_TAG" DenBrowser`. This command is for the lightweight snapshot
tags used here; annotated or signed tags require recreating their metadata.

Publish the corrected branch and tag together with explicit leases and an
atomic push. Set these variables to the exact object IDs just reviewed, not
values refreshed automatically during the push:

```bash
# EXPECTED_BRANCH=<reviewed remote refs/heads/DenBrowser object ID>
# EXPECTED_TAG=<reviewed remote refs/tags/$NEW_TAG object ID>
git push --atomic \
    --force-with-lease="refs/heads/DenBrowser:$EXPECTED_BRANCH" \
    --force-with-lease="refs/tags/$NEW_TAG:$EXPECTED_TAG" \
    origin DenBrowser:refs/heads/DenBrowser "$NEW_TAG:refs/tags/$NEW_TAG"
```

A lease failure means someone changed the remote: inspect it before retrying.
Tell collaborators that the tag moved; ordinary fetches do not overwrite an
existing local tag. After preserving any local work, they can explicitly fetch
the replacement with `git fetch origin "refs/tags/$NEW_TAG:refs/tags/$NEW_TAG" --force`.

## Missing patch documentation after a rebase

If `gen-patches.sh` reports an invalid documentation body with `Found: <empty>`,
the commit's `# PATCH:` block may have been stripped during conflict resolution.
The generator stops before writing any files so the saved documentation remains
available.

Back up the fork branch, set `core.commentChar` as above, and use an interactive
rebase to edit the affected commits. Restore each complete message (subject,
blank line, documentation body) from the pre-rebase commit or the corresponding
patch file's documentation header. When supplying a message file, use
`git commit --amend --cleanup=whitespace -F <message-file>`, then continue the
rebase. Check that the repaired branch has the same tree as the backup before
regenerating patches. Review the restored documentation if conflict resolution
changed the patch's behavior.

Repairing messages changes commit IDs, including those of later commits. Keep
the backup until verification is complete; updating an already-pushed branch
requires coordinating the history rewrite and pushing with `--force-with-lease`.

## Patch change statistics

`scripts/patch-stats.py` reports each tagged patch commit's Firefox source-line
changes, split into code, comment-only, and blank additions/deletions. By
default it selects the newest stable `denbrowser-*` tag in `../firefox` and
infers its nearest `FIREFOX_*esr_RELEASE` base:

```bash
scripts/patch-stats.py
```

For a reproducible historical source report, specify both tags explicitly:

```bash
scripts/patch-stats.py \
  --base-tag FIREFOX_153_1_0esr_RELEASE \
  --tag denbrowser-153.1.0esr-2
```

Use `--show-files` for rows beneath each patch or `--format json` for structured
output. A changed line containing code and a trailing comment counts as code;
only comment-only lines count as comments. Patch MPL/rationale headers, commit
messages, and unified-diff metadata do not count toward source lines. The
classifier uses each complete before/after source file, so multiline comment
state carries across unchanged hunks. It fails on unsupported text types rather
than silently guessing, and checks each categorized total against Git's
`--numstat` total so no changed text lines are omitted.

Rows marked `[local stub]` come from this repo's current `patches/` manifest,
because stubs have no Firefox commit or tag object. Use `--no-local-stubs` for a
strictly tag-contained historical report. `PATCH CHURN` sums every
parent-to-commit patch diff, so its `FILES` count is file-change occurrences and
a later patch can count a path or line again. `FINAL TREE` is the direct
ESR-base-to-tag delta. Binary changes increment `BIN` but have no line counts.

Run the focused tests after changing the classifier:

```bash
python3 -m unittest discover -s test/patch_stats -p 'test_*.py'
```

## Restart from scratch (re-bootstrap)

To rebuild from the patch **files**, preserve the existing branch and seed an
unused branch first. Use this only when the files are the reviewed, complete
patch set; for a stale-branch rebase, prefer the known-good snapshot recovery
above. The Firefox checkout must be clean, including no untracked files.

```bash
cd ../DenBrowser
# Set OLD_BASE to the ESR base the saved patches were generated against.
RESEED=reseed/denbrowser-$(date +%Y%m%d-%H%M%S)
scripts/seed-fork-branch.sh --base-tag "$OLD_BASE" --branch "$RESEED" || exit 1
```

Verify the seeded branch before replacing `DenBrowser`. Then follow the rebase,
verification, and tagging steps above. Do not delete the old branch or create
a release tag before verification.
