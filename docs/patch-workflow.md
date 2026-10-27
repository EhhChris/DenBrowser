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

Assume the branch is currently on `FIREFOX_<OLD>esr_RELEASE` and you're moving to
`FIREFOX_<NEW>esr_RELEASE`. Both tags must exist in `../firefox`
(`git -C ../firefox fetch upstream --tags`).

Set Git's comment character before starting the rebase. Patch documentation
uses `#` lines, which Git's default message cleanup otherwise removes when
editing a commit message after resolving conflicts. Using `;` keeps those
lines while still removing Git's generated editor comments.

```bash
cd ../firefox
git config rerere.enabled true          # reuse each resolution across retries
git config --local core.commentChar ';' # preserve # PATCH documentation

# Replay the patch commits from the old base onto the new ESR tag.
git rebase --onto FIREFOX_<NEW>esr_RELEASE FIREFOX_<OLD>esr_RELEASE DenBrowser
#   ...resolve conflicts commit-by-commit:
#     edit files → git add <file> → GIT_EDITOR=true git rebase --continue
#   A patch upstream has made redundant may go empty — drop it (git rebase --skip)
#     and delete its patches/ file. If a resolution changes WHAT a patch does,
#     also edit that commit's body so the regenerated comment stays truthful.

git tag denbrowser-<NEW>esr-1           # snapshot the branch tip
```

Then regenerate the files in this repo and verify:

```bash
cd ../DenBrowser
scripts/gen-patches.sh --base-tag FIREFOX_<NEW>esr_RELEASE   # rewrites patches/*.patch

# Round-trip check: re-seed a throwaway branch from the files; it must reproduce
# the branch exactly.
scripts/seed-fork-branch.sh --base-tag FIREFOX_<NEW>esr_RELEASE --branch _roundtrip
git -C ../firefox diff --quiet DenBrowser _roundtrip && echo "round-trip OK"
git -C ../firefox switch DenBrowser && git -C ../firefox branch -D _roundtrip

# Build gate: fetch the new ESR tarball, apply the regenerated patches, build.
./build.sh --ffversion <NEW>            # (see build.sh --help)
```

Commit the refreshed `patches/`, then push the fork branch/tags as desired.

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

To rebuild the branch from the patch **files** (e.g. discarding a bad rebase):

```bash
cd ../firefox && git branch -D DenBrowser          # old tips stay under their tags
cd ../DenBrowser
scripts/seed-fork-branch.sh --base-tag FIREFOX_<CUR>esr_RELEASE --branch DenBrowser
git -C ../firefox tag denbrowser-<CUR>esr-1
```

Then rebase onto the target ESR as above.
