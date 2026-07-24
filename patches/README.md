> **Note:** This project and its scaffolding were built with AI assistance (Claude, Anthropic).
> Review all generated code and patches carefully before use in production.

# DenBrowser Patch Development Guide

## Workflow

**These `.patch` files are a generated artifact.** The source of truth is the
one-commit-per-patch `DenBrowser` branch of the Firefox fork at `../firefox`; the
files here are regenerated from it with `scripts/gen-patches.sh`. Do **not**
hand-edit a `.patch` file — edit the corresponding commit on the branch and
regenerate.

See **[`../docs/patch-workflow.md`](../docs/patch-workflow.md)** for the full
procedure (bumping to a new ESR, adding a patch, restarting from scratch, tag and
commit conventions).

At build time, `apply-patches.sh` applies these files (in lexicographic order,
via `git apply -p1`) to the fetched ESR tarball.

## Patch naming

`NNN-short-description.patch` — three-digit prefix for ordering.

## Stub patches

Patches with `# STUB` as the first line are skipped by `apply-patches.sh`. Remove
that line once the patch contains real diff content.

## Key Firefox source areas

| Feature | Primary source file(s) |
|---------|------------------------|
| Command-line flag stripping | `toolkit/xre/nsAppRunner.cpp` |
| Pref service / lockPref enforcement | `modules/libpref/Preferences.cpp`, `modules/libpref/Preferences.h` |
| Network I/O gating | `netwerk/base/nsIOService.cpp`, `netwerk/base/nsIOService.h` |
| Socket connections | `netwerk/socket/nsSocketTransportService.cpp` |
| Download manager | `toolkit/components/downloads/DownloadCore.jsm`, `nsExternalHelperAppService.cpp` |
| Clipboard | `widget/nsBaseClipboard.cpp`, `dom/events/ClipboardEvent.cpp` |
| Screensharing | `dom/media/webrtc/MediaEngineDefault.cpp`, `browser/modules/ContentObservers.jsm` |
| Print | `layout/printing/nsPrintJob.cpp`, `toolkit/components/printing/` |
| Screenshots (built-in) | `browser/extensions/screenshots/` |
| Citrix endpoint capture bridge | `toolkit/xre/DenCitrixCapture*.{h,cpp}` |
| Preferences/policies | `browser/components/enterprisepolicies/` |
| New-tab page routing | `browser/components/about/AboutRedirector.cpp` + `components.conf` (registers `about:denbrowserhome`), `browser/modules/AboutNewTab.sys.mjs` (pins `newTabURL`), `browser/base/content/denbrowser-newtab.{html,css}` |
| Bookmarks (read-only) | `toolkit/components/places/Bookmarks.sys.mjs` |
