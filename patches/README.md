> **Note:** This project and its scaffolding were built with AI assistance (Claude, Anthropic).
> Review all generated code and patches carefully before use in production.

# DenBrowser Patch Development Guide

## Workflow

1. Run `../scripts/fetch-esr.sh` to get the Firefox source.
2. Make changes in the source tree under `../src/firefox-<version>/`.
3. Generate a patch:
   ```
   cd ../src/firefox-<version>
   hg diff > ../../patches/00N-my-change.patch
   # OR if using plain git/diff:
   diff -Naur original_file modified_file > ../../patches/00N-my-change.patch
   ```
4. Test applying cleanly: `patch -p1 --dry-run < ../../patches/00N-my-change.patch`
5. Patches are applied in lexicographic order by `apply-patches.sh`.

## Patch naming

`NNN-short-description.patch` — three-digit prefix for ordering.

## Stub patches

Patches with `# STUB` as the first line are skipped by `apply-patches.sh`. Remove
that line once the patch contains real diff content.

## Key Firefox source areas

| Feature | Primary source file(s) |
|---------|------------------------|
| Command-line flag stripping | `toolkit/xre/nsAppRunner.cpp` |
| Network I/O gating | `netwerk/base/nsIOService.cpp`, `netwerk/base/nsIOService.h` |
| Socket connections | `netwerk/socket/nsSocketTransportService.cpp` |
| Download manager | `toolkit/components/downloads/DownloadCore.jsm`, `nsExternalHelperAppService.cpp` |
| Clipboard | `widget/nsBaseClipboard.cpp`, `dom/events/ClipboardEvent.cpp` |
| Screensharing | `dom/media/webrtc/MediaEngineDefault.cpp`, `browser/modules/ContentObservers.jsm` |
| Print | `layout/printing/nsPrintJob.cpp`, `toolkit/components/printing/` |
| Screenshots (built-in) | `browser/extensions/screenshots/` |
| Preferences/policies | `browser/components/enterprisepolicies/` |
