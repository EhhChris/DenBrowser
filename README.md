> **Note:** This project and its scaffolding were built with AI assistance (Claude, Anthropic).
> Review all generated code and patches carefully before use in production.

# ZeroFox

A set of patches for building a branded version of Firefox ESR browser that attempts to restrict users from removing data from the browser or otherwise persisting it locally. ZeroFox is **not** a complete solution, and really only makes sense when the deployment and operating environment is largely controlled and the user has no elevated privileges. The intended purpose is to provide a moderate approach to data loss prevention strategies with less intense external infrastructure requirements and less user impact on performance for use in **controlled** environments.

**Currently only built and tested against FireFox ESR 140.9.1**

As this project progresses tags will be cut and attempt to follow the latest ESR releases.

---

## Prerequisites

- Python 3, Rust, Node.js (required by Firefox build system — see [Firefox build docs](https://firefox-source-docs.mozilla.org/setup/))
- ~20 GB free disk space for the source + build artifacts

## Deployment requirements

ZeroFox keeps page content out of Firefox's on-disk profile (PBM forced on,
disk cache hard-disabled, downloads blocked, SanitizeOnShutdown locked).
What it cannot control is the **operating system** writing process memory
to disk underneath it. To close that gap, every deployment host must:

- **Enable full-disk encryption** (FileVault on macOS, BitLocker on Windows,
  LUKS on Linux). Anything the OS pages out to swap/pagefile, captures in a
  crash dump (`WerFault`, `sysdiagnose`, kernel minidump), or writes to a
  hibernation image is then encrypted at rest under a user- or TPM-bound key.
- **Disable hibernation**, or ensure the hibernation image is encrypted.
  (FDE generally covers this, but verify on locked-down kiosk images.)
- **On Linux**, prefer `swapoff` or an encrypted swap partition. Unencrypted
  swap defeats every in-memory protection in this project.

These are operational controls, not build-time controls. The browser cannot
enforce them; the deployment image must. See `patches/007-ramdisk-profile.patch`
for the detailed analysis of why ZeroFox does not ship a RAM-disk profile.

## Quick start

```bash
# 1. Bootstrap the Firefox build system (first time only)
./scripts/fetch-esr.sh            # downloads & verifies Firefox ESR source
cd src/firefox-$(cat src/.esr_version)
./mach bootstrap                  # installs Rust, cbindgen, etc.
cd ../..

# 2. Build
./build.sh # Attempts the full build process on the last esr version pulled by fetch-esr.sh
```

---

## Project structure

```
ZeroFox/
├── build.sh                    # Full build orchestration
├── config/
│   ├── mozconfig               # Firefox build flags & app identity
│   ├── policies.json           # Enterprise policy enforcement
│   └── user.js                 # Hardened preference overrides (injected at launch)
├── patches/
│   ├── README.md               # Patch development guide
│   ├── 000-fix-bindgen-basic-string-view.patch
│   ├── 001-disable-screenshots.patch
│   ├── 002-disable-screenshare.patch
│   ├── 003-restrict-clipboard.patch
│   ├── 004-restrict-downloads.patch
│   ├── 005-disable-printing.patch
│   ├── 006-enforce-vpn.patch
│   ├── 007-ramdisk-profile.patch
│   ├── 008-disable-devtools.patch
│   ├── 009-zerofox-branding.patch
│   ├── 010-disable-diagnostics.patch
│   └── 011-disable-extensions.patch
├── scripts/
│   ├── fetch-esr.sh            # Download & verify latest Firefox ESR
│   └── apply-patches.sh        # Apply patches with dry-run validation
└── branding/                   # ZeroFox branding assets
```

---

## Patch status

**TODO:** create new table for this once closer to reality and more human review is done.

---
